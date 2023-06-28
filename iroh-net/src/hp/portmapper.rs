#![allow(unused)]
use std::{
    net::{SocketAddr, SocketAddrV4},
    num::NonZeroU16,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task,
};
use tokio_stream::wrappers;
use tracing::{debug, trace};

use iroh_metrics::{inc, portmap::PortmapMetrics as Metrics};

use crate::util;

mod upnp;

/// If a port mapping service has been seen during the last [`AVAILABILITY_TRUST_DURATION`] it
/// will not be probed again.
const AVAILABILITY_TRUST_DURATION: Duration = Duration::from_secs(60 * 10); // 10 minutes

// alias to reduce verbosity
type StrResult<T> = std::result::Result<T, String>;

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub pcp: bool,
    pub pmp: bool,
    pub upnp: bool,
}

#[derive(Debug)]
enum Message {
    /// Request to update the local port.
    ///
    /// The resulting external address can be obtained subscribing using the [`Handle`].
    /// A value of `None` will deactivate port mapping.
    UpdateLocalPort { local_port: Option<NonZeroU16> },
    /// Request to probe the port mapping protocols.
    ///
    /// The requester should wait for the result at the [`oneshot::Receiver`] counterpart of the
    /// [`oneshot::Sender`].
    Probe {
        result_tx: oneshot::Sender<StrResult<ProbeResult>>,
    },
}

#[derive(Debug, Clone)]
pub struct Client {
    /// A watcher over the most recent external address obtained from port mapping.
    ///
    /// See [`watch::Receiver`].
    port_mapping: watch::Receiver<Option<SocketAddrV4>>,
    /// Channel used to communicate with the port mapping service.
    service_tx: mpsc::Sender<Message>,
    /// A handle to the service that will cancel the spawned task once the client is dropped.
    service_handle: std::sync::Arc<util::CancelOnDrop>,
}

impl Client {
    /// Create a new port mapping client.
    pub async fn new() -> Self {
        let (service_tx, service_rx) = mpsc::channel(4);

        let (mut service, watcher) = Service::new(service_rx);

        let handle = util::CancelOnDrop::new(
            "portmap_service",
            tokio::spawn(async move { service.run().await }).abort_handle(),
        );

        let client = Client {
            port_mapping: watcher,
            service_tx,
            service_handle: std::sync::Arc::new(handle),
        };
        client
    }

    /// Request a probe to the port mapping protocols.
    pub fn probe(&self) -> oneshot::Receiver<StrResult<ProbeResult>> {
        let (result_tx, result_rx) = oneshot::channel();

        use mpsc::error::TrySendError::*;
        if let Err(e) = self.service_tx.try_send(Message::Probe { result_tx }) {
            // Recover the sender and return the error there
            let (result_tx, e) = match e {
                Full(Message::Probe { result_tx }) => (result_tx, "Port mapping channel full"),
                Closed(Message::Probe { result_tx }) => (result_tx, "Port mapping channel closed"),
                Full(_) | Closed(_) => unreachable!("Sent value is a probe."),
            };

            result_tx
                .send(Err(e.into()))
                .expect("receiver counterpart has not been dropped or closed.");
        }
        result_rx
    }

    /// Update the local port.
    ///
    /// A value of `None` will invalidate any active mapping and deactivate port mapping.
    /// This can fail if communicating with the port-mapping service fails.
    pub fn update_local_port(&self, local_port: Option<NonZeroU16>) -> Result<()> {
        self.service_tx
            .try_send(Message::UpdateLocalPort { local_port })
            .map_err(Into::into)
    }

    /// Watch the external address for changes in the mappings.
    pub fn watch_external_address(&self) -> watch::Receiver<Option<SocketAddrV4>> {
        self.port_mapping.clone()
    }
}

#[derive(Debug)]
struct FullProbe {
    f: usize,
}

/// A port mapping client.
#[derive(Debug)]
pub struct Service {
    /// Local port to map.
    local_port: Option<NonZeroU16>,

    rx: mpsc::Receiver<Message>,
    last_upnp_gateway_addr: Option<(SocketAddrV4, Instant)>,
    current_mapping: CurrentMapping,
    /// Task attempting to get a port mapping.
    ///
    /// This task will be cancelled if a request to set the local port arrives before it's
    /// finished.
    mapping_task: Option<util::AbortingJoinHandle<Result<upnp::Mapping>>>,
    /// Task probing the necessary protocols.
    ///
    /// Requests for a probe that arrive while this task is still in progress will receive the same
    /// result.
    probing_task: Option<(
        util::AbortingJoinHandle<FullProbe>,
        Vec<oneshot::Sender<StrResult<ProbeResult>>>,
    )>,
}

#[derive(PartialEq, Eq, Debug)]
enum ReleaseMapping {
    Yes,
    No,
}

/// Holds the current mapping value and ensures that any change is reported accordingly.
#[derive(Debug)]
struct CurrentMapping {
    mapping: Option<upnp::Mapping>,
    address_tx: watch::Sender<Option<SocketAddrV4>>,
}

impl CurrentMapping {
    fn new(mapping: Option<upnp::Mapping>) -> (Self, watch::Receiver<Option<SocketAddrV4>>) {
        let maybe_external_addr = mapping.as_ref().map(|mapping| mapping.external());
        let (address_tx, address_rx) = watch::channel(maybe_external_addr);
        let wrapper = CurrentMapping {
            mapping,
            address_tx,
        };
        (wrapper, address_rx)
    }

    /// Updates the mapping, informing of any changes to the external address. The old mapping is
    /// returned.
    fn update(&mut self, mapping: Option<upnp::Mapping>) -> Option<upnp::Mapping> {
        trace!("New port mapping {mapping:?}");
        let maybe_external_addr = mapping.as_ref().map(|mapping| mapping.external());
        let old_mapping = std::mem::replace(&mut self.mapping, mapping);
        self.address_tx.send_if_modified(|old_addr| {
            // replace the value always, as it could have different internal values
            let old_addr = std::mem::replace(old_addr, maybe_external_addr);
            // inform only if this produces a different external address
            old_addr != maybe_external_addr
        });
        old_mapping
    }

    fn value(&self) -> Option<&upnp::Mapping> {
        self.mapping.as_ref()
    }
}

impl Service {
    fn new(rx: mpsc::Receiver<Message>) -> (Self, watch::Receiver<Option<SocketAddrV4>>) {
        let (current_mapping, watcher) = CurrentMapping::new(None);
        let service = Service {
            local_port: None,
            rx,
            last_upnp_gateway_addr: None,
            current_mapping,
            mapping_task: None,
            probing_task: None,
        };

        (service, watcher)
    }
    /// Clears the current mapping and releases it if necessary.
    async fn invalidate_mapping(&mut self, release: ReleaseMapping) {
        if let Some(old_mapping) = self.current_mapping.update(None) {
            if release == ReleaseMapping::Yes {
                if let Err(e) = old_mapping.release().await {
                    debug!("Failed to release mapping {e}");
                }
            }
        }
    }

    async fn run(mut self) -> Result<()> {
        debug!("Portmap starting");
        loop {
            tokio::select! {
                msg = self.rx.recv() => {
                    match msg {
                        Some(msg) => {
                            self.handle_msg(msg).await;
                        },
                        None => {
                            debug!("portmap service channel dropped. Likely shutting down.");
                            break;
                        }
                    }
                }
                mapping_result = util::MaybeFuture{inner: self.mapping_task.as_mut()} => {
                    // regardless of outcome, the task is finished, clear it
                    self.mapping_task = None;
                    // there isn't really a way to react to a join error here. Flatten it to make
                    // it easier to work with
                    let result = match mapping_result {
                        Ok(result) => result,
                        Err(join_err) => Err(anyhow!("Failed to obtain a result {join_err}"))
                    };
                    self.on_mapping_result(result).await;
                }
                probe_result = util::MaybeFuture{inner: self.probing_task.as_mut().map(|(fut, _rec)| fut)} => {
                    // retrieve the receivers and clear the task.
                    let receivers = self.probing_task.take().expect("is some").1;
                    let probe_result = probe_result.map_err(|join_err|anyhow!("Failed to obtain a result {join_err}"));
                    self.on_probe_result(probe_result, receivers).await;
                }
            }
        }
        Ok(())
    }

    async fn on_probe_result(
        &mut self,
        result: Result<FullProbe>,
        receivers: Vec<oneshot::Sender<StrResult<ProbeResult>>>,
    ) {
        match result {
            Err(e) => {
                // inform the receivers about the error
                let e: String = e.to_string();
                for tx in receivers {
                    let _ = tx.send(Err(e.clone()));
                }
            }
            Ok(result) => {
                debug!("{result:?}")
            },
        }
    }

    async fn on_mapping_result(&mut self, result: Result<upnp::Mapping>) {
        match result {
            Ok(mapping) => {
                let old_mapping = self.current_mapping.update(Some(mapping));
            }
            Err(e) => debug!("Failed to get a port mapping {e}"),
        }
    }

    async fn handle_msg(&mut self, msg: Message) {
        debug!("received message {msg:?}");
        match msg {
            Message::UpdateLocalPort { local_port } => self.update_local_port(local_port).await,
            Message::Probe { result_tx } => self.probe_request(result_tx),
        }
    }

    /// Updates the local port of the port mapping service.
    ///
    /// If the port changed, any port mapping task is cancelled. If the new port is some, it will
    /// start a new port mapping task.
    async fn update_local_port(&mut self, local_port: Option<NonZeroU16>) {
        // Ignore requests to update the local port in a way that does not produce a change.
        if local_port != self.local_port {
            let old_port = std::mem::replace(&mut self.local_port, local_port);

            // Clear the current mapping task if any.

            let dropped_task = self.mapping_task.take();
            // Check if the dropped task had finished to reduce log noise.
            let did_cancel = dropped_task
                .map(|task| !task.is_finished())
                .unwrap_or_default();

            if did_cancel {
                debug!(
                    "Canceled mapping task due to local port update. Old: {:?} New: {:?}",
                    old_port, self.local_port
                )
            }

            // Since the port has changed, the current mapping is no longer valid and should be
            // release.

            self.invalidate_mapping(ReleaseMapping::Yes).await;

            // Start a new mapping task to account for the new port if necessary.

            if let Some(local_port) = self.local_port {
                debug!("Getting a port mapping for port {local_port}");
                let handle = tokio::spawn(upnp::Mapping::new(
                    std::net::Ipv4Addr::LOCALHOST,
                    local_port,
                ));
                self.mapping_task = Some(handle.into());
            }
        }
    }

    /// Handles a probe request.
    ///
    /// If there is a task getting a probe, the receiver will be added with any other waiting for a
    /// result. If no probe is underway, a result can be returned immediately if it's still
    /// considered valid. Otherwise, a new probe task will be started.
    fn probe_request(&mut self, result_tx: oneshot::Sender<StrResult<ProbeResult>>) {
        inc!(Metrics::ProbeRequests);
        match self.probing_task.as_mut() {
            Some((_task_handle, receivers)) => receivers.push(result_tx),
            None => {
                // let probe_is_valid = todo!();
                // if probe_is_valid {
                //     // send the result based on the last stored value
                // } else {
                //     inc!(Metrics::ProbesDone);
                //     // start a probing Task
                // }
                let handle = tokio::spawn(async {
                    let result = upnp::probe_available().await;
                    match result {
                        Ok(x) => {
                            debug!("Found upnp gateway at {x}");
                            FullProbe { f: 1 }
                        }
                        Err(e) => {
                            debug!("upnp probe failed {e}");
                            FullProbe { f: 0 }
                        }
                    }
                });
                self.probing_task = Some((handle.into(), vec![result_tx]));
            }
        }
    }

    /// UPnP: searches for an upnp internet gateway device (a router).
    pub async fn probe(&mut self) -> Result<ProbeResult> {
        let upnp = self.upnp_available_from_cache() || self.probe_upnp_available().await;

        Ok(ProbeResult {
            pcp: false,
            pmp: false,
            upnp,
        })
    }

    /// Checks if the last seen upnp gateway should still be trusted as available.
    ///
    /// Returns false otherwise, or if there is no cached gateway.
    fn upnp_available_from_cache(&self) -> bool {
        self.last_upnp_gateway_addr
            .as_ref()
            .map(|(_gateway_addr, last_probed)| {
                *last_probed + AVAILABILITY_TRUST_DURATION > Instant::now()
            })
            .unwrap_or_default()
    }

    /// Probes for UPnP gateways.
    async fn probe_upnp_available(&mut self) -> bool {
        inc!(Metrics::UpnpProbes);
        match upnp::probe_available().await {
            Ok(gateway_addr) => {
                debug!("found upnp gateway {gateway_addr}");
                let old_gateway = self
                    .last_upnp_gateway_addr
                    .replace((gateway_addr, Instant::now()));
                if let Some((old_gateway_addr, _last_seen)) = old_gateway {
                    if old_gateway_addr != gateway_addr {
                        inc!(Metrics::UpnpGatewayUpdated);
                        debug!("upnp gateway changed from {old_gateway_addr} to {gateway_addr}");
                        // TODO(@divagant-martian): tailscale does not clear the mappings here.
                        // This means the gateway has changed but we believe `self.current_mapping`
                        // is still valid.
                    }
                }
                true
            }
            Err(e) => {
                inc!(Metrics::UpnpProbesFailed);
                debug!("upnp probe failed {e}");
                // invalidate last seen gateway and time
                self.last_upnp_gateway_addr = None;
                false
            }
        }
    }

    /*
        /// Quickly returns with our current cached portmapping, if any.
        /// If there's not one, it starts up a background goroutine to create one.
        /// If the background goroutine ends up creating one, the `on_change` hook registered with the
        /// `Client::new` constructor (if any) will fire.
        // TODO(@divagant-martian): fix docs. Also, this will probably only ever return ipv4 addresses.
        pub async fn get_cached_mapping_or_start_creating_one(&mut self) -> Option<SocketAddr> {
            // TODO(@divagant-martian): this has a lock ensure just one mapping attempt is underway
            if let Some(mapping) = &mut self.current_external_address {
                let now = Instant::now();
                if now <= mapping.good_until() {
                    debug!("renewing mapping {mapping}");
                    // TODO(@divagant-martian): this would go in a goroutine
                    if now >= mapping.renew_after() {
                        inc!(Metrics::UpnpPortmapAttempts);
                        if let Err(e) = mapping.renew().await {
                            inc!(Metrics::UpnpPortmapFailed);
                            debug!("failed to renew port mapping {mapping}: {e}");
                        }
                    }
                    // port mapping is still good regardless of renewal
                    Some(mapping.external().into())
                } else {
                    // TODO(@divagant-martian): tailscale returns nil without clearing the mapping
                    None
                }
            } else if let Some(local_port) = self.local_port {
                inc!(Metrics::UpnpPortmapAttempts);
                match upnp::Mapping::new(std::net::Ipv4Addr::LOCALHOST, local_port).await {
                    Ok(mapping) => {
                        debug!("upnp port mapping created {mapping}");
                        let external = mapping.external().into();
                        self.current_external_address = Some(mapping);
                        Some(external)
                    }
                    Err(e) => {
                        inc!(Metrics::UpnpPortmapFailed);
                        debug!("Failed to create upnp port mapping: {e}");
                        None
                    }
                }
            } else {
                debug!("No valid local port provided to create a mapping");
                None
            }
        }

    pub async fn close(&mut self) {
        // TODO(@divagant-martian):
        // tailscale has a `closed` bool, which is not very pretty.
        // Easiest way to emulate this is consume self and have the owner have an Option. This does
        // bring some complexity, so maybe we can just not close (permanently) but simply clean
        // (invalidate mappings)
        //
        // The only place this is ever used is to prevent closing twice...
        let _ = self.invalidate_mapping().await;
    }
    */
}
