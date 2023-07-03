//! Port mapping client and service.

use std::{
    net::SocketAddrV4,
    num::NonZeroU16,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use futures::StreamExt;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, trace};

use iroh_metrics::{inc, portmap::PortmapMetrics as Metrics};

use crate::util;

use mapping::CurrentMapping;

mod mapping;
mod upnp;

/// If a port mapping service has been seen within the last [`AVAILABILITY_TRUST_DURATION`] it will
/// not be probed again.
const AVAILABILITY_TRUST_DURATION: Duration = Duration::from_secs(60 * 10); // 10 minutes

/// Capacity of the channel to communicate with the long-running service.
const SERVICE_CHANNEL_CAPACITY: usize = 32; // should be plenty

#[derive(Debug, Clone)]
pub struct ProbeOutput {
    /// If UPnP can be considered available.
    pub upnp: bool,
    /// If PCP can be considered available.
    pub pcp: bool,
    /// If PMP can be considered available.
    pub pmp: bool,
}

impl ProbeOutput {
    pub fn all_available(&self) -> bool {
        self.upnp && self.pcp && self.pmp
    }
}

#[derive(derive_more::Debug)]
enum Message {
    /// Attempt to get a mapping if the local port is set but there is no mapping.
    ProcureMapping,
    /// Request to update the local port.
    ///
    /// The resulting external address can be obtained subscribing using
    /// [`Client::watch_external_address`].
    /// A value of `None` will deactivate port mapping.
    UpdateLocalPort { local_port: Option<NonZeroU16> },
    /// Request to probe the port mapping protocols.
    ///
    /// The requester should wait for the result at the [`oneshot::Receiver`] counterpart of the
    /// [`oneshot::Sender`].
    Probe {
        /// Sender side to communicate the result of the probe.
        #[debug("_")]
        result_tx: oneshot::Sender<Result<ProbeOutput, String>>,
    },
}

/// Port mapping client.
#[derive(Debug, Clone)]
pub struct Client {
    /// A watcher over the most recent external address obtained from port mapping.
    ///
    /// See [`watch::Receiver`].
    port_mapping: watch::Receiver<Option<SocketAddrV4>>,
    /// Channel used to communicate with the port mapping service.
    service_tx: mpsc::Sender<Message>,
    /// A handle to the service that will cancel the spawned task once the client is dropped.
    _service_handle: std::sync::Arc<util::CancelOnDrop>,
}

impl Client {
    /// Create a new port mapping client.
    pub async fn new() -> Self {
        let (service_tx, service_rx) = mpsc::channel(SERVICE_CHANNEL_CAPACITY);

        let (service, watcher) = Service::new(service_rx);

        let handle = util::CancelOnDrop::new(
            "portmap_service",
            tokio::spawn(async move { service.run().await }).abort_handle(),
        );

        Client {
            port_mapping: watcher,
            service_tx,
            _service_handle: std::sync::Arc::new(handle),
        }
    }

    /// Request a probe to the port mapping protocols.
    ///
    /// Returns the [`oneshot::Receiver`] used to obtain the result of the probe.
    pub fn probe(&self) -> oneshot::Receiver<Result<ProbeOutput, String>> {
        let (result_tx, result_rx) = oneshot::channel();

        if let Err(e) = self.service_tx.try_send(Message::Probe { result_tx }) {
            use mpsc::error::TrySendError::*;

            // recover the sender and return the error there
            let (result_tx, e) = match e {
                Full(Message::Probe { result_tx }) => (result_tx, "Port mapping channel full"),
                Closed(Message::Probe { result_tx }) => (result_tx, "Port mapping channel closed"),
                Full(_) | Closed(_) => unreachable!("Sent value is a probe."),
            };

            // sender was just created. If it's dropped we have two send error and are likely
            // shutting down
            // NOTE: second Err is infallible match due to being the sent value
            if let Err(Err(e)) = result_tx.send(Err(e.into())) {
                trace!("Failed to request probe: {e}")
            }
        }
        result_rx
    }

    /// Try to get a mapping for the last local port if there isn't one already.
    pub fn procure_mapping(&self) {
        // requester can't really do anything with this error if returned, so we log it
        if let Err(e) = self.service_tx.try_send(Message::ProcureMapping) {
            trace!("Failed to request mapping {e}")
        }
    }

    /// Update the local port.
    ///
    /// If the port changes, this will trigger a port mapping attempt.
    pub fn update_local_port(&self, local_port: NonZeroU16) {
        let local_port = Some(local_port);
        // requester can't really do anything with this error if returned, so we log it
        if let Err(e) = self
            .service_tx
            .try_send(Message::UpdateLocalPort { local_port })
        {
            trace!("Failed to update local port {e}")
        }
    }

    /// Deactivate port mapping.
    pub fn deactivate(&self) {
        // requester can't really do anything with this error if returned, so we log it
        if let Err(e) = self
            .service_tx
            .try_send(Message::UpdateLocalPort { local_port: None })
        {
            trace!("Failed to deactivate port mapping {e}")
        }
    }

    /// Watch the external address for changes in the mappings.
    pub fn watch_external_address(&self) -> watch::Receiver<Option<SocketAddrV4>> {
        self.port_mapping.clone()
    }
}

/// Port mapping protocol information obtained during a probe.
#[derive(Debug, Default)]
struct Probe {
    /// The last [`igd::aio::Gateway`] and when was it last seen.
    last_upnp_gateway_addr: Option<(upnp::Gateway, Instant)>,
    // TODO(@divma): PCP placeholder.
    last_pcp: Option<Instant>,
    // TODO(@divma): PMP placeholder.
    last_pmp: Option<Instant>,
}

impl Probe {
    /// Create a new probe based on a previous output.
    async fn new(output: ProbeOutput) -> Probe {
        let ProbeOutput {
            upnp,
            pcp: _,
            pmp: _,
        } = output;
        let mut upnp_probing_task = util::MaybeFuture {
            inner: (!upnp).then(|| {
                Box::pin(async {
                    upnp::probe_available()
                        .await
                        .map(|addr| (addr, Instant::now()))
                })
            }),
        };

        // placeholder tasks
        let pcp_probing_task = async { None };
        let pmp_probing_task = async { None };

        if upnp_probing_task.inner.is_some() {
            inc!(Metrics::UpnpProbes);
        }

        let mut upnp_done = upnp_probing_task.inner.is_none();
        let mut pcp_done = true;
        let mut pmp_done = true;

        tokio::pin!(pmp_probing_task);
        tokio::pin!(pcp_probing_task);

        let mut probe = Probe::default();

        while !upnp_done || !pcp_done || !pmp_done {
            tokio::select! {
                last_upnp_gateway_addr = &mut upnp_probing_task, if !upnp_done => {
                    trace!("tick: upnp probe ready");
                    probe.last_upnp_gateway_addr = last_upnp_gateway_addr;
                    upnp_done = true;
                },
                last_pmp = &mut pmp_probing_task, if !pmp_done => {
                    trace!("tick: pmp probe ready");
                    probe.last_pmp = last_pmp;
                    pmp_done = true;
                },
                last_pcp = &mut pcp_probing_task, if !pcp_done => {
                    trace!("tick: pcp probe ready");
                    probe.last_pcp = last_pcp;
                    pcp_done = true;
                },
            }
        }

        probe
    }

    /// Returns a [`ProbeOutput`] indicating which services can be considered available.
    fn output(&self) -> ProbeOutput {
        let now = Instant::now();

        // check if the last UPnP gateway is valid
        let upnp = self
            .last_upnp_gateway_addr
            .as_ref()
            .map(|(_gateway_addr, last_probed)| *last_probed + AVAILABILITY_TRUST_DURATION > now)
            .unwrap_or_default();

        // not probing for now
        let pcp = false;

        // not probing for now
        let pmp = false;

        ProbeOutput { upnp, pcp, pmp }
    }

    /// Updates a probe with the `Some` values of another probe.
    fn update(&mut self, probe: Probe) {
        let Probe {
            last_upnp_gateway_addr,
            last_pcp,
            last_pmp,
        } = probe;
        if last_upnp_gateway_addr.is_some() {
            inc!(Metrics::UpnpAvailable);
            let new_gateway = last_upnp_gateway_addr
                .as_ref()
                .map(|(addr, _last_seen)| addr);
            let old_gateway = self
                .last_upnp_gateway_addr
                .as_ref()
                .map(|(addr, _last_seen)| addr);
            if new_gateway != old_gateway {
                inc!(Metrics::UpnpGatewayUpdated);
                debug!(
                    "upnp gateway changed {:?} -> {:?}",
                    old_gateway
                        .map(|gw| gw.to_string())
                        .unwrap_or("None".into()),
                    new_gateway
                        .map(|gw| gw.to_string())
                        .unwrap_or("None".into())
                )
            };
            self.last_upnp_gateway_addr = last_upnp_gateway_addr;
        }
        if last_pcp.is_some() {
            self.last_pcp = last_pcp;
        }
        if last_pmp.is_some() {
            self.last_pmp = last_pmp;
        }
    }
}

// mainly to make clippy happy
type ProbeResult = Result<ProbeOutput, String>;

/// A port mapping client.
#[derive(Debug)]
pub struct Service {
    /// Local port to map.
    local_port: Option<NonZeroU16>,
    /// Channel over which the service is informed of messages.
    ///
    /// The service will stop when all senders are gone.
    rx: mpsc::Receiver<Message>,
    /// Currently active mapping.
    current_mapping: CurrentMapping,
    /// Last updated probe.
    full_probe: Probe,
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
        util::AbortingJoinHandle<Probe>,
        Vec<oneshot::Sender<ProbeResult>>,
    )>,
}

impl Service {
    fn new(rx: mpsc::Receiver<Message>) -> (Self, watch::Receiver<Option<SocketAddrV4>>) {
        let (current_mapping, watcher) = CurrentMapping::new();
        let service = Service {
            local_port: None,
            rx,
            current_mapping,
            full_probe: Default::default(),
            mapping_task: None,
            probing_task: None,
        };

        (service, watcher)
    }

    /// Clears the current mapping and releases it.
    async fn invalidate_mapping(&mut self) {
        if let Some(old_mapping) = self.current_mapping.update(None) {
            if let Err(e) = old_mapping.release().await {
                debug!("failed to release mapping {e}");
            }
        }
    }

    async fn run(mut self) -> Result<()> {
        debug!("portmap starting");
        loop {
            tokio::select! {
                msg = self.rx.recv() => {
                    trace!("tick: msg {msg:?}");
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
                mapping_result = util::MaybeFuture{ inner: self.mapping_task.as_mut() } => {
                    trace!("tick: mapping ready");
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
                probe_result = util::MaybeFuture{ inner: self.probing_task.as_mut().map(|(fut, _rec)| fut) } => {
                    trace!("tick: probe ready");
                    // retrieve the receivers and clear the task
                    let receivers = self.probing_task.take().expect("is some").1;
                    let probe_result = probe_result.map_err(|join_err| anyhow!("Failed to obtain a result {join_err}"));
                    self.on_probe_result(probe_result, receivers).await;
                }
                Some(event) = self.current_mapping.next() => {
                    trace!("tick: mapping event {event:?}");
                    match event {
                        mapping::Event::Renew { external_port } | mapping::Event::Expired { external_port } => {
                            self.get_mapping(Some(external_port));
                        },
                    }

                }
            }
        }
        Ok(())
    }

    async fn on_probe_result(
        &mut self,
        result: Result<Probe>,
        receivers: Vec<oneshot::Sender<ProbeResult>>,
    ) {
        let result = match result {
            Err(e) => Err(e.to_string()),
            Ok(probe) => {
                self.full_probe.update(probe);
                // TODO(@divma): the gateway of the current mapping could have changed. Tailscale
                // still assumes the current mapping is valid/active and will return it even after
                // this
                Ok(self.full_probe.output())
            }
        };
        for tx in receivers {
            // ignore the error. If the receiver is no longer there we don't really care
            let _ = tx.send(result.clone());
        }
    }

    async fn on_mapping_result(&mut self, result: Result<upnp::Mapping>) {
        match result {
            Ok(mapping) => {
                self.current_mapping.update(Some(mapping));
            }
            Err(e) => {
                debug!("failed to get a port mapping {e}");
                inc!(Metrics::MappingFailures)
            }
        }
    }

    async fn handle_msg(&mut self, msg: Message) {
        match msg {
            Message::ProcureMapping => self.update_local_port(self.local_port).await,
            Message::UpdateLocalPort { local_port } => self.update_local_port(local_port).await,
            Message::Probe { result_tx } => self.probe_request(result_tx),
        }
    }

    /// Updates the local port of the port mapping service.
    ///
    /// If the port changed, any port mapping task is cancelled. If the new port is some, it will
    /// start a new port mapping task.
    async fn update_local_port(&mut self, local_port: Option<NonZeroU16>) {
        // ignore requests to update the local port in a way that does not produce a change
        if local_port != self.local_port {
            inc!(Metrics::LocalPortUpdates);
            let old_port = std::mem::replace(&mut self.local_port, local_port);

            // clear the current mapping task if any

            let dropped_task = self.mapping_task.take();
            // check if the dropped task had finished to reduce log noise
            let did_cancel = dropped_task
                .map(|task| !task.is_finished())
                .unwrap_or_default();

            if did_cancel {
                debug!(
                    "canceled mapping task due to local port update. Old: {:?} New: {:?}",
                    old_port, self.local_port
                )
            }

            // get the current external port if any to try to get it again
            let port = self.current_mapping.external().map(|(_addr, port)| port);

            // since the port has changed, the current mapping is no longer valid and should be
            // released

            self.invalidate_mapping().await;

            // start a new mapping task to account for the new port if necessary
            self.get_mapping(port)
        } else if self.current_mapping.external().is_none() {
            // if the local port has not changed, but there is no active mapping try to get one
            self.get_mapping(None)
        }
    }

    fn get_mapping(&mut self, external_port: Option<NonZeroU16>) {
        if let Some(local_port) = self.local_port {
            inc!(Metrics::MappingAttempts);
            debug!("getting a port mapping for port {local_port} -> {external_port:?}");
            let gateway = self
                .full_probe
                .last_upnp_gateway_addr
                .as_ref()
                .map(|(gateway, _last_seen)| gateway.clone());
            let local_ip = std::net::Ipv4Addr::LOCALHOST;
            self.mapping_task = Some(
                tokio::spawn(upnp::Mapping::new(
                    local_ip,
                    local_port,
                    gateway,
                    external_port,
                ))
                .into(),
            );
        }
    }

    /// Handles a probe request.
    ///
    /// If there is a task getting a probe, the receiver will be added with any other waiting for a
    /// result. If no probe is underway, a result can be returned immediately if it's still
    /// considered valid. Otherwise, a new probe task will be started.
    fn probe_request(&mut self, result_tx: oneshot::Sender<Result<ProbeOutput, String>>) {
        match self.probing_task.as_mut() {
            Some((_task_handle, receivers)) => receivers.push(result_tx),
            None => {
                let probe_output = self.full_probe.output();
                if probe_output.all_available() {
                    // we don't care if the requester is no longer there
                    let _ = result_tx.send(Ok(probe_output));
                } else {
                    inc!(Metrics::ProbesStarted);
                    let handle = tokio::spawn(async move { Probe::new(probe_output).await });
                    let receivers = vec![result_tx];
                    self.probing_task = Some((handle.into(), receivers));
                }
            }
        }
    }
}
