//! Port mapping client and service.

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroU16,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use futures::StreamExt;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, info_span, trace, Instrument};

use iroh_metrics::inc;

use crate::{net::interfaces::HomeRouter, util};

use current_mapping::CurrentMapping;

mod current_mapping;
mod mapping;
mod metrics;
mod pcp;
mod upnp;

pub use metrics::Metrics;

/// If a port mapping service has been seen within the last [`AVAILABILITY_TRUST_DURATION`] it will
/// not be probed again.
const AVAILABILITY_TRUST_DURATION: Duration = Duration::from_secs(60 * 10); // 10 minutes

/// Capacity of the channel to communicate with the long-running service.
const SERVICE_CHANNEL_CAPACITY: usize = 32; // should be plenty

/// If a port mapping service has not been seen within the last [`UNAVAILABILITY_TRUST_DURATION`]
/// we allow trying a mapping using said protocol.
const UNAVAILABILITY_TRUST_DURATION: Duration = Duration::from_secs(5);

/// Output of a port mapping probe.
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
#[display("portmap={{ UPnP: {upnp}, PMP: {pmp}, PCP: {pcp} }}")]
pub struct ProbeOutput {
    /// If UPnP can be considered available.
    pub upnp: bool,
    /// If PCP can be considered available.
    pub pcp: bool,
    /// If PMP can be considered available.
    pub pmp: bool,
}

impl ProbeOutput {
    /// Indicates if all port mapping protocols are available.
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

/// Configures which port mapping protocols are enabled in the [`Service`].
#[derive(Debug, Clone)]
pub struct Config {
    /// Whether UPnP is enabled.
    pub enable_upnp: bool,
    /// Whether PCP is enabled.
    pub enable_pcp: bool,
    /// Whether PMP is enabled.
    pub enable_nat_pmp: bool,
}

impl Default for Config {
    /// By default all port mapping protocols are enabled.
    fn default() -> Self {
        Config {
            enable_upnp: true,
            enable_pcp: true,
            enable_nat_pmp: true,
        }
    }
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
    /// Creates a client that uses the default configuration.
    ///
    /// See [`Config::default`].
    pub async fn default() -> Self {
        Self::new(Config::default()).await
    }

    /// Create a new port mapping client.
    pub async fn new(config: Config) -> Self {
        let (service_tx, service_rx) = mpsc::channel(SERVICE_CHANNEL_CAPACITY);

        let (service, watcher) = Service::new(config, service_rx);

        let handle = util::CancelOnDrop::new(
            "portmap_service",
            tokio::spawn(
                async move { service.run().await }.instrument(info_span!("portmapper.service")),
            )
            .abort_handle(),
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
#[derive(Debug)]
struct Probe {
    /// When was the probe last updated.
    last_probe: Instant,
    /// The last [`igd::aio::Gateway`] and when was it last seen.
    last_upnp_gateway_addr: Option<(upnp::Gateway, Instant)>,
    /// Last time PCP was seen.
    last_pcp: Option<Instant>,
    // TODO(@divma): PMP placeholder.
    last_pmp: Option<Instant>,
}

impl Default for Probe {
    fn default() -> Self {
        Self {
            last_probe: Instant::now() - AVAILABILITY_TRUST_DURATION,
            last_upnp_gateway_addr: None,
            last_pcp: None,
            last_pmp: None,
        }
    }
}

impl Probe {
    /// Create a new probe based on a previous output.
    async fn new(
        config: Config,
        output: ProbeOutput,
        local_ip: Ipv4Addr,
        gateway: Ipv4Addr,
    ) -> Probe {
        let ProbeOutput { upnp, pcp, pmp: _ } = output;
        let Config {
            enable_upnp,
            enable_pcp,
            enable_nat_pmp: _,
        } = config;
        let mut upnp_probing_task = util::MaybeFuture {
            inner: (enable_upnp && !upnp).then(|| {
                Box::pin(async {
                    upnp::probe_available()
                        .await
                        .map(|addr| (addr, Instant::now()))
                })
            }),
        };

        let mut pcp_probing_task = util::MaybeFuture {
            inner: (enable_pcp && !pcp).then(|| {
                Box::pin(async {
                    inc!(Metrics, pcp_probes);
                    pcp::probe_available(local_ip, gateway)
                        .await
                        .then(Instant::now)
                })
            }),
        };

        let pmp_probing_task = async { None };

        if upnp_probing_task.inner.is_some() {
            inc!(Metrics, upnp_probes);
        }

        let mut upnp_done = upnp_probing_task.inner.is_none();
        let mut pcp_done = pcp_probing_task.inner.is_none();
        let mut pmp_done = true;

        tokio::pin!(pmp_probing_task);

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

        let pcp = self
            .last_pcp
            .as_ref()
            .map(|last_probed| *last_probed + AVAILABILITY_TRUST_DURATION > now)
            .unwrap_or_default();

        // not probing for now
        let pmp = false;

        ProbeOutput { upnp, pcp, pmp }
    }

    /// Updates a probe with the `Some` values of another probe that is _assumed_ newer.
    fn update(&mut self, probe: Probe) {
        let Probe {
            last_probe,
            last_upnp_gateway_addr,
            last_pcp,
            last_pmp,
        } = probe;
        if last_upnp_gateway_addr.is_some() {
            inc!(Metrics, upnp_available);
            let new_gateway = last_upnp_gateway_addr
                .as_ref()
                .map(|(addr, _last_seen)| addr);
            let old_gateway = self
                .last_upnp_gateway_addr
                .as_ref()
                .map(|(addr, _last_seen)| addr);
            if new_gateway != old_gateway {
                inc!(Metrics, upnp_gateway_updated);
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
            inc!(Metrics, pcp_available);
            self.last_pcp = last_pcp;
        }
        if last_pmp.is_some() {
            self.last_pmp = last_pmp;
        }

        self.last_probe = last_probe;
    }
}

// mainly to make clippy happy
type ProbeResult = Result<ProbeOutput, String>;

/// A port mapping client.
#[derive(Debug)]
pub struct Service {
    config: Config,
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
    mapping_task: Option<util::AbortingJoinHandle<Result<mapping::Mapping>>>,
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
    fn new(
        config: Config,
        rx: mpsc::Receiver<Message>,
    ) -> (Self, watch::Receiver<Option<SocketAddrV4>>) {
        let (current_mapping, watcher) = CurrentMapping::new();
        let service = Service {
            config,
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
                        current_mapping::Event::Renew { external_ip, external_port } | current_mapping::Event::Expired { external_ip, external_port } => {
                            self.get_mapping(Some((external_ip, external_port)));
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
                let output = self.full_probe.output();
                debug!("probe output {output}");
                Ok(output)
            }
        };
        for tx in receivers {
            // ignore the error. If the receiver is no longer there we don't really care
            let _ = tx.send(result.clone());
        }
    }

    async fn on_mapping_result(&mut self, result: Result<mapping::Mapping>) {
        match result {
            Ok(mapping) => {
                self.current_mapping.update(Some(mapping));
            }
            Err(e) => {
                debug!("failed to get a port mapping {e}");
                inc!(Metrics, mapping_failures);
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
            inc!(Metrics, local_port_updates);
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
            let external_addr = self.current_mapping.external();

            // since the port has changed, the current mapping is no longer valid and should be
            // released

            if external_addr.is_some() {
                self.invalidate_mapping().await;
            }

            // start a new mapping task to account for the new port if necessary
            self.get_mapping(external_addr);
        } else if self.current_mapping.external().is_none() {
            // if the local port has not changed, but there is no active mapping try to get one
            self.get_mapping(None)
        }
    }

    fn get_mapping(&mut self, external_addr: Option<(Ipv4Addr, NonZeroU16)>) {
        if let Some(local_port) = self.local_port {
            inc!(Metrics, mapping_attempts);

            let (local_ip, gateway) = match ip_and_gateway() {
                Ok(ip_and_gw) => ip_and_gw,
                Err(e) => return debug!("can't get mapping: {e}"),
            };

            let ProbeOutput { upnp, pcp, pmp: _ } = self.full_probe.output();

            debug!("getting a port mapping for {local_ip}:{local_port} -> {external_addr:?}");
            let recently_probed =
                self.full_probe.last_probe + UNAVAILABILITY_TRUST_DURATION > Instant::now();
            // strategy:
            // 1. check the available services and prefer pcp, then nat_pmp then upnp since it's
            //    the most unreliable, but possibly the most deployed one
            // 2. if no service was available, fallback to upnp if enabled
            self.mapping_task = if pcp || (!recently_probed && self.config.enable_pcp) {
                let task = mapping::Mapping::new_pcp(local_ip, local_port, gateway, external_addr);
                Some(tokio::spawn(task).into())
            } else if upnp || self.config.enable_upnp {
                let external_port = external_addr.map(|(_addr, port)| port);
                let gateway = self
                    .full_probe
                    .last_upnp_gateway_addr
                    .as_ref()
                    .map(|(gateway, _last_seen)| gateway.clone());
                let task = mapping::Mapping::new_upnp(local_ip, local_port, gateway, external_port);
                Some(tokio::spawn(task).into())
            } else {
                // give up
                return;
            }
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
                    inc!(Metrics, probes_started);

                    let (local_ip, gateway) = match ip_and_gateway() {
                        Ok(ip_and_gw) => ip_and_gw,
                        Err(e) => {
                            // there is no guarantee this will be displayed, so log it anyway
                            debug!("could not start probe: {e}");
                            let _ = result_tx.send(Err(e.to_string()));
                            return;
                        }
                    };

                    let config = self.config.clone();
                    let handle = tokio::spawn(
                        async move { Probe::new(config, probe_output, local_ip, gateway).await }
                            .instrument(info_span!("portmapper.probe")),
                    );
                    let receivers = vec![result_tx];
                    self.probing_task = Some((handle.into(), receivers));
                }
            }
        }
    }
}

/// Gets the local ip and gateway address for port mapping.
fn ip_and_gateway() -> Result<(Ipv4Addr, Ipv4Addr)> {
    let Some(HomeRouter { gateway, my_ip }) = HomeRouter::new() else {
        anyhow::bail!("no gateway found for probe");
    };

    let local_ip = match my_ip {
        Some(std::net::IpAddr::V4(ip))
            if !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() =>
        {
            ip
        }
        other => {
            debug!("no address suitable for port mapping found ({other:?}), using localhost");
            Ipv4Addr::LOCALHOST
        }
    };

    let std::net::IpAddr::V4(gateway) = gateway else {
        anyhow::bail!("gateway found is ipv6, ignoring");
    };

    Ok((local_ip, gateway))
}
