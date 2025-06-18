//! Checks the network conditions from the current host.
//!
//! NetReport is responsible for finding out the network conditions of the current host, like
//! whether it is connected to the internet via IPv4 and/or IPv6, what the NAT situation is
//! etc and reachability to the configured relays.
// Based on <https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go>

#![cfg_attr(iroh_docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(wasm_browser, allow(unused))]

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    net::SocketAddr,
    sync::Arc,
};

use defaults::timeouts::PROBES_TIMEOUT;
use iroh_base::RelayUrl;
#[cfg(not(wasm_browser))]
use iroh_relay::dns::DnsResolver;
#[cfg(not(wasm_browser))]
use iroh_relay::quic::QuicClient;
#[cfg(not(wasm_browser))]
use iroh_relay::RelayNode;
use iroh_relay::{
    quic::{QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON},
    RelayMap,
};
#[cfg(not(wasm_browser))]
use n0_future::task;
use n0_future::{
    task::AbortOnDropHandle,
    time::{self, Duration, Instant},
    StreamExt,
};
use n0_watcher::{Watchable, Watcher};
use reportgen::{ProbeFinished, ProbeReport, QadProbeReport};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

mod defaults;
mod ip_mapped_addrs;
mod metrics;
mod probes;
mod report;
mod reportgen;

mod options;

/// We "vendor" what we need of the library in browsers for simplicity.
///
/// We could consider making `portmapper` compile to wasm in the future,
/// but what we need is so little it's likely not worth it.
#[cfg(wasm_browser)]
pub(crate) mod portmapper {
    /// Output of a port mapping probe.
    #[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
    #[display("portmap={{ UPnP: {upnp}, PMP: {nat_pmp}, PCP: {pcp} }}")]
    pub struct ProbeOutput {
        /// If UPnP can be considered available.
        pub upnp: bool,
        /// If PCP can be considered available.
        pub pcp: bool,
        /// If PMP can be considered available.
        pub nat_pmp: bool,
    }
}

pub(crate) use ip_mapped_addrs::{IpMappedAddr, IpMappedAddresses};

pub(crate) use self::reportgen::IfStateDetails;
#[cfg(not(wasm_browser))]
use self::reportgen::SocketState;
pub use self::{
    metrics::Metrics,
    options::Options,
    probes::Probe,
    report::{RelayLatencies, Report},
    reportgen::QuicConfig,
};
use crate::util::MaybeFuture;

const FULL_REPORT_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// The maximum latency of all nodes, if none are found yet.
///
/// Normally the max latency of all nodes is computed, but if we don't yet know any nodes
/// latencies we return this as default.  This is the value of the initial STUN probe
/// delays.  It is only used as time to wait for further latencies to arrive, which *should*
/// never happen unless there already is at least one latency.  Yet here we are, defining a
/// default which will never be used.
const DEFAULT_MAX_LATENCY: Duration = Duration::from_millis(100);

const ENOUGH_NODES: usize = 3;

/// Client to run net_reports.
///
/// Creating this creates a net_report actor which runs in the background.  Most of the time
/// it is idle unless [`Client::get_report`] is called, which is the main interface.
///
/// The [`Client`] struct can be cloned and results multiple handles to the running actor.
/// If all [`Client`]s are dropped the actor stops running.
///
/// While running the net_report actor expects to be passed all received stun packets using
/// `Addr::receive_stun_packet`.
#[derive(Debug)]
pub(crate) struct Client {
    #[cfg(not(wasm_browser))]
    socket_state: SocketState,
    metrics: Arc<Metrics>,
    probes: BTreeSet<Probe>,
    relay_map: RelayMap,
    #[cfg(not(wasm_browser))]
    qad_conns: QadConns,
    #[cfg(any(test, feature = "test-utils"))]
    insecure_skip_relay_cert_verify: bool,

    /// A collection of previously generated reports.
    ///
    /// Sometimes it is useful to look at past reports to decide what to do.
    reports: Reports,
}

#[cfg(not(wasm_browser))]
#[derive(Debug, Default)]
struct QadConns {
    v4: Option<(RelayUrl, QadConn)>,
    v6: Option<(RelayUrl, QadConn)>,
}

#[cfg(not(wasm_browser))]
impl QadConns {
    fn clear(&mut self) {
        if let Some((_, conn)) = self.v4.take() {
            conn.conn
                .close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
        }
        if let Some((_, conn)) = self.v6.take() {
            conn.conn
                .close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
        }
    }

    fn current(&self) -> Vec<ProbeReport> {
        let mut reports = Vec::new();
        if let Some((_, ref conn)) = self.v4 {
            if let Some(mut r) = conn.observer.get() {
                // grab latest rtt
                r.latency = conn.conn.rtt();
                reports.push(ProbeReport::QadIpv4(r));
            }
        }

        if let Some((_, ref conn)) = self.v6 {
            if let Some(mut r) = conn.observer.get() {
                // grab latest rtt
                r.latency = conn.conn.rtt();
                reports.push(ProbeReport::QadIpv6(r));
            }
        }

        reports
    }

    fn watch_v4(&self) -> impl n0_future::Stream<Item = Option<QadProbeReport>> + Unpin {
        let watcher = self.v4.as_ref().map(|(_url, conn)| conn.observer.watch());

        if let Some(watcher) = watcher {
            watcher.stream_updates_only().boxed()
        } else {
            n0_future::stream::empty().boxed()
        }
    }

    fn watch_v6(&self) -> impl n0_future::Stream<Item = Option<QadProbeReport>> + Unpin {
        let watcher = self.v6.as_ref().map(|(_url, conn)| conn.observer.watch());
        if let Some(watcher) = watcher {
            watcher.stream_updates_only().boxed()
        } else {
            n0_future::stream::empty().boxed()
        }
    }
}

#[cfg(not(wasm_browser))]
#[derive(Debug)]
struct QadConn {
    conn: quinn::Connection,
    observer: Watchable<Option<QadProbeReport>>,
    _handle: AbortOnDropHandle<()>,
}

#[derive(Debug)]
struct Reports {
    /// Do a full relay scan, even if last is `Some`.
    next_full: bool,
    /// Some previous reports.
    prev: BTreeMap<Instant, Report>,
    /// Most recent report.
    last: Option<Report>,
    /// Time of last full (non-incremental) report.
    last_full: Instant,
}

impl Default for Reports {
    fn default() -> Self {
        Self {
            next_full: true,
            prev: Default::default(),
            last: Default::default(),
            last_full: Instant::now(),
        }
    }
}

impl Client {
    /// Creates a new net_report client.
    pub(crate) fn new(
        #[cfg(not(wasm_browser))] dns_resolver: DnsResolver,
        #[cfg(not(wasm_browser))] ip_mapped_addrs: Option<IpMappedAddresses>,
        relay_map: RelayMap,
        opts: Options,
        metrics: Arc<Metrics>,
    ) -> Self {
        let probes = opts.as_protocols();
        #[cfg(any(test, feature = "test-utils"))]
        let insecure_skip_relay_cert_verify = opts.insecure_skip_relay_cert_verify;

        #[cfg(not(wasm_browser))]
        let quic_client = opts
            .quic_config
            .map(|c| iroh_relay::quic::QuicClient::new(c.ep, c.client_config));

        #[cfg(not(wasm_browser))]
        let socket_state = SocketState {
            quic_client,
            dns_resolver,
            ip_mapped_addrs,
        };

        Client {
            #[cfg(not(wasm_browser))]
            socket_state,
            metrics,
            reports: Reports::default(),
            probes,
            relay_map,
            qad_conns: QadConns::default(),
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify,
        }
    }

    /// Generates a [`Report`].
    ///
    /// Look at [`Options`] for the different configuration options.
    pub(crate) async fn get_report(&mut self, if_state: IfStateDetails, is_major: bool) -> Report {
        let now = Instant::now();

        let mut do_full = is_major
            || self.reports.next_full
            || now.duration_since(self.reports.last_full) > FULL_REPORT_INTERVAL;

        debug!(%do_full, "net_report starting");

        // If the last report had a captive portal and reported no UDP access,
        // it's possible that we didn't get a useful net_report due to the
        // captive portal blocking us. If so, make this report a full (non-incremental) one.
        if !do_full {
            if let Some(ref last) = self.reports.last {
                if !last.has_udp() && last.captive_portal == Some(true) {
                    do_full = true;
                }
            }
        }
        if do_full {
            self.reports.last = None; // causes ProbePlan::new below to do a full (initial) plan
            self.reports.next_full = false;
            self.reports.last_full = now;
            self.metrics.reports_full.inc();
        }
        self.metrics.reports.inc();

        let enough_relays = std::cmp::min(self.relay_map.len(), ENOUGH_NODES);
        #[cfg(wasm_browser)]
        let if_state = IfStateDetails::default();
        #[cfg(not(wasm_browser))]
        let if_state = IfStateDetails {
            have_v4: if_state.have_v4,
            have_v6: if_state.have_v6,
        };

        let mut report = Report::default();

        #[cfg(not(wasm_browser))]
        let reports = self
            .spawn_qad_probes(&if_state, enough_relays, do_full)
            .await;

        #[cfg(not(wasm_browser))]
        for r in reports {
            report.update(&r);
        }

        let (actor, mut probe_rx) = reportgen::Client::new(
            self.reports.last.clone(),
            self.relay_map.clone(),
            self.probes.clone(),
            if_state,
            #[cfg(not(wasm_browser))]
            self.socket_state.clone(),
            #[cfg(any(test, feature = "test-utils"))]
            self.insecure_skip_relay_cert_verify,
        );

        let mut timeout_fut = std::pin::pin!(MaybeFuture::default());

        #[cfg(not(wasm_browser))]
        let mut qad_v4_stream = self.qad_conns.watch_v4();
        #[cfg(not(wasm_browser))]
        let mut qad_v6_stream = self.qad_conns.watch_v6();

        loop {
            tokio::select! {
                biased;

                _ = &mut timeout_fut, if timeout_fut.is_some() => {
                    trace!("timeout done, shutting down");
                    drop(actor); // shuts down the probes
                    break;
                }

                Some(Some(r)) = qad_v4_stream.next() => {
                    trace!(?r, "new report from QAD V4");
                    report.update(&ProbeReport::QadIpv4(r));
                }

                Some(Some(r)) = qad_v6_stream.next() => {
                    trace!(?r, "new report from QAD V6");
                    report.update(&ProbeReport::QadIpv6(r));
                }

                maybe_probe = probe_rx.recv() => {
                    let Some(probe_res) = maybe_probe else {
                        break;
                    };
                    trace!(?probe_res, "handling probe");
                    match probe_res {
                        ProbeFinished::Regular(probe) => match probe {
                            Ok(probe) => {
                                report.update(&probe);
                                if timeout_fut.is_none() {
                                    if let Some(timeout) = self.have_enough_reports(enough_relays, &report) {
                                        timeout_fut.as_mut().set_future(time::sleep(timeout));
                                    }
                                }
                            }
                            Err(err) => {
                                trace!("probe errored: {:?}", err);
                            }
                        },
                        #[cfg(not(wasm_browser))]
                        ProbeFinished::CaptivePortal(portal) => {
                            report.captive_portal = portal;
                        }
                    }
                }
            }
        }

        self.add_report_history_and_set_preferred_relay(&mut report);
        debug!(
            ?report,
            "generated report in {:02}ms",
            now.elapsed().as_millis()
        );

        report
    }

    #[cfg(not(wasm_browser))]
    async fn spawn_qad_probes(
        &mut self,
        if_state: &IfStateDetails,
        enough_relays: usize,
        do_full: bool,
    ) -> Vec<ProbeReport> {
        debug!("spawning QAD probes");

        let Some(ref quic_client) = self.socket_state.quic_client else {
            return Vec::new();
        };

        if do_full {
            // clear out existing connections if we are doing a full reset
            self.qad_conns.clear();
        }

        if let Some((url, conn)) = &self.qad_conns.v4 {
            // verify conn is still around
            if let Some(reason) = conn.conn.close_reason() {
                trace!(?url, "QAD v4 conn closed: {}", reason);
                self.qad_conns.v4.take();
            }
        }
        if let Some((url, conn)) = &self.qad_conns.v6 {
            // verify conn is still around
            if let Some(reason) = conn.conn.close_reason() {
                trace!(?url, "QAD v6 conn closed: {}", reason);
                self.qad_conns.v6.take();
            }
        }
        if self.qad_conns.v4.is_some() && self.qad_conns.v6.is_some() == if_state.have_v6 {
            trace!("not spawning QAD, already have probes");
            return self.qad_conns.current();
        }

        // TODO: randomize choice?
        const MAX_RELAYS: usize = 5;

        let mut v4_buf = JoinSet::new();
        let cancel_v4 = CancellationToken::new();
        let mut v6_buf = JoinSet::new();
        let cancel_v6 = CancellationToken::new();

        for relay_node in self.relay_map.nodes().take(MAX_RELAYS) {
            if if_state.have_v4 {
                debug!(?relay_node.url, "v4 QAD probe");
                let ip_mapped_addrs = self.socket_state.ip_mapped_addrs.clone();
                let relay_node = relay_node.clone();
                let dns_resolver = self.socket_state.dns_resolver.clone();
                let quic_client = quic_client.clone();

                v4_buf.spawn(
                    cancel_v4
                        .child_token()
                        .run_until_cancelled_owned(time::timeout(
                            PROBES_TIMEOUT,
                            run_probe_v4(ip_mapped_addrs, relay_node, quic_client, dns_resolver),
                        )),
                );
            }

            if if_state.have_v6 {
                debug!(?relay_node.url, "v6 QAD probe");
                let ip_mapped_addrs = self.socket_state.ip_mapped_addrs.clone();
                let relay_node = relay_node.clone();
                let dns_resolver = self.socket_state.dns_resolver.clone();
                let quic_client = quic_client.clone();
                v6_buf.spawn(
                    cancel_v6
                        .child_token()
                        .run_until_cancelled_owned(time::timeout(
                            PROBES_TIMEOUT,
                            run_probe_v6(ip_mapped_addrs, relay_node, quic_client, dns_resolver),
                        )),
                );
            }
        }

        let mut reports = Vec::new();

        loop {
            trace!("tick: qad probes");

            if reports.len() >= enough_relays {
                debug!("enough probes: {}", reports.len());
                cancel_v4.cancel();
                cancel_v6.cancel();
                break;
            }

            // TODO: verify select and join_next work as expected
            tokio::select! {
                biased;

                val = v4_buf.join_next(), if !v4_buf.is_empty() => {
                    if let Some(Ok(Some(Ok(res)))) = val {
                        match res {
                            Ok((r, conn)) => {
                                debug!(?r, "got v4 QAD conn");
                                let url = r.node.clone();
                                reports.push(ProbeReport::QadIpv4(r));
                                if self.qad_conns.v4.is_none() {
                                    self.qad_conns.v4.replace((url, conn));
                                } else {
                                    conn.conn.close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
                                }
                            }
                            Err(err) => {
                                debug!("probe v4 failed: {:?}", err);
                            }
                        }
                    } else {
                        dbg!(val);
                    }
                }
                val = v6_buf.join_next(), if !v6_buf.is_empty() => {
                    if let Some(Ok(Some(Ok(res)))) = val {
                        match res {
                            Ok((r, conn)) => {
                                debug!(?r, "got v6 QAD conn");
                                let url = r.node.clone();
                                reports.push(ProbeReport::QadIpv6(r));
                                if self.qad_conns.v6.is_none() {
                                    self.qad_conns.v6.replace((url, conn));
                                } else {
                                    conn.conn.close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
                                }
                            }
                            Err(err) => {
                                debug!("probe v6 failed: {:?}", err);
                            }
                        }
                    } else {
                        dbg!(val);
                    }
                }
                else => {
                    break;
                }
            }
        }

        reports
    }

    fn have_enough_reports(&self, enough_relays: usize, report: &Report) -> Option<Duration> {
        // Once we've heard from enough relay servers (3), start a timer to give up on the other
        // probes. The timer's duration is a function of whether this is our initial full
        // probe or an incremental one. For incremental ones, wait for the duration of the
        // slowest relay. For initial ones, double that.
        let latencies: Vec<Duration> = report.relay_latency.iter().map(|(_, l)| l).collect();
        let have_enough_latencies = latencies.len() >= enough_relays;

        if have_enough_latencies {
            let timeout = match self.reports.last.is_some() {
                true => Duration::from_secs(0),
                false => latencies
                    .iter()
                    .max()
                    .copied()
                    .unwrap_or(DEFAULT_MAX_LATENCY),
            };
            debug!(
                reports=latencies.len(),
                delay=?timeout,
                "Have enough probe reports, aborting further probes soon",
            );

            Some(timeout)
        } else {
            None
        }
    }

    /// Adds `r` to the set of recent Reports and mutates `r.preferred_relay` to contain the best recent one.
    fn add_report_history_and_set_preferred_relay(&mut self, r: &mut Report) {
        let mut prev_relay = None;
        if let Some(ref last) = self.reports.last {
            prev_relay.clone_from(&last.preferred_relay);

            // If we don't have new information, copy this from the last report
            if r.mapping_varies_by_dest_ipv4.is_none() {
                r.mapping_varies_by_dest_ipv4 = last.mapping_varies_by_dest_ipv4;
            }
            if r.mapping_varies_by_dest_ipv6.is_none() {
                r.mapping_varies_by_dest_ipv6 = last.mapping_varies_by_dest_ipv6;
            }
        }

        let now = Instant::now();
        const MAX_AGE: Duration = Duration::from_secs(5 * 60);

        // relay ID => its best recent latency in last MAX_AGE
        let mut best_recent = RelayLatencies::default();

        // chain the current report as we are still mutating it
        let prevs_iter = self
            .reports
            .prev
            .iter()
            .map(|(a, b)| -> (&Instant, &Report) { (a, b) });

        let mut to_remove = Vec::new();
        for (t, pr) in prevs_iter {
            if now.duration_since(*t) > MAX_AGE {
                to_remove.push(*t);
                continue;
            }
            best_recent.merge(&pr.relay_latency);
        }
        // merge in current run
        best_recent.merge(&r.relay_latency);

        for t in to_remove {
            self.reports.prev.remove(&t);
        }

        // Then, pick which currently-alive relay server from the
        // current report has the best latency over the past MAX_AGE.
        let mut best_any = Duration::default();
        let mut old_relay_cur_latency = Duration::default();
        {
            for (url, duration) in r.relay_latency.iter() {
                if Some(url) == prev_relay.as_ref() {
                    old_relay_cur_latency = duration;
                }
                if let Some(best) = best_recent.get(url) {
                    if r.preferred_relay.is_none() || best < best_any {
                        best_any = best;
                        r.preferred_relay.replace(url.clone());
                    }
                }
            }

            // If we're changing our preferred relay but the old one's still
            // accessible and the new one's not much better, just stick with
            // where we are.
            if prev_relay.is_some()
                && r.preferred_relay != prev_relay
                && !old_relay_cur_latency.is_zero()
                && best_any > old_relay_cur_latency / 3 * 2
            {
                r.preferred_relay = prev_relay;
            }
        }

        self.reports.prev.insert(now, r.clone());
        self.reports.last = Some(r.clone());
    }
}

async fn run_probe_v4(
    ip_mapped_addrs: Option<IpMappedAddresses>,
    relay_node: Arc<RelayNode>,
    quic_client: QuicClient,
    dns_resolver: DnsResolver,
) -> n0_snafu::Result<(QadProbeReport, QadConn)> {
    let relay_addr_orig = reportgen::get_relay_addr_ipv4(&dns_resolver, &relay_node).await?;
    let relay_addr =
        reportgen::maybe_to_mapped_addr(ip_mapped_addrs.as_ref(), relay_addr_orig.into());

    debug!(?relay_addr_orig, ?relay_addr, "relay addr v4");
    let host = relay_node.url.host_str().unwrap();
    let conn = quic_client.create_conn(relay_addr, host).await?;
    let mut receiver = conn.observed_external_addr();

    // wait for an addr
    let addr = receiver
        .wait_for(|addr| addr.is_some())
        .await
        .unwrap()
        .expect("known");
    let report = QadProbeReport {
        node: relay_node.url.clone(),
        addr: SocketAddr::new(addr.ip().to_canonical(), addr.port()),
        latency: conn.rtt(),
    };

    let observer = Watchable::new(None);
    // TODO: this is sad
    let ob = observer.clone();
    let node = relay_node.url.clone();
    let conn2 = conn.clone();
    let handle = task::spawn(async move {
        loop {
            let val = *receiver.borrow();
            // if we've sent to an ipv4 address, but received an observed address
            // that is ivp6 then the address is an [IPv4-Mapped IPv6 Addresses](https://doc.rust-lang.org/beta/std/net/struct.Ipv6Addr.html#ipv4-mapped-ipv6-addresses)
            let val = val.map(|val| SocketAddr::new(val.ip().to_canonical(), val.port()));
            let latency = conn2.rtt();
            trace!(?val, ?relay_addr, ?latency, "got addr V4");
            if ob
                .set(val.map(|addr| QadProbeReport {
                    node: node.clone(),
                    addr,
                    latency,
                }))
                .is_err()
            {
                // cancel if the observer is gone
                break;
            }
            if receiver.changed().await.is_err() {
                break;
            }
        }
    });
    let handle = AbortOnDropHandle::new(handle);

    Ok((
        report,
        QadConn {
            conn,
            observer,
            _handle: handle,
        },
    ))
}

async fn run_probe_v6(
    ip_mapped_addrs: Option<IpMappedAddresses>,
    relay_node: Arc<RelayNode>,
    quic_client: QuicClient,
    dns_resolver: DnsResolver,
) -> n0_snafu::Result<(QadProbeReport, QadConn)> {
    let relay_addr_orig = reportgen::get_relay_addr_ipv6(&dns_resolver, &relay_node).await?;
    let relay_addr =
        reportgen::maybe_to_mapped_addr(ip_mapped_addrs.as_ref(), relay_addr_orig.into());

    debug!(?relay_addr_orig, ?relay_addr, "relay addr v6");
    let host = relay_node.url.host_str().unwrap();
    let conn = quic_client.create_conn(relay_addr, host).await?;
    let mut receiver = conn.observed_external_addr();

    // wait for an addr
    let addr = receiver
        .wait_for(|addr| addr.is_some())
        .await
        .unwrap()
        .expect("known");
    let report = QadProbeReport {
        node: relay_node.url.clone(),
        addr: SocketAddr::new(addr.ip().to_canonical(), addr.port()),
        latency: conn.rtt(),
    };

    let observer = Watchable::new(None);
    // TODO: this is sad
    let ob = observer.clone();
    let node = relay_node.url.clone();
    let conn2 = conn.clone();
    let handle = task::spawn(async move {
        loop {
            let val = *receiver.borrow();
            // if we've sent to an ipv4 address, but received an observed address
            // that is ivp6 then the address is an IPv4-Mapped IPv6 Addresses
            let val = val.map(|val| SocketAddr::new(val.ip().to_canonical(), val.port()));
            let latency = conn2.rtt();
            trace!(?val, ?relay_addr, ?latency, "got addr V6");
            if ob
                .set(val.map(|addr| QadProbeReport {
                    node: node.clone(),
                    addr,
                    latency,
                }))
                .is_err()
            {
                // cancel if the observer is gone
                break;
            }
            if receiver.changed().await.is_err() {
                break;
            }
        }
    });
    let handle = AbortOnDropHandle::new(handle);

    Ok((
        report,
        QadConn {
            conn,
            observer,
            _handle: handle,
        },
    ))
}

#[cfg(test)]
mod test_utils {
    //! Creates a relay server against which to perform tests

    use iroh_relay::{server, RelayNode, RelayQuicConfig};

    pub(crate) async fn relay() -> (server::Server, RelayNode) {
        let server = server::Server::spawn(server::testing::server_config())
            .await
            .expect("should serve relay");
        let quic = Some(RelayQuicConfig {
            port: server.quic_addr().expect("server should run quic").port(),
        });
        let node_desc = RelayNode {
            url: server.https_url().expect("should work as relay"),
            quic,
        };

        (server, node_desc)
    }

    /// Create a [`crate::RelayMap`] of the given size.
    ///
    /// This function uses [`relay`]. Note that the returned map uses internal order that will
    /// often _not_ match the order of the servers.
    pub(crate) async fn relay_map(relays: usize) -> (Vec<server::Server>, crate::RelayMap) {
        let mut servers = Vec::with_capacity(relays);
        let mut nodes = Vec::with_capacity(relays);
        for _ in 0..relays {
            let (relay_server, node) = relay().await;
            servers.push(relay_server);
            nodes.push(node);
        }
        (servers, crate::RelayMap::from_iter(nodes))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use iroh_base::RelayUrl;
    use iroh_relay::dns::DnsResolver;
    use n0_snafu::{Result, ResultExt};
    use tokio_util::sync::CancellationToken;
    use tracing_test::traced_test;

    use super::*;
    use crate::net_report::probes::Probe;

    #[tokio::test]
    #[traced_test]
    async fn test_basic() -> Result<()> {
        let (server, relay) = test_utils::relay().await;
        let client_config = iroh_relay::client::make_dangerous_client_config();
        let ep = quinn::Endpoint::client(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)).e()?;
        let quic_addr_disc = QuicConfig {
            ep: ep.clone(),
            client_config,
            ipv4: true,
            ipv6: true,
        };
        let relay_map = RelayMap::from(relay);

        let resolver = DnsResolver::new();
        let opts = Options::default().quic_config(Some(quic_addr_disc.clone()));
        let mut client = Client::new(
            resolver.clone(),
            None,
            relay_map.clone(),
            opts.clone(),
            Default::default(),
        );
        let if_state = IfStateDetails::fake();

        // Note that the ProbePlan will change with each iteration.
        for i in 0..5 {
            let cancel = CancellationToken::new();
            println!("--round {}", i);
            let r = client.get_report(if_state.clone(), false).await;

            assert!(r.has_udp(), "want UDP");
            assert_eq!(
                r.relay_latency.len(),
                1,
                "expected 1 key in RelayLatency; got {}",
                r.relay_latency.len()
            );
            assert!(
                r.relay_latency.iter().next().is_some(),
                "expected key 1 in RelayLatency; got {:?}",
                r.relay_latency
            );
            assert!(r.global_v4.is_some(), "expected globalV4 set");
            assert!(r.preferred_relay.is_some(),);
            cancel.cancel();
        }

        ep.wait_idle().await;
        server.shutdown().await?;

        Ok(())
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_add_report_history_set_preferred_relay() -> Result {
        fn relay_url(i: u16) -> RelayUrl {
            format!("http://{i}.com").parse().unwrap()
        }

        // report returns a *Report from (relay host, Duration)+ pairs.
        fn report(a: impl IntoIterator<Item = (&'static str, u64)>) -> Option<Report> {
            let mut report = Report::default();
            for (s, d) in a {
                assert!(s.starts_with('d'), "invalid relay server key");
                let id: u16 = s[1..].parse().unwrap();
                report.relay_latency.update_relay(
                    relay_url(id),
                    Duration::from_secs(d),
                    Probe::QadIpv4,
                );
            }

            Some(report)
        }
        struct Step {
            /// Delay in seconds
            after: u64,
            r: Option<Report>,
        }
        struct Test {
            name: &'static str,
            steps: Vec<Step>,
            /// want PreferredRelay on final step
            want_relay: Option<RelayUrl>,
            // wanted len(c.prev)
            want_prev_len: usize,
        }

        let tests = [
            Test {
                name: "first_reading",
                steps: vec![Step {
                    after: 0,
                    r: report([("d1", 2), ("d2", 3)]),
                }],
                want_prev_len: 1,
                want_relay: Some(relay_url(1)),
            },
            Test {
                name: "with_two",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 2), ("d2", 3)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 3)]),
                    },
                ],
                want_prev_len: 2,
                want_relay: Some(relay_url(1)), // t0's d1 of 2 is still best
            },
            Test {
                name: "but_now_d1_gone",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 2), ("d2", 3)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 3)]),
                    },
                    Step {
                        after: 2,
                        r: report([("d2", 3)]),
                    },
                ],
                want_prev_len: 3,
                want_relay: Some(relay_url(2)), // only option
            },
            Test {
                name: "d1_is_back",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 2), ("d2", 3)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 3)]),
                    },
                    Step {
                        after: 2,
                        r: report([("d2", 3)]),
                    },
                    Step {
                        after: 3,
                        r: report([("d1", 4), ("d2", 3)]),
                    }, // same as 2 seconds ago
                ],
                want_prev_len: 4,
                want_relay: Some(relay_url(1)), // t0's d1 of 2 is still best
            },
            Test {
                name: "things_clean_up",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 1), ("d2", 2)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 1), ("d2", 2)]),
                    },
                    Step {
                        after: 2,
                        r: report([("d1", 1), ("d2", 2)]),
                    },
                    Step {
                        after: 3,
                        r: report([("d1", 1), ("d2", 2)]),
                    },
                    Step {
                        after: 10 * 60,
                        r: report([("d3", 3)]),
                    },
                ],
                want_prev_len: 1, // t=[0123]s all gone. (too old, older than 10 min)
                want_relay: Some(relay_url(3)), // only option
            },
            Test {
                name: "preferred_relay_hysteresis_no_switch",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 4), ("d2", 5)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 3)]),
                    },
                ],
                want_prev_len: 2,
                want_relay: Some(relay_url(1)), // 2 didn't get fast enough
            },
            Test {
                name: "preferred_relay_hysteresis_do_switch",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 4), ("d2", 5)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 1)]),
                    },
                ],
                want_prev_len: 2,
                want_relay: Some(relay_url(2)), // 2 got fast enough
            },
        ];
        let resolver = DnsResolver::new();
        for mut tt in tests {
            println!("test: {}", tt.name);
            let relay_map = RelayMap::empty();
            let opts = Options::default();
            let mut client =
                Client::new(resolver.clone(), None, relay_map, opts, Default::default());
            for s in &mut tt.steps {
                // trigger the timer
                tokio::time::advance(Duration::from_secs(s.after)).await;
                client.add_report_history_and_set_preferred_relay(s.r.as_mut().unwrap());
            }
            let last_report = tt.steps.last().unwrap().r.clone().unwrap();
            let got = client.reports.prev.len();
            let want = tt.want_prev_len;
            assert_eq!(got, want, "prev length");
            let got = &last_report.preferred_relay;
            let want = &tt.want_relay;
            assert_eq!(got, want, "preferred_relay");
        }

        Ok(())
    }
}
