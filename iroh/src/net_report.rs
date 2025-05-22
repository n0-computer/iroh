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

use std::{collections::BTreeMap, fmt::Debug, sync::Arc};

#[cfg(not(wasm_browser))]
use iroh_relay::dns::DnsResolver;
use iroh_relay::RelayMap;
use n0_future::time::{Duration, Instant};
use nested_enum_utils::common_fields;
#[cfg(not(wasm_browser))]
use netwatch::UdpSocket;
use reportgen::{ActorRunError, ProbeFinished, ProbeReport};
use snafu::Snafu;
use tracing::{debug, trace};

mod defaults;
#[cfg(not(wasm_browser))]
mod dns;
mod ip_mapped_addrs;
mod metrics;
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

#[cfg(not(wasm_browser))]
use self::reportgen::SocketState;
pub use self::{
    metrics::Metrics,
    options::Options,
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
    /// The port mapper client, if those are requested.
    ///
    /// The port mapper is responsible for talking to routers via UPnP and the like to try
    /// and open ports.
    #[cfg(not(wasm_browser))]
    port_mapper: Option<portmapper::Client>,
    /// The DNS resolver to use for probes that need to perform DNS lookups
    #[cfg(not(wasm_browser))]
    dns_resolver: DnsResolver,
    /// The [`IpMappedAddresses`] that allows you to do QAD in iroh
    #[cfg(not(wasm_browser))]
    ip_mapped_addrs: Option<IpMappedAddresses>,
    metrics: Arc<Metrics>,

    /// A collection of previously generated reports.
    ///
    /// Sometimes it is useful to look at past reports to decide what to do.
    reports: Reports,
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
        #[cfg(not(wasm_browser))] port_mapper: Option<portmapper::Client>,
        #[cfg(not(wasm_browser))] dns_resolver: DnsResolver,
        #[cfg(not(wasm_browser))] ip_mapped_addrs: Option<IpMappedAddresses>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Client {
            #[cfg(not(wasm_browser))]
            port_mapper,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            #[cfg(not(wasm_browser))]
            ip_mapped_addrs,
            metrics,
            reports: Reports::default(),
        }
    }

    /// Generates a [`Report`].
    ///
    /// Look at [`Options`] for the different configuration options.
    pub(crate) async fn get_report(
        &mut self,
        relay_map: RelayMap,
        opts: Options,
    ) -> Result<Report, ReportError> {
        debug!("net_report starting");

        let protocols = opts.to_protocols();
        #[cfg(not(wasm_browser))]
        let socket_state = SocketState {
            port_mapper: self.port_mapper.clone(),
            quic_config: opts.quic_config,
            dns_resolver: self.dns_resolver.clone(),
            ip_mapped_addrs: self.ip_mapped_addrs.clone(),
        };
        trace!("Attempting probes for protocols {protocols:#?}");

        let now = Instant::now();

        let mut do_full = self.reports.next_full
            || now.duration_since(self.reports.last_full) > FULL_REPORT_INTERVAL;

        // If the last report had a captive portal and reported no UDP access,
        // it's possible that we didn't get a useful net_report due to the
        // captive portal blocking us. If so, make this report a full (non-incremental) one.
        if !do_full {
            if let Some(ref last) = self.reports.last {
                do_full = !last.udp && last.captive_portal.unwrap_or_default();
            }
        }
        if do_full {
            self.reports.last = None; // causes ProbePlan::new below to do a full (initial) plan
            self.reports.next_full = false;
            self.reports.last_full = now;
            self.metrics.reports_full.inc();
        }
        self.metrics.reports.inc();

        let enough_relays = std::cmp::min(relay_map.len(), ENOUGH_NODES);
        let (actor, mut probe_rx) = reportgen::Client::new(
            self.reports.last.clone(),
            relay_map,
            protocols,
            #[cfg(not(wasm_browser))]
            socket_state,
            #[cfg(any(test, feature = "test-utils"))]
            opts.insecure_skip_relay_cert_verify,
        );

        let mut report = Report {
            os_has_ipv6: os_has_ipv6(),
            ..Default::default()
        };

        let mut timeout_fut = std::pin::pin!(MaybeFuture::default());

        loop {
            tokio::select! {
                biased;

                _ = &mut timeout_fut, if timeout_fut.is_some() => {
                    drop(actor); // shuts down the probes
                    break;
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
                                if let Some(timeout) = self.have_enough_reports(enough_relays, &report) {
                                    timeout_fut.as_mut().set_future(tokio::time::sleep(timeout));
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
                        #[cfg(not(wasm_browser))]
                        ProbeFinished::Portmap(portmap) => {
                            report.portmap_probe = portmap;
                        }
                    }
                }
            }
        }

        self.add_report_history_and_set_preferred_relay(&mut report);
        debug!("{report:?}");

        Ok(report)
    }

    fn have_enough_reports(&self, enough_relays: usize, report: &Report) -> Option<Duration> {
        // Once we've heard from enough relay servers (3), start a timer to give up on the other
        // probes. The timer's duration is a function of whether this is our initial full
        // probe or an incremental one. For incremental ones, wait for the duration of the
        // slowest relay. For initial ones, double that.
        let latencies: Vec<Duration> = report.relay_latency.iter().map(|(_, l)| l).collect();
        let have_enough_latencies = latencies.len() >= enough_relays;

        if have_enough_latencies {
            let timeout = latencies
                .iter()
                .max()
                .copied()
                .unwrap_or(DEFAULT_MAX_LATENCY);
            let timeout = match self.reports.last.is_some() {
                true => timeout,
                false => timeout * 2,
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

#[allow(missing_docs)]
#[common_fields({
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ReportError {
    #[snafu(display("Report aborted early"))]
    Abort { reason: ActorRunError },
    #[snafu(display("Report generation is already running"))]
    AlreadyRunning {},
    #[snafu(display("Internal actor is gone"))]
    ActorGone {},
}

/// Test if IPv6 works at all, or if it's been hard disabled at the OS level.
#[cfg(not(wasm_browser))]
fn os_has_ipv6() -> bool {
    UdpSocket::bind_local_v6(0).is_ok()
}

/// Always returns false in browsers
#[cfg(wasm_browser)]
fn os_has_ipv6() -> bool {
    false
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
            stun_only: false, // the checks above and below guarantee both stun and relay
            stun_port: server.stun_addr().expect("server should serve stun").port(),
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
    use n0_snafu::{Result, ResultExt};
    use netwatch::IpFamily;

    use tokio_util::sync::CancellationToken;
    use tracing_test::traced_test;

    use super::*;
    use crate::net_report::{dns, reportgen::ProbeProto};

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

        let resolver = dns::tests::resolver();
        let mut client = Client::new(None, resolver.clone(), None, Default::default());

        // Note that the ProbePlan will change with each iteration.
        for i in 0..5 {
            let cancel = CancellationToken::new();
            println!("--round {}", i);
            let r = client
                .get_report(
                    relay_map.clone(),
                    Options::default().quic_config(Some(quic_addr_disc.clone())),
                )
                .await?;

            assert!(r.udp, "want UDP");
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
                    ProbeProto::QadIpv4,
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
        let resolver = dns::tests::resolver();
        for mut tt in tests {
            println!("test: {}", tt.name);
            let mut client = Client::new(None, resolver.clone(), None, Default::default());
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
