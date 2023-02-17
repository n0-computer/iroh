//! Implements a socket that can change its communication path while in use, actively searching for the best way to communicate.
//!
//! Based on tailscale/wgengine/magicsock

use std::collections::HashSet;
use std::{net::SocketAddr, time::Duration};

use futures::Future;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{self, Instant};

use super::derp;

mod conn;
mod endpoint;
mod rebinding_conn;

pub use self::conn::Conn;

use self::endpoint::Endpoint;

/// UDP socket read/write buffer size (7MB). The value of 7MB is chosen as it
/// is the max supported by a default configuration of macOS. Some platforms will silently clamp the value.
const SOCKET_BUFFER_SIZE: usize = 7 << 20;

/// Reports whether magicsock should enable the DERP return path optimization (Issue 150).
fn use_derp_route() -> bool {
    // if b, ok := debugUseDerpRoute().Get(); ok {
    //     return b;
    // }

    // ob := controlclient.DERPRouteFlag();
    // if v, ok := ob.Get(); ok {
    //     return v
    // }
    true
}

/// All the information magicsock tracks about a particular peer.
#[derive(Clone)]
pub struct PeerInfo {
    pub ep: Endpoint,
    /// An inverted version of `PeerMap.by_ip_port` (below), so
    /// that when we're deleting this node, we can rapidly find out the
    /// keys that need deleting from `PeerMap::by_ip_port` without having to
    /// iterate over every `SocketAddr known for any peer.
    pub ip_ports: HashSet<SocketAddr>, // TODO: figure out clone behaviour
}

impl PeerInfo {
    pub fn new(ep: Endpoint) -> Self {
        PeerInfo {
            ep,
            ip_ports: Default::default(),
        }
    }
}

/// Contains fields for an active DERP connection.
#[derive(Debug)]
struct ActiveDerp {
    c: derp::http::Client,
    // cancel  context.CancelFunc
    // writeCh chan<- derpWriteRequest
    /// The time of the last request for its write
    // channel (currently even if there was no write).
    // It is always non-nil and initialized to a non-zero Time.
    last_write: Instant,
    create_time: Instant,
}

/// How long since the last activity we try to keep an established endpoint peering alive.
/// It's also the idle time at which we stop doing STUN queries to keep NAT mappings alive.
const SESSION_ACTIVE_TIMEOUT: Duration = Duration::from_secs(45);

/// How often we try to upgrade to a better patheven if we have some non-DERP route that works.
const UPGRADE_INTERVAL: Duration = Duration::from_secs(1 * 60);

/// How often pings to the best UDP address are sent.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);

/// How long we trust a UDP address as the exclusive path (without using DERP) without having heard a Pong reply.
const TRUST_UDP_ADDR_DURATION: Duration = Duration::from_millis(6500);

/// The latency at or under which we don't try to upgrade to a better path.
const GOOD_ENOUGH_LATENCY: Duration = Duration::from_millis(5);

/// How long a non-home DERP connection needs to be idle (last written to) before we close it.
const DERP_INACTIVE_CLEANUP_TIME: Duration = Duration::from_secs(60);

/// How often `clean_stale_derp` runs when there are potentially-stale DERP connections to close.
const DERP_CLEAN_STALE_INTERVAL: Duration = Duration::from_secs(15);

/// How long we consider a STUN-derived endpoint valid for. UDP NAT mappings typically
/// expire at 30 seconds, so this is a few seconds shy of that.
const ENDPOINTS_FRESH_ENOUGH_DURATION: Duration = Duration::from_secs(27);

/// How long we wait for a pong reply before assuming it's never coming.
const PING_TIMEOUT_DURATION: Duration = Duration::from_secs(5);

/// The minimum time between pings to an endpoint. (Except in the case of CallMeMaybe frames
/// resetting the counter, as the first pings likely didn't through the firewall)
const DISCO_PING_INTERVAL: Duration = Duration::from_secs(5);

/// How many `PongReply` values we keep per `EndpointState`.
const PONG_HISTORY_COUNT: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PongReply {
    latency: Duration,
    /// When we received the pong.
    pong_at: Instant,
    // The pong's src (usually same as endpoint map key).
    from: SocketAddr,
    // What they reported they heard.
    pong_src: SocketAddr,
}

#[derive(Debug)]
pub struct SentPing {
    pub to: SocketAddr,
    pub at: Instant,
    // timeout timer
    pub timer: Timer,
    pub purpose: DiscoPingPurpose,
}

/// The reason why a discovery ping message was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoPingPurpose {
    /// Means that purpose of a ping was to see if a path was valid.
    Discovery,
    /// Means that purpose of a ping was whether a peer was still there.
    Heartbeat,
    /// Mmeans that the user is running "tailscale ping" from the CLI. These types of pings can go over DERP.
    Cli,
}

// TODO: once derp::http::Client is implemented

// // derpAddrFamSelector is the derphttp.AddressFamilySelector we pass
// // to derphttp.Client.SetAddressFamilySelector.
// //
// // It provides the hint as to whether in an IPv4-vs-IPv6 race that
// // IPv4 should be held back a bit to give IPv6 a better-than-50/50
// // chance of winning. We only return true when we believe IPv6 will
// // work anyway, so we don't artificially delay the connection speed.
// type derpAddrFamSelector struct{ c *Conn }

// func (s derpAddrFamSelector) PreferIPv6() bool {
// 	if r := s.c.lastNetCheckReport.Load(); r != nil {
// 		return r.IPv6
// 	}
// 	return false
// }

// TODO: metrics
// var (
// 	metricNumPeers     = clientmetric.NewGauge("magicsock_netmap_num_peers")
// 	metricNumDERPConns = clientmetric.NewGauge("magicsock_num_derp_conns")

// 	metricRebindCalls     = clientmetric.NewCounter("magicsock_rebind_calls")
// 	metricReSTUNCalls     = clientmetric.NewCounter("magicsock_restun_calls")
// 	metricUpdateEndpoints = clientmetric.NewCounter("magicsock_update_endpoints")

// 	// Sends (data or disco)
// 	metricSendDERPQueued      = clientmetric.NewCounter("magicsock_send_derp_queued")
// 	metricSendDERPErrorChan   = clientmetric.NewCounter("magicsock_send_derp_error_chan")
// 	metricSendDERPErrorClosed = clientmetric.NewCounter("magicsock_send_derp_error_closed")
// 	metricSendDERPErrorQueue  = clientmetric.NewCounter("magicsock_send_derp_error_queue")
// 	metricSendUDP             = clientmetric.NewCounter("magicsock_send_udp")
// 	metricSendUDPError        = clientmetric.NewCounter("magicsock_send_udp_error")
// 	metricSendDERP            = clientmetric.NewCounter("magicsock_send_derp")
// 	metricSendDERPError       = clientmetric.NewCounter("magicsock_send_derp_error")

// 	// Data packets (non-disco)
// 	metricSendData            = clientmetric.NewCounter("magicsock_send_data")
// 	metricSendDataNetworkDown = clientmetric.NewCounter("magicsock_send_data_network_down")
// 	metricRecvDataDERP        = clientmetric.NewCounter("magicsock_recv_data_derp")
// 	metricRecvDataIPv4        = clientmetric.NewCounter("magicsock_recv_data_ipv4")
// 	metricRecvDataIPv6        = clientmetric.NewCounter("magicsock_recv_data_ipv6")

// 	// Disco packets
// 	metricSendDiscoUDP         = clientmetric.NewCounter("magicsock_disco_send_udp")
// 	metricSendDiscoDERP        = clientmetric.NewCounter("magicsock_disco_send_derp")
// 	metricSentDiscoUDP         = clientmetric.NewCounter("magicsock_disco_sent_udp")
// 	metricSentDiscoDERP        = clientmetric.NewCounter("magicsock_disco_sent_derp")
// 	metricSentDiscoPing        = clientmetric.NewCounter("magicsock_disco_sent_ping")
// 	metricSentDiscoPong        = clientmetric.NewCounter("magicsock_disco_sent_pong")
// 	metricSentDiscoCallMeMaybe = clientmetric.NewCounter("magicsock_disco_sent_callmemaybe")
// 	metricRecvDiscoBadPeer     = clientmetric.NewCounter("magicsock_disco_recv_bad_peer")
// 	metricRecvDiscoBadKey      = clientmetric.NewCounter("magicsock_disco_recv_bad_key")
// 	metricRecvDiscoBadParse    = clientmetric.NewCounter("magicsock_disco_recv_bad_parse")

// 	metricRecvDiscoUDP                 = clientmetric.NewCounter("magicsock_disco_recv_udp")
// 	metricRecvDiscoDERP                = clientmetric.NewCounter("magicsock_disco_recv_derp")
// 	metricRecvDiscoPing                = clientmetric.NewCounter("magicsock_disco_recv_ping")
// 	metricRecvDiscoPong                = clientmetric.NewCounter("magicsock_disco_recv_pong")
// 	metricRecvDiscoCallMeMaybe         = clientmetric.NewCounter("magicsock_disco_recv_callmemaybe")
// 	metricRecvDiscoCallMeMaybeBadNode  = clientmetric.NewCounter("magicsock_disco_recv_callmemaybe_bad_node")
// 	metricRecvDiscoCallMeMaybeBadDisco = clientmetric.NewCounter("magicsock_disco_recv_callmemaybe_bad_disco")

// 	// metricDERPHomeChange is how many times our DERP home region DI has
// 	// changed from non-zero to a different non-zero.
// 	metricDERPHomeChange = clientmetric.NewCounter("derp_home_change")

// 	// Disco packets received bpf read path
// 	metricRecvDiscoPacketIPv4 = clientmetric.NewCounter("magicsock_disco_recv_bpf_ipv4")
// 	metricRecvDiscoPacketIPv6 = clientmetric.NewCounter("magicsock_disco_recv_bpf_ipv6")
// )

// TODO: better place

/// A timer that works similar to golangs `Timer`.
#[derive(Debug)]
pub struct Timer {
    s: mpsc::Sender<Duration>,
    t: JoinHandle<()>,
}

impl Timer {
    /// Will trigger the execution of `f` after time `d` once.
    pub fn after<F>(d: Duration, f: F) -> Self
    where
        F: Future<Output = ()> + Send + Sync + 'static,
    {
        let (s, mut r) = mpsc::channel(1);

        let t = tokio::task::spawn(async move {
            let sleep = time::sleep(d);
            tokio::pin!(sleep);

            loop {
                tokio::select! {
                    biased;

                    msg = r.recv() => match msg {
                        Some(new_duration) => {
                            // Reset when a new duration was received.
                            sleep.as_mut().reset(Instant::now() + new_duration);
                        }
                        None => {
                            // dropped, end this
                            break;
                        }
                    },
                    _ = &mut sleep => {
                        // expired
                        f.await;
                        break;
                    }
                }
            }
        });

        Timer { s, t }
    }

    pub async fn reset(&self, d: Duration) {
        self.s.send(d).await.ok();
    }

    /// Returns true if not yet expired.
    pub async fn stop(self) -> bool {
        self.t.abort();
        // If the task was not completed yet, the abort triggers an error.
        self.t.await.is_err()
    }
}

impl Future for Timer {
    type Output = ();

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.t).poll(cx).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use super::*;

    #[tokio::test]
    async fn test_timer_success() {
        let val = Arc::new(AtomicBool::new(false));

        assert!(!val.load(Ordering::Relaxed));

        let moved_val = val.clone();
        let timer = Timer::after(Duration::from_millis(10), async move {
            moved_val.store(true, Ordering::Relaxed);
        });

        assert!(!val.load(Ordering::Relaxed));

        timer.await;
        assert!(val.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_timer_abort() {
        let val = Arc::new(AtomicBool::new(false));

        assert!(!val.load(Ordering::Relaxed));

        let moved_val = val.clone();
        let timer = Timer::after(Duration::from_millis(10), async move {
            moved_val.store(true, Ordering::Relaxed);
        });

        assert!(!val.load(Ordering::Relaxed));
        assert!(timer.stop().await);
        assert!(!val.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_timer_abort_late() {
        let val = Arc::new(AtomicBool::new(false));

        assert!(!val.load(Ordering::Relaxed));

        let moved_val = val.clone();
        let timer = Timer::after(Duration::from_millis(10), async move {
            moved_val.store(true, Ordering::Relaxed);
        });

        assert!(!val.load(Ordering::Relaxed));
        time::sleep(Duration::from_millis(15)).await;

        assert!(!timer.stop().await);
        assert!(val.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_timer_reset() {
        let val = Arc::new(AtomicBool::new(false));

        assert!(!val.load(Ordering::Relaxed));

        let moved_val = val.clone();
        let timer = Timer::after(Duration::from_millis(10), async move {
            moved_val.store(true, Ordering::Relaxed);
        });

        assert!(!val.load(Ordering::Relaxed));
        time::sleep(Duration::from_millis(5)).await;

        // not yet expired
        assert!(!val.load(Ordering::Relaxed));
        // reset for another 10ms
        timer.reset(Duration::from_millis(20)).await;

        // would have expired if not reset
        time::sleep(Duration::from_millis(5)).await;
        assert!(!val.load(Ordering::Relaxed));

        // definitely expired now
        time::sleep(Duration::from_millis(25)).await;
        assert!(val.load(Ordering::Relaxed));
    }
}
