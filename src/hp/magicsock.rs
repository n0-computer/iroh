//! Implements a socket that can change its communication path while in use, actively searching for the best way to communicate.
//!
//! Based on tailscale/wgengine/magicsock

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    net::UdpSocket,
    sync::Mutex,
    time::{self, Instant},
};

use super::derp;

mod conn;
mod endpoint;
mod rebinding_conn;

pub use self::conn::Conn;
pub use self::endpoint::Endpoint;

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
    return true;
}

/// All the information magicsock tracks about a particular peer.
#[derive(Clone)]
struct PeerInfo {
    ep: Endpoint,
    // ipPorts is an inverted version of peerMap.byIPPort (below), so
    // that when we're deleting this node, we can rapidly find out the
    // keys that need deleting from peerMap.byIPPort without having to
    // iterate over every IPPort known for any peer.
    ip_ports: Arc<HashMap<SocketAddr, bool>>,
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

/// A wireguard-go conn.Bind for a Conn. It bridges the behavior of wireguard-go and a Conn.
/// wireguard-go calls Close then Open on device.Up.
/// That won't work well for a Conn, which is only closed on shutdown.
/// The subsequent Close is a real close.
struct ConnBind {
    conn: UdpSocket,
    closed: Mutex<bool>,
}

// func (c *connBind) BatchSize() int {
// 	// TODO(raggi): determine by properties rather than hardcoding platform behavior
// 	switch runtime.GOOS {
// 	case "linux":
// 		return conn.DefaultBatchSize
// 	default:
// 		return 1
// 	}
// }

// // Open is called by WireGuard to create a UDP binding.
// // The ignoredPort comes from wireguard-go, via the wgcfg config.
// // We ignore that port value here, since we have the local port available easily.
// func (c *connBind) Open(ignoredPort uint16) ([]conn.ReceiveFunc, uint16, error) {
// 	c.mu.Lock()
// 	defer c.mu.Unlock()
// 	if !c.closed {
// 		return nil, 0, errors.New("magicsock: connBind already open")
// 	}
// 	c.closed = false
// 	fns := []conn.ReceiveFunc{c.receiveIPv4, c.receiveIPv6, c.receiveDERP}
// 	if runtime.GOOS == "js" {
// 		fns = []conn.ReceiveFunc{c.receiveDERP}
// 	}
// 	// TODO: Combine receiveIPv4 and receiveIPv6 and receiveIP into a single
// 	// closure that closes over a *RebindingUDPConn?
// 	return fns, c.LocalPort(), nil
// }

// // SetMark is used by wireguard-go to set a mark bit for packets to avoid routing loops.
// // We handle that ourselves elsewhere.
// func (c *connBind) SetMark(value uint32) error {
// 	return nil
// }

// // Close closes the connBind, unless it is already closed.
// func (c *connBind) Close() error {
// 	c.mu.Lock()
// 	defer c.mu.Unlock()
// 	if c.closed {
// 		return nil
// 	}
// 	c.closed = true
// 	// Unblock all outstanding receives.
// 	c.pconn4.Close()
// 	c.pconn6.Close()
// 	if c.closeDisco4 != nil {
// 		c.closeDisco4.Close()
// 	}
// 	if c.closeDisco6 != nil {
// 		c.closeDisco6.Close()
// 	}
// 	// Send an empty read result to unblock receiveDERP,
// 	// which will then check connBind.Closed.
// 	// connBind.Closed takes c.mu, but c.derpRecvCh is buffered.
// 	c.derpRecvCh <- derpReadResult{}
// 	return nil
// }

// // Closed reports whether c is closed.
// func (c *connBind) Closed() bool {
// 	c.mu.Lock()
// 	defer c.mu.Unlock()
// 	return c.closed
// }

// func (u udpConnWithBatchOps) WriteBatch(ms []ipv6.Message, flags int) (int, error) {
// 	return u.xpc.WriteBatch(ms, flags)
// }

// func (u udpConnWithBatchOps) ReadBatch(ms []ipv6.Message, flags int) (int, error) {
// 	return u.xpc.ReadBatch(ms, flags)
// }

// // upgradePacketConn may upgrade a nettype.PacketConn to a udpConnWithBatchOps.
// func upgradePacketConn(p nettype.PacketConn, network string) nettype.PacketConn {
// 	uc, ok := p.(*net.UDPConn)
// 	if ok && runtime.GOOS == "linux" && (network == "udp4" || network == "udp6") {
// 		// recvmmsg/sendmmsg were added in 2.6.33 but we support down to 2.6.32
// 		// for old NAS devices. See https://github.com/tailscale/tailscale/issues/6807.
// 		// As a cheap heuristic: if the Linux kernel starts with "2", just consider
// 		// it too old for the fast paths. Nobody who cares about performance runs such
// 		// ancient kernels.
// 		if strings.HasPrefix(hostinfo.GetOSVersion(), "2") {
// 			return p
// 		}
// 		// Non-Linux does not support batch operations. x/net will fall back to
// 		// recv/sendmsg, but not all platforms have recv/sendmsg support. Keep
// 		// this simple for now.
// 		return newUDPConnWithBatchOps(uc, network)
// 	}
// 	return p
// }

// func newBlockForeverConn() *blockForeverConn {
// 	c := new(blockForeverConn)
// 	c.cond = sync.NewCond(&c.mu)
// 	return c
// }

// // blockForeverConn is a net.PacketConn whose reads block until it is closed.
// type blockForeverConn struct {
// 	mu     sync.Mutex
// 	cond   *sync.Cond
// 	closed bool
// }

// func (c *blockForeverConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
// 	c.mu.Lock()
// 	for !c.closed {
// 		c.cond.Wait()
// 	}
// 	c.mu.Unlock()
// 	return 0, nil, net.ErrClosed
// }

// func (c *blockForeverConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
// 	// Silently drop writes.
// 	return len(p), nil
// }

// func (c *blockForeverConn) WriteToUDPAddrPort(p []byte, addr netip.AddrPort) (int, error) {
// 	// Silently drop writes.
// 	return len(p), nil
// }

// func (c *blockForeverConn) ReadBatch(p []ipv6.Message, flags int) (int, error) {
// 	c.mu.Lock()
// 	for !c.closed {
// 		c.cond.Wait()
// 	}
// 	c.mu.Unlock()
// 	return 0, net.ErrClosed
// }

// func (c *blockForeverConn) WriteBatch(p []ipv6.Message, flags int) (int, error) {
// 	// Silently drop writes.
// 	return len(p), nil
// }

// func (c *blockForeverConn) LocalAddr() net.Addr {
// 	// Return a *net.UDPAddr because lots of code assumes that it will.
// 	return new(net.UDPAddr)
// }

// func (c *blockForeverConn) Close() error {
// 	c.mu.Lock()
// 	defer c.mu.Unlock()
// 	if c.closed {
// 		return net.ErrClosed
// 	}
// 	c.closed = true
// 	c.cond.Broadcast()
// 	return nil
// }

// func (c *blockForeverConn) SetDeadline(t time.Time) error      { return errors.New("unimplemented") }
// func (c *blockForeverConn) SetReadDeadline(t time.Time) error  { return errors.New("unimplemented") }
// func (c *blockForeverConn) SetWriteDeadline(t time.Time) error { return errors.New("unimplemented") }

// // simpleDur rounds d such that it stringifies to something short.
// func simpleDur(d time.Duration) time.Duration {
// 	if d < time.Second {
// 		return d.Round(time.Millisecond)
// 	}
// 	if d < time.Minute {
// 		return d.Round(time.Second)
// 	}
// 	return d.Round(time.Minute)
// }

// func sbPrintAddr(sb *strings.Builder, a netip.AddrPort) {
// 	is6 := a.Addr().Is6()
// 	if is6 {
// 		sb.WriteByte('[')
// 	}
// 	fmt.Fprintf(sb, "%s", a.Addr())
// 	if is6 {
// 		sb.WriteByte(']')
// 	}
// 	fmt.Fprintf(sb, ":%d", a.Port())
// }

// func ippDebugString(ua netip.AddrPort) string {
// 	if ua.Addr() == derpMagicIPAddr {
// 		return fmt.Sprintf("derp-%d", ua.Port())
// 	}
// 	return ua.String()
// }

// const (
// 	// sessionActiveTimeout is how long since the last activity we
// 	// try to keep an established endpoint peering alive.
// 	// It's also the idle time at which we stop doing STUN queries to
// 	// keep NAT mappings alive.
// 	sessionActiveTimeout = 45 * time.Second

// 	// upgradeInterval is how often we try to upgrade to a better path
// 	// even if we have some non-DERP route that works.
// 	upgradeInterval = 1 * time.Minute

// 	// heartbeatInterval is how often pings to the best UDP address
// 	// are sent.
// 	heartbeatInterval = 3 * time.Second

// 	// trustUDPAddrDuration is how long we trust a UDP address as the exclusive
// 	// path (without using DERP) without having heard a Pong reply.
// 	trustUDPAddrDuration = 6500 * time.Millisecond

// 	// goodEnoughLatency is the latency at or under which we don't
// 	// try to upgrade to a better path.
// 	goodEnoughLatency = 5 * time.Millisecond

// 	// derpInactiveCleanupTime is how long a non-home DERP connection
// 	// needs to be idle (last written to) before we close it.
// 	derpInactiveCleanupTime = 60 * time.Second

// 	// derpCleanStaleInterval is how often cleanStaleDerp runs when there
// 	// are potentially-stale DERP connections to close.
// 	derpCleanStaleInterval = 15 * time.Second

// 	// endpointsFreshEnoughDuration is how long we consider a
// 	// STUN-derived endpoint valid for. UDP NAT mappings typically
// 	// expire at 30 seconds, so this is a few seconds shy of that.
// 	endpointsFreshEnoughDuration = 27 * time.Second
// )

// // Constants that are variable for testing.
// var (
// 	// pingTimeoutDuration is how long we wait for a pong reply before
// 	// assuming it's never coming.
// 	pingTimeoutDuration = 5 * time.Second

// 	// discoPingInterval is the minimum time between pings
// 	// to an endpoint. (Except in the case of CallMeMaybe frames
// 	// resetting the counter, as the first pings likely didn't through
// 	// the firewall)
// 	discoPingInterval = 5 * time.Second
// )

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
struct SentPing {
    to: SocketAddr,
    at: Instant,
    // timeout timer
    timer: time::Interval,
    purpose: DiscoPingPurpose,
}

/// The reason why a discovery ping message was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoPingPurpose {
    /// Means that purpose of a ping was to see if a path was valid.
    Discovery,
    /// Means that purpose of a ping was whether a peer was still there.
    Heartbeat,
    /// Mmeans that the user is running "tailscale ping" from the CLI. These types of pings can go over DERP.
    Cli,
}

// // derpStr replaces DERP IPs in s with "derp-".
// func derpStr(s string) string { return strings.ReplaceAll(s, "127.3.3.40:", "derp-") }

// // ippEndpointCache is a mutex-free single-element cache, mapping from
// // a single netip.AddrPort to a single endpoint.
// type ippEndpointCache struct {
// 	ipp netip.AddrPort
// 	gen int64
// 	de  *endpoint
// }

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
