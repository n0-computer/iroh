//! Implements a socket that can change its communication path while in use, actively searching for the best way to communicate.
//!
//! Based on tailscale/wgengine/magicsock

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    net::UdpSocket,
    sync::{Mutex, RwLock},
    time::{self, Instant},
};

use super::{derp, stun};

mod conn;
mod endpoint;

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

// // Close closes the connection.
// //
// // Only the first close does anything. Any later closes return nil.
// func (c *Conn) Close() error {
// 	c.mu.Lock()
// 	defer c.mu.Unlock()
// 	if c.closed {
// 		return nil
// 	}
// 	c.closing.Store(true)
// 	if c.derpCleanupTimerArmed {
// 		c.derpCleanupTimer.Stop()
// 	}
// 	c.stopPeriodicReSTUNTimerLocked()
// 	c.portMapper.Close()

// 	c.peerMap.forEachEndpoint(func(ep *endpoint) {
// 		ep.stopAndReset()
// 	})

// 	c.closed = true
// 	c.connCtxCancel()
// 	c.closeAllDerpLocked("conn-close")
// 	// Ignore errors from c.pconnN.Close.
// 	// They will frequently have been closed already by a call to connBind.Close.
// 	c.pconn6.Close()
// 	c.pconn4.Close()

// 	// Wait on goroutines updating right at the end, once everything is
// 	// already closed. We want everything else in the Conn to be
// 	// consistently in the closed state before we release mu to wait
// 	// on the endpoint updater & derphttp.Connect.
// 	for c.goroutinesRunningLocked() {
// 		c.muCond.Wait()
// 	}
// 	return nil
// }

// func (c *Conn) goroutinesRunningLocked() bool {
// 	if c.endpointsUpdateActive {
// 		return true
// 	}
// 	// The goroutine running dc.Connect in derpWriteChanOfAddr may linger
// 	// and appear to leak, as observed in https://github.com/tailscale/tailscale/issues/554.
// 	// This is despite the underlying context being cancelled by connCtxCancel above.
// 	// To avoid this condition, we must wait on derpStarted here
// 	// to ensure that this goroutine has exited by the time Close returns.
// 	// We only do this if derpWriteChanOfAddr has executed at least once:
// 	// on the first run, it sets firstDerp := true and spawns the aforementioned goroutine.
// 	// To detect this, we check activeDerp, which is initialized to non-nil on the first run.
// 	if c.activeDerp != nil {
// 		select {
// 		case <-c.derpStarted:
// 			break
// 		default:
// 			return true
// 		}
// 	}
// 	return false
// }

// func maxIdleBeforeSTUNShutdown() time.Duration {
// 	if debugReSTUNStopOnIdle() {
// 		return 45 * time.Second
// 	}
// 	return sessionActiveTimeout
// }

// func (c *Conn) shouldDoPeriodicReSTUNLocked() bool {
// 	if c.networkDown() {
// 		return false
// 	}
// 	if len(c.peerSet) == 0 || c.privateKey.IsZero() {
// 		// If no peers, not worth doing.
// 		// Also don't if there's no key (not running).
// 		return false
// 	}
// 	if f := c.idleFunc; f != nil {
// 		idleFor := f()
// 		if debugReSTUNStopOnIdle() {
// 			c.logf("magicsock: periodicReSTUN: idle for %v", idleFor.Round(time.Second))
// 		}
// 		if idleFor > maxIdleBeforeSTUNShutdown() {
// 			if c.netMap != nil && c.netMap.Debug != nil && c.netMap.Debug.ForceBackgroundSTUN {
// 				// Overridden by control.
// 				return true
// 			}
// 			return false
// 		}
// 	}
// 	return true
// }

// func (c *Conn) onPortMapChanged() { c.ReSTUN("portmap-changed") }

// // ReSTUN triggers an address discovery.
// // The provided why string is for debug logging only.
// func (c *Conn) ReSTUN(why string) {
// 	c.mu.Lock()
// 	defer c.mu.Unlock()
// 	if c.closed {
// 		// raced with a shutdown.
// 		return
// 	}
// 	metricReSTUNCalls.Add(1)

// 	// If the user stopped the app, stop doing work. (When the
// 	// user stops Tailscale via the GUI apps, ipn/local.go
// 	// reconfigures the engine with a zero private key.)
// 	//
// 	// This used to just check c.privateKey.IsZero, but that broke
// 	// some end-to-end tests that didn't ever set a private
// 	// key somehow. So for now, only stop doing work if we ever
// 	// had a key, which helps real users, but appeases tests for
// 	// now. TODO: rewrite those tests to be less brittle or more
// 	// realistic.
// 	if c.privateKey.IsZero() && c.everHadKey {
// 		c.logf("magicsock: ReSTUN(%q) ignored; stopped, no private key", why)
// 		return
// 	}

// 	if c.endpointsUpdateActive {
// 		if c.wantEndpointsUpdate != why {
// 			c.dlogf("[v1] magicsock: ReSTUN: endpoint update active, need another later (%q)", why)
// 			c.wantEndpointsUpdate = why
// 		}
// 	} else {
// 		c.endpointsUpdateActive = true
// 		go c.updateEndpoints(why)
// 	}
// }

// // listenPacket opens a packet listener.
// // The network must be "udp4" or "udp6".
// func (c *Conn) listenPacket(network string, port uint16) (nettype.PacketConn, error) {
// 	ctx := context.Background() // unused without DNS name to resolve
// 	addr := net.JoinHostPort("", fmt.Sprint(port))
// 	if c.testOnlyPacketListener != nil {
// 		return nettype.MakePacketListenerWithNetIP(c.testOnlyPacketListener).ListenPacket(ctx, network, addr)
// 	}
// 	return nettype.MakePacketListenerWithNetIP(netns.Listener(c.logf)).ListenPacket(ctx, network, addr)
// }

// var debugBindSocket = envknob.RegisterBool("TS_DEBUG_MAGICSOCK_BIND_SOCKET")

// // bindSocket initializes rucPtr if necessary and binds a UDP socket to it.
// // Network indicates the UDP socket type; it must be "udp4" or "udp6".
// // If rucPtr had an existing UDP socket bound, it closes that socket.
// // The caller is responsible for informing the portMapper of any changes.
// // If curPortFate is set to dropCurrentPort, no attempt is made to reuse
// // the current port.
// func (c *Conn) bindSocket(ruc *RebindingUDPConn, network string, curPortFate currentPortFate) error {
// 	if debugBindSocket() {
// 		c.logf("magicsock: bindSocket: network=%q curPortFate=%v", network, curPortFate)
// 	}

// 	// Hold the ruc lock the entire time, so that the close+bind is atomic
// 	// from the perspective of ruc receive functions.
// 	ruc.mu.Lock()
// 	defer ruc.mu.Unlock()

// 	if runtime.GOOS == "js" {
// 		ruc.setConnLocked(newBlockForeverConn(), "")
// 		return nil
// 	}

// 	if debugAlwaysDERP() {
// 		c.logf("disabled %v per TS_DEBUG_ALWAYS_USE_DERP", network)
// 		ruc.setConnLocked(newBlockForeverConn(), "")
// 		return nil
// 	}

// 	// Build a list of preferred ports.
// 	// Best is the port that the user requested.
// 	// Second best is the port that is currently in use.
// 	// If those fail, fall back to 0.
// 	var ports []uint16
// 	if port := uint16(c.port.Load()); port != 0 {
// 		ports = append(ports, port)
// 	}
// 	if ruc.pconn != nil && curPortFate == keepCurrentPort {
// 		curPort := uint16(ruc.localAddrLocked().Port)
// 		ports = append(ports, curPort)
// 	}
// 	ports = append(ports, 0)
// 	// Remove duplicates. (All duplicates are consecutive.)
// 	uniq.ModifySlice(&ports)

// 	if debugBindSocket() {
// 		c.logf("magicsock: bindSocket: candidate ports: %+v", ports)
// 	}

// 	var pconn nettype.PacketConn
// 	for _, port := range ports {
// 		// Close the existing conn, in case it is sitting on the port we want.
// 		err := ruc.closeLocked()
// 		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, errNilPConn) {
// 			c.logf("magicsock: bindSocket %v close failed: %v", network, err)
// 		}
// 		// Open a new one with the desired port.
// 		pconn, err = c.listenPacket(network, port)
// 		if err != nil {
// 			c.logf("magicsock: unable to bind %v port %d: %v", network, port, err)
// 			continue
// 		}
// 		trySetSocketBuffer(pconn, c.logf)
// 		// Success.
// 		if debugBindSocket() {
// 			c.logf("magicsock: bindSocket: successfully listened %v port %d", network, port)
// 		}
// 		ruc.setConnLocked(pconn, network)
// 		if network == "udp4" {
// 			health.SetUDP4Unbound(false)
// 		}
// 		return nil
// 	}

// 	// Failed to bind, including on port 0 (!).
// 	// Set pconn to a dummy conn whose reads block until closed.
// 	// This keeps the receive funcs alive for a future in which
// 	// we get a link change and we can try binding again.
// 	ruc.setConnLocked(newBlockForeverConn(), "")
// 	if network == "udp4" {
// 		health.SetUDP4Unbound(true)
// 	}
// 	return fmt.Errorf("failed to bind any ports (tried %v)", ports)
// }

// type currentPortFate uint8

// const (
// 	keepCurrentPort = currentPortFate(0)
// 	dropCurrentPort = currentPortFate(1)
// )

// // rebind closes and re-binds the UDP sockets.
// // We consider it successful if we manage to bind the IPv4 socket.
// func (c *Conn) rebind(curPortFate currentPortFate) error {
// 	if err := c.bindSocket(&c.pconn6, "udp6", curPortFate); err != nil {
// 		c.logf("magicsock: Rebind ignoring IPv6 bind failure: %v", err)
// 	}
// 	if err := c.bindSocket(&c.pconn4, "udp4", curPortFate); err != nil {
// 		return fmt.Errorf("magicsock: Rebind IPv4 failed: %w", err)
// 	}
// 	c.portMapper.SetLocalPort(c.LocalPort())
// 	return nil
// }

// // Rebind closes and re-binds the UDP sockets and resets the DERP connection.
// // It should be followed by a call to ReSTUN.
// func (c *Conn) Rebind() {
// 	metricRebindCalls.Add(1)
// 	if err := c.rebind(keepCurrentPort); err != nil {
// 		c.logf("%w", err)
// 		return
// 	}

// 	var ifIPs []netip.Prefix
// 	if c.linkMon != nil {
// 		st := c.linkMon.InterfaceState()
// 		defIf := st.DefaultRouteInterface
// 		ifIPs = st.InterfaceIPs[defIf]
// 		c.logf("Rebind; defIf=%q, ips=%v", defIf, ifIPs)
// 	}

// 	c.maybeCloseDERPsOnRebind(ifIPs)
// 	c.resetEndpointStates()
// }

// // resetEndpointStates resets the preferred address for all peers.
// // This is called when connectivity changes enough that we no longer
// // trust the old routes.
// func (c *Conn) resetEndpointStates() {
// 	c.mu.Lock()
// 	defer c.mu.Unlock()
// 	c.peerMap.forEachEndpoint(func(ep *endpoint) {
// 		ep.noteConnectivityChange()
// 	})
// }

// // packIPPort packs an IPPort into the form wanted by WireGuard.
// func packIPPort(ua netip.AddrPort) []byte {
// 	ip := ua.Addr().Unmap()
// 	a := ip.As16()
// 	ipb := a[:]
// 	if ip.Is4() {
// 		ipb = ipb[12:]
// 	}
// 	b := make([]byte, 0, len(ipb)+2)
// 	b = append(b, ipb...)
// 	b = append(b, byte(ua.Port()))
// 	b = append(b, byte(ua.Port()>>8))
// 	return b
// }

// // ParseEndpoint is called by WireGuard to connect to an endpoint.
// func (c *Conn) ParseEndpoint(nodeKeyStr string) (conn.Endpoint, error) {
// 	k, err := key.ParseNodePublicUntyped(mem.S(nodeKeyStr))
// 	if err != nil {
// 		return nil, fmt.Errorf("magicsock: ParseEndpoint: parse failed on %q: %w", nodeKeyStr, err)
// 	}

// 	c.mu.Lock()
// 	defer c.mu.Unlock()
// 	if c.closed {
// 		return nil, errConnClosed
// 	}
// 	ep, ok := c.peerMap.endpointForNodeKey(k)
// 	if !ok {
// 		// We should never be telling WireGuard about a new peer
// 		// before magicsock knows about it.
// 		c.logf("[unexpected] magicsock: ParseEndpoint: unknown node key=%s", k.ShortString())
// 		return nil, fmt.Errorf("magicsock: ParseEndpoint: unknown peer %q", k.ShortString())
// 	}

// 	return ep, nil
// }

// type batchReaderWriter interface {
// 	batchReader
// 	batchWriter
// }

// type batchWriter interface {
// 	WriteBatch([]ipv6.Message, int) (int, error)
// }

// type batchReader interface {
// 	ReadBatch([]ipv6.Message, int) (int, error)
// }

// // udpConnWithBatchOps wraps a *net.UDPConn in order to extend it to support
// // batch operations.
// //
// // TODO(jwhited): This wrapping is temporary. https://github.com/golang/go/issues/45886
// type udpConnWithBatchOps struct {
// 	*net.UDPConn
// 	xpc batchReaderWriter
// }

// func newUDPConnWithBatchOps(conn *net.UDPConn, network string) udpConnWithBatchOps {
// 	ucbo := udpConnWithBatchOps{
// 		UDPConn: conn,
// 	}
// 	switch network {
// 	case "udp4":
// 		ucbo.xpc = ipv4.NewPacketConn(conn)
// 	case "udp6":
// 		ucbo.xpc = ipv6.NewPacketConn(conn)
// 	default:
// 		panic("bogus network")
// 	}
// 	return ucbo
// }

// func (u udpConnWithBatchOps) WriteBatch(ms []ipv6.Message, flags int) (int, error) {
// 	return u.xpc.WriteBatch(ms, flags)
// }

// func (u udpConnWithBatchOps) ReadBatch(ms []ipv6.Message, flags int) (int, error) {
// 	return u.xpc.ReadBatch(ms, flags)
// }

/// A UDP socket that can be re-bound. Unix has no notion of re-binding a socket, so we swap it out for a new one.
pub struct RebindingUdpConn {
    // TODO: evaluate which locking strategy to use
    // pconnAtomic is a pointer to the value stored in pconn, but doesn't
    // require acquiring mu. It's used for reads/writes and only upon failure
    // do the reads/writes then check pconn (after acquiring mu) to see if
    // there's been a rebind meanwhile.
    // pconn isn't really needed, but makes some of the code simpler
    // to keep it distinct.
    // Neither is expected to be nil, sockets are bound on creation.
    // pconn_atomic: atomic.Pointer[nettype.PacketConn],
    pconn: RwLock<UdpSocket>,
    port: u16,
}

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

// // setConnLocked sets the provided nettype.PacketConn. It should be called only
// // after acquiring RebindingUDPConn.mu. It upgrades the provided
// // nettype.PacketConn to a udpConnWithBatchOps when appropriate. This upgrade
// // is intentionally pushed closest to where read/write ops occur in order to
// // avoid disrupting surrounding code that assumes nettype.PacketConn is a
// // *net.UDPConn.
// func (c *RebindingUDPConn) setConnLocked(p nettype.PacketConn, network string) {
// 	upc := upgradePacketConn(p, network)
// 	c.pconn = upc
// 	c.pconnAtomic.Store(&upc)
// 	c.port = uint16(c.localAddrLocked().Port)
// }

// // currentConn returns c's current pconn, acquiring c.mu in the process.
// func (c *RebindingUDPConn) currentConn() nettype.PacketConn {
// 	c.mu.Lock()
// 	defer c.mu.Unlock()
// 	return c.pconn
// }

// func (c *RebindingUDPConn) readFromWithInitPconn(pconn nettype.PacketConn, b []byte) (int, net.Addr, error) {
// 	for {
// 		n, addr, err := pconn.ReadFrom(b)
// 		if err != nil && pconn != c.currentConn() {
// 			pconn = *c.pconnAtomic.Load()
// 			continue
// 		}
// 		return n, addr, err
// 	}
// }

// // ReadFrom reads a packet from c into b.
// // It returns the number of bytes copied and the source address.
// func (c *RebindingUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
// 	return c.readFromWithInitPconn(*c.pconnAtomic.Load(), b)
// }

// // ReadFromNetaddr reads a packet from c into b.
// // It returns the number of bytes copied and the return address.
// // It is identical to c.ReadFrom, except that it returns a netip.AddrPort instead of a net.Addr.
// // ReadFromNetaddr is designed to work with specific underlying connection types.
// // If c's underlying connection returns a non-*net.UPDAddr return address, ReadFromNetaddr will return an error.
// // ReadFromNetaddr exists because it removes an allocation per read,
// // when c's underlying connection is a net.UDPConn.
// func (c *RebindingUDPConn) ReadFromNetaddr(b []byte) (n int, ipp netip.AddrPort, err error) {
// 	for {
// 		pconn := *c.pconnAtomic.Load()

// 		// Optimization: Treat *net.UDPConn specially.
// 		// This lets us avoid allocations by calling ReadFromUDPAddrPort.
// 		// The non-*net.UDPConn case works, but it allocates.
// 		if udpConn, ok := pconn.(*net.UDPConn); ok {
// 			n, ipp, err = udpConn.ReadFromUDPAddrPort(b)
// 		} else {
// 			var addr net.Addr
// 			n, addr, err = pconn.ReadFrom(b)
// 			pAddr, ok := addr.(*net.UDPAddr)
// 			if addr != nil && !ok {
// 				return 0, netip.AddrPort{}, fmt.Errorf("RebindingUDPConn.ReadFromNetaddr: underlying connection returned address of type %T, want *netaddr.UDPAddr", addr)
// 			}
// 			if pAddr != nil {
// 				ipp = netaddr.Unmap(pAddr.AddrPort())
// 				if !ipp.IsValid() {
// 					return 0, netip.AddrPort{}, errors.New("netaddr.FromStdAddr failed")
// 				}
// 			}
// 		}

// 		if err != nil && pconn != c.currentConn() {
// 			// The connection changed underfoot. Try again.
// 			continue
// 		}
// 		return n, ipp, err
// 	}
// }

// func (c *RebindingUDPConn) WriteBatch(msgs []ipv6.Message, flags int) (int, error) {
// 	var (
// 		n     int
// 		err   error
// 		start int
// 	)
// 	for {
// 		pconn := *c.pconnAtomic.Load()
// 		bw, ok := pconn.(batchWriter)
// 		if !ok {
// 			for _, msg := range msgs {
// 				_, err = c.writeToWithInitPconn(pconn, msg.Buffers[0], msg.Addr)
// 				if err != nil {
// 					return n, err
// 				}
// 				n++
// 			}
// 			return n, nil
// 		}

// 		n, err = bw.WriteBatch(msgs[start:], flags)
// 		if err != nil {
// 			if pconn != c.currentConn() {
// 				continue
// 			}
// 			return n, err
// 		} else if n == len(msgs[start:]) {
// 			return len(msgs), nil
// 		} else {
// 			start += n
// 		}
// 	}
// }

// func (c *RebindingUDPConn) ReadBatch(msgs []ipv6.Message, flags int) (int, error) {
// 	for {
// 		pconn := *c.pconnAtomic.Load()
// 		br, ok := pconn.(batchReader)
// 		if !ok {
// 			var err error
// 			msgs[0].N, msgs[0].Addr, err = c.readFromWithInitPconn(pconn, msgs[0].Buffers[0])
// 			if err == nil {
// 				return 1, nil
// 			}
// 			return 0, err
// 		}
// 		n, err := br.ReadBatch(msgs, flags)
// 		if err != nil && pconn != c.currentConn() {
// 			continue
// 		}
// 		return n, err
// 	}
// }

// func (c *RebindingUDPConn) Port() uint16 {
// 	c.mu.Lock()
// 	defer c.mu.Unlock()
// 	return c.port
// }

// func (c *RebindingUDPConn) LocalAddr() *net.UDPAddr {
// 	c.mu.Lock()
// 	defer c.mu.Unlock()
// 	return c.localAddrLocked()
// }

// func (c *RebindingUDPConn) localAddrLocked() *net.UDPAddr {
// 	return c.pconn.LocalAddr().(*net.UDPAddr)
// }

// // errNilPConn is returned by RebindingUDPConn.Close when there is no current pconn.
// // It is for internal use only and should not be returned to users.
// var errNilPConn = errors.New("nil pconn")

// func (c *RebindingUDPConn) Close() error {
// 	c.mu.Lock()
// 	defer c.mu.Unlock()
// 	return c.closeLocked()
// }

// func (c *RebindingUDPConn) closeLocked() error {
// 	if c.pconn == nil {
// 		return errNilPConn
// 	}
// 	c.port = 0
// 	return c.pconn.Close()
// }

// func (c *RebindingUDPConn) writeToWithInitPconn(pconn nettype.PacketConn, b []byte, addr net.Addr) (int, error) {
// 	for {
// 		n, err := pconn.WriteTo(b, addr)
// 		if err != nil && pconn != c.currentConn() {
// 			pconn = *c.pconnAtomic.Load()
// 			continue
// 		}
// 		return n, err
// 	}
// }

// func (c *RebindingUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
// 	return c.writeToWithInitPconn(*c.pconnAtomic.Load(), b, addr)
// }

// func (c *RebindingUDPConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
// 	for {
// 		pconn := *c.pconnAtomic.Load()
// 		n, err := pconn.WriteToUDPAddrPort(b, addr)
// 		if err != nil && pconn != c.currentConn() {
// 			continue
// 		}
// 		return n, err
// 	}
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

// func (c *Conn) derpRegionCodeOfAddrLocked(ipPort string) string {
// 	_, portStr, err := net.SplitHostPort(ipPort)
// 	if err != nil {
// 		return ""
// 	}
// 	regionID, err := strconv.Atoi(portStr)
// 	if err != nil {
// 		return ""
// 	}
// 	return c.derpRegionCodeOfIDLocked(regionID)
// }

// func (c *Conn) derpRegionCodeOfIDLocked(regionID int) string {
// 	if c.derpMap == nil {
// 		return ""
// 	}
// 	if r, ok := c.derpMap.Regions[regionID]; ok {
// 		return r.RegionCode
// 	}
// 	return ""
// }

// func (c *Conn) UpdateStatus(sb *ipnstate.StatusBuilder) {
// 	c.mu.Lock()
// 	defer c.mu.Unlock()

// 	var tailscaleIPs []netip.Addr
// 	if c.netMap != nil {
// 		tailscaleIPs = make([]netip.Addr, 0, len(c.netMap.Addresses))
// 		for _, addr := range c.netMap.Addresses {
// 			if !addr.IsSingleIP() {
// 				continue
// 			}
// 			sb.AddTailscaleIP(addr.Addr())
// 			tailscaleIPs = append(tailscaleIPs, addr.Addr())
// 		}
// 	}

// 	sb.MutateSelfStatus(func(ss *ipnstate.PeerStatus) {
// 		if !c.privateKey.IsZero() {
// 			ss.PublicKey = c.privateKey.Public()
// 		} else {
// 			ss.PublicKey = key.NodePublic{}
// 		}
// 		ss.Addrs = make([]string, 0, len(c.lastEndpoints))
// 		for _, ep := range c.lastEndpoints {
// 			ss.Addrs = append(ss.Addrs, ep.Addr.String())
// 		}
// 		ss.OS = version.OS()
// 		if c.derpMap != nil {
// 			derpRegion, ok := c.derpMap.Regions[c.myDerp]
// 			if ok {
// 				ss.Relay = derpRegion.RegionCode
// 			}
// 		}
// 		ss.TailscaleIPs = tailscaleIPs
// 	})

// 	if sb.WantPeers {
// 		c.peerMap.forEachEndpoint(func(ep *endpoint) {
// 			ps := &ipnstate.PeerStatus{InMagicSock: true}
// 			//ps.Addrs = append(ps.Addrs, n.Endpoints...)
// 			ep.populatePeerStatus(ps)
// 			sb.AddPeer(ep.publicKey, ps)
// 		})
// 	}

// 	c.foreachActiveDerpSortedLocked(func(node int, ad activeDerp) {
// 		// TODO(bradfitz): add to ipnstate.StatusBuilder
// 		//f("<li><b>derp-%v</b>: cr%v,wr%v</li>", node, simpleDur(now.Sub(ad.createTime)), simpleDur(now.Sub(*ad.lastWrite)))
// 	})
// }

// // SetStatistics specifies a per-connection statistics aggregator.
// // Nil may be specified to disable statistics gathering.
// func (c *Conn) SetStatistics(stats *connstats.Statistics) {
// 	c.stats.Store(stats)
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

/// Some state and history for a specific endpoint of a endpoint.
/// (The subject is the endpoint.endpointState map key)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EndpointState {
    /// The last (outgoing) ping time.
    last_ping: Instant,

    /// If non-zero, means that this was an endpoint
    /// that we learned about at runtime (from an incoming ping)
    /// and that is not in the network map. If so, we keep the time
    /// updated and use it to discard old candidates.
    last_got_ping: Option<Instant>,

    /// Contains the TxID for the last incoming ping. This is
    /// used to de-dup incoming pings that we may see on both the raw disco
    /// socket on Linux, and UDP socket. We cannot rely solely on the raw socket
    /// disco handling due to https://github.com/tailscale/tailscale/issues/7078.
    last_got_ping_tx_id: stun::TransactionId,

    /// If non-zero, is the time this endpoint was advertised last via a call-me-maybe disco message.
    call_me_maybe_time: Option<Instant>,

    /// Ring buffer up to PongHistoryCount entries
    recent_pongs: Vec<PongReply>,
    /// Index into recentPongs of most recent; older before, wrapped
    recent_pong: usize,

    /// Index in nodecfg.Node.Endpoints; meaningless if last_got_ping non-zero.
    index: usize,
}

// // indexSentinelDeleted is the temporary value that endpointState.index takes while
// // a endpoint's endpoints are being updated from a new network map.
// const indexSentinelDeleted = -1

// // shouldDeleteLocked reports whether we should delete this endpoint.
// func (st *endpointState) shouldDeleteLocked() bool {
// 	switch {
// 	case !st.callMeMaybeTime.IsZero():
// 		return false
// 	case st.lastGotPing.IsZero():
// 		// This was an endpoint from the network map. Is it still in the network map?
// 		return st.index == indexSentinelDeleted
// 	default:
// 		// This was an endpoint discovered at runtime.
// 		return time.Since(st.lastGotPing) > sessionActiveTimeout
// 	}
// }

// func (de *endpoint) deleteEndpointLocked(ep netip.AddrPort) {
// 	delete(de.endpointState, ep)
// 	if de.bestAddr.AddrPort == ep {
// 		de.bestAddr = addrLatency{}
// 	}
// }

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
