use tokio::{net::UdpSocket, sync::RwLock};

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

impl RebindingUdpConn {
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
}
