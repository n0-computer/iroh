//! Based on tailscale/derp/derphttp/derphttp_client.go
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Result;
use futures::future::BoxFuture;
use tokio::sync::Mutex;

use crate::hp::derp::{DerpNode, PacketForwarder};
use crate::hp::key;

use crate::hp::derp::{client::Client as DerpClient, DerpRegion, ReceivedMessage};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ClientError {
    #[error("todo")]
    Todo,
    #[error("closed")]
    Closed,
    #[error("no derp client")]
    NoClient,
    #[error("send")]
    Send,
}

/// An HTTP DERP client.
///
/// Cheaply clonable.
#[derive(Clone)]
pub struct Client {
    inner: Arc<InnerClient>,
}

impl PartialEq for Client {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl Eq for Client {}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Client {{}}")
    }
}

struct InnerClient {
    secret_key: key::node::SecretKey,
    get_region:
        Option<Box<dyn Fn() -> BoxFuture<'static, Option<DerpRegion>> + Send + Sync + 'static>>,
    can_ack_pings: bool,
    is_preferred: Mutex<bool>,
    derp_client: Mutex<Option<DerpClient<tokio::net::tcp::OwnedReadHalf>>>,
    is_closed: AtomicBool,
    address_family_selector:
        Option<Box<dyn Fn() -> BoxFuture<'static, bool> + Send + Sync + 'static>>,
    conn_gen: AtomicUsize,
}

/// Build a Client
pub struct ClientBuilder {
    /// Default is false
    can_ack_pings: bool,
    /// Default is false
    is_preferred: bool,
    /// Default is None
    address_family_selector:
        Option<Box<dyn Fn() -> BoxFuture<'static, bool> + Send + Sync + 'static>>,
}

impl std::fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let address_family_selector_txt = match self.address_family_selector {
            Some(_) => "Some(Box<dyn Fn() -> BoxFuture<'static, bool> + Send + Sync + 'static>)",
            None => "None",
        };
        write!(f, "ClientBuilder {{ can_ack_pings: {}, is_preferred: {}, address_family_selector: {address_family_selector_txt} }}", self.can_ack_pings, self.is_preferred)
    }
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            can_ack_pings: false,
            is_preferred: false,
            address_family_selector: None,
        }
    }

    // S returns if we should prefer ipv6
    // it replaces the derphttp.AddressFamilySelector we pass
    // It provides the hint as to whether in an IPv4-vs-IPv6 race that
    // IPv4 should be held back a bit to give IPv6 a better-than-50/50
    // chance of winning. We only return true when we believe IPv6 will
    // work anyway, so we don't artificially delay the connection speed.
    pub fn address_family_selector<S>(mut self, selector: S) -> Self
    where
        S: Fn() -> BoxFuture<'static, bool> + Send + Sync + 'static,
    {
        self.address_family_selector = Some(Box::new(selector));
        self
    }

    pub fn can_ack_pings(mut self, can: bool) -> Self {
        self.can_ack_pings = can;
        self
    }

    pub fn is_preferred(mut self, is: bool) -> Self {
        self.is_preferred = is;
        self
    }

    pub fn new_region<F>(self, key: key::node::SecretKey, f: F) -> Client
    where
        F: Fn() -> BoxFuture<'static, Option<DerpRegion>> + Send + Sync + 'static,
    {
        Client {
            inner: Arc::new(InnerClient {
                secret_key: key,
                get_region: Some(Box::new(f)),
                can_ack_pings: self.can_ack_pings,
                is_preferred: Mutex::new(self.is_preferred),
                derp_client: Mutex::new(None),
                is_closed: AtomicBool::new(false),
                address_family_selector: self.address_family_selector,
                conn_gen: AtomicUsize::new(0),
            }),
        }
    }
}

impl Client {
    /// Let the server know that this client is the preferred client
    pub async fn note_preferred(&self, is_preferred: bool) {
        {
            let mut old = self.inner.is_preferred.lock().await;
            if *old == is_preferred {
                return;
            }
            *old = is_preferred;
        }
        // only send the preference if we already have a connection
        let res = {
            let client = self.inner.derp_client.lock().await;
            if let Some(client) = &*client {
                client.note_preferred(is_preferred).await
            } else {
                return;
            }
        };
        // need to do this outside the above closure because they rely on the same lock
        // if there was an error sending, close the underlying derp connection
        if let Err(_) = res {
            self.close_for_reconnect().await;
        }
    }

    /// Get the local addr of the connection. If there is no current underlying derp connection
    /// or the [`Client`] is closed, returns `None`.
    pub async fn local_addr(&self) -> Option<SocketAddr> {
        if self.inner.is_closed.load(Ordering::SeqCst) {
            return None;
        }
        let client = self.inner.derp_client.lock().await;
        if let Some(client) = &*client {
            match client.local_addr().await {
                Ok(addr) => return Some(addr),
                _ => return None,
            }
        }
        None
    }

    /// Connect to a Derp Server and returns the underlying Derp Client.
    ///
    /// Returns [`ClientError::Closed`] if the [`Client`] is closed.
    ///
    /// If there is already an active derp connection, returns the already
    /// connected [`crate::hp::derp::client::Client`].
    async fn connect(
        &self,
    ) -> Result<(DerpClient<tokio::net::tcp::OwnedReadHalf>, usize), ClientError> {
        if self.inner.is_closed.load(Ordering::Relaxed) {
            return Err(ClientError::Closed);
        }

        if let Some(derp_client) = &*self.inner.derp_client.lock().await {
            return Ok((
                derp_client.clone(),
                self.inner.conn_gen.load(Ordering::SeqCst),
            ));
        }
        // do connection work
        // // timeout is the fallback maximum time (if ctx doesn't limit
        // // it further) to do all of: DNS + TCP + TLS + HTTP Upgrade +
        // // DERP upgrade.
        // const timeout = 10 * time.Second
        // ctx, cancel := context.WithTimeout(ctx, timeout)
        // go func() {
        // select {
        // case <-ctx.Done():
        // // Either timeout fired (handled below), or
        // // we're returning via the defer cancel()
        // // below.
        // case <-c.ctx.Done():
        // // Propagate a Client.Close call into
        // // cancelling this context.
        // cancel()
        // }
        // }()
        // defer cancel()

        // var reg *tailcfg.DERPRegion // nil when using c.url to dial
        // if c.getRegion != nil {
        // reg = c.getRegion()
        // if reg == nil {
        // return nil, 0, errors.New("DERP region not available")
        // }
        // }

        // var tcpConn net.Conn

        // defer func() {
        // if err != nil {
        // if ctx.Err() != nil {
        // err = fmt.Errorf("%v: %v", ctx.Err(), err)
        // }
        // err = fmt.Errorf("%s connect to %v: %v", caller, c.targetString(reg), err)
        // if tcpConn != nil {
        // go tcpConn.Close()
        // }
        // }
        // }()

        // var node *tailcfg.DERPNode // nil when using c.url to dial
        // switch {
        // case useWebsockets():
        // var urlStr string
        // if c.url != nil {
        // urlStr = c.url.String()
        // } else {
        // urlStr = c.urlString(reg.Nodes[0])
        // }
        // c.logf("%s: connecting websocket to %v", caller, urlStr)
        // conn, err := dialWebsocketFunc(ctx, urlStr)
        // if err != nil {
        // c.logf("%s: websocket to %v error: %v", caller, urlStr, err)
        // return nil, 0, err
        // }
        // brw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
        // derpClient, err := derp.NewClient(c.privateKey, conn, brw, c.logf,
        // derp.MeshKey(c.MeshKey),
        // derp.CanAckPings(c.canAckPings),
        // derp.IsProber(c.IsProber),
        // )
        // if err != nil {
        // return nil, 0, err
        // }
        // if c.preferred {
        // if err := derpClient.NotePreferred(true); err != nil {
        // go conn.Close()
        // return nil, 0, err
        // }
        // }
        // c.serverPubKey = derpClient.ServerPublicKey()
        // c.client = derpClient
        // c.netConn = conn
        // c.connGen++
        // return c.client, c.connGen, nil
        // case c.url != nil:
        // c.logf("%s: connecting to %v", caller, c.url)
        // tcpConn, err = c.dialURL(ctx)
        // default:
        // c.logf("%s: connecting to derp-%d (%v)", caller, reg.RegionID, reg.RegionCode)
        // tcpConn, node, err = c.dialRegion(ctx, reg)
        // }
        // if err != nil {
        // return nil, 0, err
        // }

        // // Now that we have a TCP connection, force close it if the
        // // TLS handshake + DERP setup takes too long.
        // done := make(chan struct{})
        // defer close(done)
        // go func() {
        // select {
        // case <-done:
        // // Normal path. Upgrade occurred in time.
        // case <-ctx.Done():
        // select {
        // case <-done:
        // // Normal path. Upgrade occurred in time.
        // // But the ctx.Done() is also done because
        // // the "defer cancel()" above scheduled
        // // before this goroutine.
        // default:
        // // The TLS or HTTP or DERP exchanges didn't complete
        // // in time. Force close the TCP connection to force
        // // them to fail quickly.
        // tcpConn.Close()
        // }
        // }
        // }()

        // var httpConn net.Conn        // a TCP conn or a TLS conn; what we speak HTTP to
        // var serverPub key.NodePublic // or zero if unknown (if not using TLS or TLS middlebox eats it)
        // var serverProtoVersion int
        // var tlsState *tls.ConnectionState
        // if c.useHTTPS() {
        // tlsConn := c.tlsClient(tcpConn, node)
        // httpConn = tlsConn

        // // Force a handshake now (instead of waiting for it to
        // // be done implicitly on read/write) so we can check
        // // the ConnectionState.
        // if err := tlsConn.Handshake(); err != nil {
        // return nil, 0, err
        // }

        // // We expect to be using TLS 1.3 to our own servers, and only
        // // starting at TLS 1.3 are the server's returned certificates
        // // encrypted, so only look for and use our "meta cert" if we're
        // // using TLS 1.3. If we're not using TLS 1.3, it might be a user
        // // running cmd/derper themselves with a different configuration,
        // // in which case we can avoid this fast-start optimization.
        // // (If a corporate proxy is MITM'ing TLS 1.3 connections with
        // // corp-mandated TLS root certs than all bets are off anyway.)
        // // Note that we're not specifically concerned about TLS downgrade
        // // attacks. TLS handles that fine:
        // // https://blog.gypsyengineer.com/en/security/how-does-tls-1-3-protect-against-downgrade-attacks.html
        // cs := tlsConn.ConnectionState()
        // tlsState = &cs
        // if cs.Version >= tls.VersionTLS13 {
        // serverPub, serverProtoVersion = parseMetaCert(cs.PeerCertificates)
        // }
        // } else {
        // httpConn = tcpConn
        // }

        // brw := bufio.NewReadWriter(bufio.NewReader(httpConn), bufio.NewWriter(httpConn))
        // var derpClient *derp.Client

        // req, err := http.NewRequest("GET", c.urlString(node), nil)
        // if err != nil {
        // return nil, 0, err
        // }
        // req.Header.Set("Upgrade", "DERP")
        // req.Header.Set("Connection", "Upgrade")

        // if !serverPub.IsZero() && serverProtoVersion != 0 {
        // // parseMetaCert found the server's public key (no TLS
        // // middlebox was in the way), so skip the HTTP upgrade
        // // exchange.  See https://github.com/tailscale/tailscale/issues/693
        // // for an overview. We still send the HTTP request
        // // just to get routed into the server's HTTP Handler so it
        // // can Hijack the request, but we signal with a special header
        // // that we don't want to deal with its HTTP response.
        // req.Header.Set(fastStartHeader, "1") // suppresses the server's HTTP response
        // if err := req.Write(brw); err != nil {
        // return nil, 0, err
        // }
        // // No need to flush the HTTP request. the derp.Client's initial
        // // client auth frame will flush it.
        // } else {
        // if err := req.Write(brw); err != nil {
        // return nil, 0, err
        // }
        // if err := brw.Flush(); err != nil {
        // return nil, 0, err
        // }

        // resp, err := http.ReadResponse(brw.Reader, req)
        // if err != nil {
        // return nil, 0, err
        // }
        // if resp.StatusCode != http.StatusSwitchingProtocols {
        // b, _ := io.ReadAll(resp.Body)
        // resp.Body.Close()
        // return nil, 0, fmt.Errorf("GET failed: %v: %s", err, b)
        // }
        // }
        // derpClient, err = derp.NewClient(c.privateKey, httpConn, brw, c.logf,
        // derp.MeshKey(c.MeshKey),
        // derp.ServerPublicKey(serverPub),
        // derp.CanAckPings(c.canAckPings),
        // derp.IsProber(c.IsProber),
        // )
        // if err != nil {
        // return nil, 0, err
        // }
        // if c.preferred {
        // if err := derpClient.NotePreferred(true); err != nil {
        // go httpConn.Close()
        // return nil, 0, err
        // }
        // }

        // c.serverPubKey = derpClient.ServerPublicKey()
        // c.client = derpClient
        // c.netConn = tcpConn
        // c.tlsState = tlsState
        let _conn_gen = self.inner.conn_gen.fetch_add(1, Ordering::SeqCst);

        todo!();
    }

    /// String representation of the url or derp region we are trying to
    /// connect to.
    fn target_string(&self, reg: &DerpRegion) -> String {
        // TODO: if  self.Url, return the url string
        format!("region {} ({})", reg.region_id, reg.region_code)
    }

    /// Return a TCP stream to the provided region, trying each node in order
    /// (using [`Client::dial_node`]) until one connects or we timeout
    // TODO add timeout?
    // TODO implement dial_node
    async fn dial_region(&self, reg: DerpRegion) -> anyhow::Result<(TcpStream, DerpNode)> {
        let target = self.target_string(&reg);
        if reg.nodes.is_empty() {
            anyhow::bail!("no nodes for {target}");
        }
        let mut first_err: Option<anyhow::Error> = None;
        for node in reg.nodes {
            if node.stun_only {
                if first_err.is_none() {
                    first_err = Some(anyhow::Error::msg(format!(
                        "no non-stun_only nodes for {target}"
                    )));
                }
                continue;
            }
            let conn = self.dial_node(&node).await;
            match conn {
                Ok(conn) => return Ok((conn, node)),
                Err(e) => first_err = Some(e),
            }
        }
        let err = first_err.unwrap();
        Err(err)
    }

    //// dialNode returns a TCP connection to node n, racing IPv4 and IPv6
    //// (both as applicable) against each other.
    //// A node is only given dialNodeTimeout to connect.
    ////
    //// TODO(bradfitz): longer if no options remain perhaps? ...  Or longer
    //// overall but have dialRegion start overlapping races?
    async fn dial_node(&self, node: &DerpNode) -> anyhow::Result<TcpStream> {
        todo!();
    }
    //func (c *Client) dialNode(ctx context.Context, n *tailcfg.DERPNode) (net.Conn, error) {
    //	// First see if we need to use an HTTP proxy.
    //	proxyReq := &http.Request{
    //		Method: "GET", // doesn't really matter
    //		URL: &url.URL{
    //			Scheme: "https",
    //			Host:   c.tlsServerName(n),
    //			Path:   "/", // unused
    //		},
    //	}
    //	if proxyURL, err := tshttpproxy.ProxyFromEnvironment(proxyReq); err == nil && proxyURL != nil {
    //		return c.dialNodeUsingProxy(ctx, n, proxyURL)
    //	}

    //	type res struct {
    //		c   net.Conn
    //		err error
    //	}
    //	resc := make(chan res) // must be unbuffered
    //	ctx, cancel := context.WithTimeout(ctx, dialNodeTimeout)
    //	defer cancel()

    //	ctx = sockstats.WithSockStats(ctx, sockstats.LabelDERPHTTPClient)

    //	nwait := 0
    //	startDial := func(dstPrimary, proto string) {
    //		nwait++
    //		go func() {
    //			if proto == "tcp4" && c.preferIPv6() {
    //				t := time.NewTimer(200 * time.Millisecond)
    //				select {
    //				case <-ctx.Done():
    //					// Either user canceled original context,
    //					// it timed out, or the v6 dial succeeded.
    //					t.Stop()
    //					return
    //				case <-t.C:
    //					// Start v4 dial
    //				}
    //			}
    //			dst := dstPrimary
    //			if dst == "" {
    //				dst = n.HostName
    //			}
    //			port := "443"
    //			if n.DERPPort != 0 {
    //				port = fmt.Sprint(n.DERPPort)
    //			}
    //			c, err := c.dialContext(ctx, proto, net.JoinHostPort(dst, port))
    //			select {
    //			case resc <- res{c, err}:
    //			case <-ctx.Done():
    //				if c != nil {
    //					c.Close()
    //				}
    //			}
    //		}()
    //	}
    //	if shouldDialProto(n.IPv4, netip.Addr.Is4) {
    //		startDial(n.IPv4, "tcp4")
    //	}
    //	if shouldDialProto(n.IPv6, netip.Addr.Is6) {
    //		startDial(n.IPv6, "tcp6")
    //	}
    //	if nwait == 0 {
    //		return nil, errors.New("both IPv4 and IPv6 are explicitly disabled for node")
    //	}

    //	var firstErr error
    //	for {
    //		select {
    //		case res := <-resc:
    //			nwait--
    //			if res.err == nil {
    //				return res.c, nil
    //			}
    //			if firstErr == nil {
    //				firstErr = res.err
    //			}
    //			if nwait == 0 {
    //				return nil, firstErr
    //			}
    //		case <-ctx.Done():
    //			return nil, ctx.Err()
    //		}
    //	}
    //}
    //
    // // dialNodeUsingProxy connects to n using a CONNECT to the HTTP(s) proxy in proxyURL.
    // func (c *Client) dialNodeUsingProxy(ctx context.Context, n *tailcfg.DERPNode, proxyURL *url.URL) (proxyConn net.Conn, err error) {
    // 	pu := proxyURL
    // 	if pu.Scheme == "https" {
    // 		var d tls.Dialer
    // 		proxyConn, err = d.DialContext(ctx, "tcp", net.JoinHostPort(pu.Hostname(), firstStr(pu.Port(), "443")))
    // 	} else {
    // 		var d net.Dialer
    // 		proxyConn, err = d.DialContext(ctx, "tcp", net.JoinHostPort(pu.Hostname(), firstStr(pu.Port(), "80")))
    // 	}
    // 	defer func() {
    // 		if err != nil && proxyConn != nil {
    // 			// In a goroutine in case it's a *tls.Conn (that can block on Close)
    // 			// TODO(bradfitz): track the underlying tcp.Conn and just close that instead.
    // 			go proxyConn.Close()
    // 		}
    // 	}()
    // 	if err != nil {
    // 		return nil, err
    // 	}

    // 	done := make(chan struct{})
    // 	defer close(done)
    // 	go func() {
    // 		select {
    // 		case <-done:
    // 			return
    // 		case <-ctx.Done():
    // 			proxyConn.Close()
    // 		}
    // 	}()

    // 	target := net.JoinHostPort(n.HostName, "443")

    // 	var authHeader string
    // 	if v, err := tshttpproxy.GetAuthHeader(pu); err != nil {
    // 		c.logf("derphttp: error getting proxy auth header for %v: %v", proxyURL, err)
    // 	} else if v != "" {
    // 		authHeader = fmt.Sprintf("Proxy-Authorization: %s\r\n", v)
    // 	}

    // 	if _, err := fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", target, pu.Hostname(), authHeader); err != nil {
    // 		if ctx.Err() != nil {
    // 			return nil, ctx.Err()
    // 		}
    // 		return nil, err
    // 	}

    // 	br := bufio.NewReader(proxyConn)
    // 	res, err := http.ReadResponse(br, nil)
    // 	if err != nil {
    // 		if ctx.Err() != nil {
    // 			return nil, ctx.Err()
    // 		}
    // 		c.logf("derphttp: CONNECT dial to %s: %v", target, err)
    // 		return nil, err
    // 	}
    // 	c.logf("derphttp: CONNECT dial to %s: %v", target, res.Status)
    // 	if res.StatusCode != 200 {
    // 		return nil, fmt.Errorf("invalid response status from HTTP proxy %s on CONNECT to %s: %v", pu, target, res.Status)
    // 	}
    // 	return proxyConn, nil
    // }

    /// Send a ping to the server. Return once we get an expected pong.
    pub async fn ping(&self) -> Result<(), ClientError> {
        let (client, _) = self.connect().await?;
        // TODO: NOT DONE, need to keep track of pings send and pongs we are waiting to receive
        // TODO: generate random data to send
        if let Err(_) = client.send_ping(*b"pingpong").await {
            self.close_for_reconnect().await;
            return Err(ClientError::Send);
        }
        Ok(())
    }

    /// Send a pong back to the server.
    ///
    /// If there is no underlying active derp connection, it creates one before attempting to
    /// send the pong message.
    ///
    /// If there is an error sending pong, it closes the underlying derp connection before
    /// returning.
    pub async fn send_pong(&self, data: [u8; 8]) -> Result<(), ClientError> {
        let (client, _) = self.connect().await?;
        if let Err(_) = client.send_pong(data).await {
            self.close_for_reconnect().await;
            return Err(ClientError::Send);
        }
        Ok(())
    }

    /// Reads a message from the server. Returns the message and the `conn_get`, or the number of
    /// re-connections this Client has ever made
    pub async fn recv_detail(&self) -> Result<(ReceivedMessage, usize), ClientError> {
        loop {
            let (client, conn_gen) = self.connect().await?;
            match client.recv().await {
                Ok(msg) => {
                    // TODO: NOT DONE if pong is received handle it
                    return Ok((msg, conn_gen));
                }
                Err(_) => {
                    self.close_for_reconnect().await;
                    if self.inner.is_closed.load(Ordering::SeqCst) {
                        return Err(ClientError::Closed);
                    }
                }
            }
        }
    }

    /// Send a packet to the server.
    ///
    /// If there is no underlying active derp connection, it creates one before attempting to
    /// send the message.
    ///
    /// If there is an error sending the packet, it closes the underlying derp connection before
    /// returning.
    pub async fn send(&self, dst_key: key::node::PublicKey, b: Vec<u8>) -> Result<(), ClientError> {
        let (client, _) = self.connect().await?;
        if let Err(_) = client.send(dst_key, b).await {
            self.close_for_reconnect().await;
            return Err(ClientError::Send);
        }
        Ok(())
    }

    /// Close the underlying derp connection. The next time the client takes some action that
    /// requires a connection, it will call `connect`.
    async fn close_for_reconnect(&self) {
        let mut client = self.inner.derp_client.lock().await;
        if let Some(client) = client.take() {
            client.close().await
        }
    }

    /// Close the http derp connection
    pub async fn close(self) {
        self.inner.is_closed.store(true, Ordering::Relaxed);
        self.close_for_reconnect().await;
    }

    /// Send a request to subscribe as a "watcher" on the server.
    ///
    /// If there is no underlying active derp connection, it creates one before attempting to
    /// send the "watch connection changes" message.
    ///
    /// If there is an error sending the message, it closes the underlying derp connection before
    /// returning.
    pub async fn watch_connection_changes(&self) -> Result<(), ClientError> {
        let (client, _) = self.connect().await?;
        if let Err(_) = client.watch_connection_changes().await {
            self.close_for_reconnect().await;
            return Err(ClientError::Send);
        }
        Ok(())
    }

    /// Send a "close peer" request to the server.
    ///
    /// If there is no underlying active derp connection, it creates one before attempting to
    /// send the request.
    ///
    /// If there is an error sending, it closes the underlying derp connection before
    /// returning.
    pub async fn close_peer(&self, target: key::node::PublicKey) -> Result<(), ClientError> {
        let (client, _) = self.connect().await?;
        if let Err(_) = client.close_peer(target).await {
            self.close_for_reconnect().await;
            return Err(ClientError::Send);
        }
        Ok(())
    }
}

impl PacketForwarder for Client {
    fn forward_packet(
        &mut self,
        srckey: key::node::PublicKey,
        dstkey: key::node::PublicKey,
        packet: bytes::Bytes,
    ) {
        let packet_forwarder = self.clone();
        tokio::spawn(async move {
            // attempt to send the packet 3 times
            for _ in 0..3 {
                let srckey = srckey.clone();
                let dstkey = dstkey.clone();
                let packet = packet.clone();
                if let Ok((client, _)) = packet_forwarder.connect().await {
                    if let Ok(_) = client.forward_packet(srckey, dstkey, packet).await {
                        return;
                    }
                }
            }
            tracing::warn!("attempted three times to forward packet from {srckey:?} to {dstkey:?}, failed. Dropping packet.");
        });
    }
}
