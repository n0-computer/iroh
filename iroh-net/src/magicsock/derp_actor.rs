use std::{
    collections::{hash_map, HashMap, HashSet},
    net::IpAddr,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

use backoff::backoff::Backoff;
use bytes::{Bytes, BytesMut};
use iroh_metrics::{inc, inc_by};
use tokio::{sync::mpsc, time};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use crate::{
    derp::{self, MAX_PACKET_SIZE},
    key::{PublicKey, PUBLIC_KEY_LENGTH},
};

use super::{ActorMessage, Inner};
use super::{DerpContents, Metrics as MagicsockMetrics};

/// How long a non-home DERP connection needs to be idle (last written to) before we close it.
const DERP_INACTIVE_CLEANUP_TIME: Duration = Duration::from_secs(60);

/// How often `clean_stale_derp` runs when there are potentially-stale DERP connections to close.
const DERP_CLEAN_STALE_INTERVAL: Duration = Duration::from_secs(15);

pub(super) enum DerpActorMessage {
    Send {
        region_id: u16,
        contents: DerpContents,
        peer: PublicKey,
    },
    Connect {
        region_id: u16,
        peer: Option<PublicKey>,
    },
    CloseOrReconnect {
        region_id: u16,
        reason: &'static str,
    },
    NotePreferred(u16),
    MaybeCloseDerpsOnRebind(Vec<IpAddr>),
    Shutdown,
}

/// Contains fields for an active DERP connection.
#[derive(Debug)]
struct ActiveDerp {
    c: derp::http::Client,
    cancel: CancellationToken,
    /// The time of the last request for its write
    /// channel (currently even if there was no write).
    last_write: Instant,
    create_time: Instant,
    reader: ReaderState,
}

/// A route entry for a public key, saying that a certain peer should be available at DERP
/// node derpID, as long as the current connection for that derpID is dc. (but dc should not be
/// used to write directly; it's owned by the read/write loops)
#[derive(Debug)]
struct DerpRoute {
    derp_id: u16,
    dc: derp::http::Client, // don't use directly; see comment above
}

pub(super) struct DerpActor {
    conn: Arc<Inner>,
    /// DERP regionID -> connection to a node in that region
    active_derp: HashMap<u16, ActiveDerp>,
    /// Contains optional alternate routes to use as an optimization instead of
    /// contacting a peer via their home DERP connection.  If they sent us a message
    /// on a different DERP connection (which should really only be on our DERP
    /// home connection, or what was once our home), then we remember that route here to optimistically
    /// use instead of creating a new DERP connection back to their home.
    derp_route: HashMap<PublicKey, DerpRoute>,
    msg_sender: mpsc::Sender<ActorMessage>,
}

impl DerpActor {
    pub(super) fn new(conn: Arc<Inner>, msg_sender: mpsc::Sender<ActorMessage>) -> Self {
        DerpActor {
            conn,
            active_derp: HashMap::default(),
            derp_route: HashMap::new(),
            msg_sender,
        }
    }

    pub(super) async fn run(mut self, mut receiver: mpsc::Receiver<DerpActorMessage>) {
        let mut cleanup_timer = time::interval_at(
            time::Instant::now() + DERP_CLEAN_STALE_INTERVAL,
            DERP_CLEAN_STALE_INTERVAL,
        );

        loop {
            tokio::select! {
                Some(msg) = receiver.recv() => {
                    match msg {
                        DerpActorMessage::Send { region_id, contents, peer } => {
                            self.send_derp(region_id, contents, peer).await;
                        }
                        DerpActorMessage::Connect { region_id, peer } => {
                            self.connect_derp(region_id, peer.as_ref()).await;
                        }
                        DerpActorMessage::CloseOrReconnect { region_id, reason } => {
                            self.close_or_reconnect_derp(region_id, reason).await;
                        }
                        DerpActorMessage::NotePreferred(my_derp) => {
                            self.note_preferred(my_derp).await;
                        }
                        DerpActorMessage::MaybeCloseDerpsOnRebind(ifs) => {
                            self.maybe_close_derps_on_rebind(&ifs).await;
                        }
                        DerpActorMessage::Shutdown => {
                            debug!("shutting down");
                            self.close_all_derp("conn-close").await;
                            break;
                        }
                    }
                }
                (region_id, result, action) = self.recv_all() => {
                    trace!("tick: recvs: {:?}, {:?}", result, action);
                    match action {
                        ReadAction::None => {},
                        ReadAction::AddPeerRoutes { peers, region, derp_client } => {
                            self.add_derp_peer_routes(peers, region, derp_client);
                        },
                        ReadAction::RemovePeerRoutes { peers, region, derp_client } => {
                            self.remove_derp_peer_routes(peers, region, &derp_client);
                        }
                    }
                    match result {
                        ReadResult::Break => {
                            // drop client
                            self.close_derp(region_id, "read error").await;
                        }
                        ReadResult::Continue => {}
                        ReadResult::Yield(read_result) => {
                            self.msg_sender.send(ActorMessage::ReceiveDerp(read_result)).await.ok();
                        }
                    }
                }
                _ = cleanup_timer.tick() => {
                    trace!("tick: cleanup");
                    self.clean_stale_derp().await;
                }
                else => {
                    trace!("shutting down derp recv loop");
                    break;
                }
            }
        }
    }

    async fn recv_all(&mut self) -> (u16, ReadResult, ReadAction) {
        if self.active_derp.is_empty() {
            futures::future::pending::<(u16, ReadResult, ReadAction)>().await;
        }

        let ((region, (result, action)), _, _) =
            futures::future::select_all(self.active_derp.iter_mut().map(|(region, ad)| {
                Box::pin(async move {
                    let res = ad.reader.recv().await;
                    (*region, res)
                })
            }))
            .await;

        (region, result, action)
    }

    async fn note_preferred(&self, my_num: u16) {
        futures::future::join_all(self.active_derp.iter().map(|(i, ad)| async move {
            let b = *i == my_num;
            ad.c.note_preferred(b).await;
        }))
        .await;
    }

    async fn send_derp(&mut self, region_id: u16, contents: DerpContents, peer: PublicKey) {
        debug!(region_id, ?peer, "sending derp");
        if !self.conn.derp_map.contains_region(region_id) {
            warn!("unknown region id {}", region_id);
            return;
        }

        // Derp Send
        let derp_client = self.connect_derp(region_id, Some(&peer)).await;
        for content in &contents {
            trace!("[DERP] -> {} ({}b) {:?}", region_id, content.len(), peer);
        }
        let total_bytes = contents.iter().map(|c| c.len() as u64).sum::<u64>();

        const PAYLAOD_SIZE: usize = MAX_PACKET_SIZE - PUBLIC_KEY_LENGTH;

        // Split into multiple packets if needed.
        // In almost all cases this will be a single packet.
        // But we have no guarantee that the total size of the contents including
        // length prefix will be smaller than the payload size.
        for packet in PacketizeIter::<_, PAYLAOD_SIZE>::new(contents) {
            match derp_client.send(peer, packet).await {
                Ok(_) => {
                    inc_by!(MagicsockMetrics, send_derp, total_bytes);
                }
                Err(err) => {
                    warn!("derp.send: failed {:?}", err);
                    inc!(MagicsockMetrics, send_derp_error);
                }
            }
        }

        // Wake up the send waker if one is waiting for space in the channel
        let mut wakers = self.conn.network_send_wakers.lock().unwrap();
        if let Some(waker) = wakers.take() {
            waker.wake();
        }
    }

    /// Connect to the given derp region.
    async fn connect_derp(
        &mut self,
        region_id: u16,
        peer: Option<&PublicKey>,
    ) -> derp::http::Client {
        // See if we have a connection open to that DERP node ID first. If so, might as
        // well use it. (It's a little arbitrary whether we use this one vs. the reverse route
        // below when we have both.)

        if let Some(ad) = self.active_derp.get_mut(&region_id) {
            ad.last_write = Instant::now();
            return ad.c.clone();
        }

        // If we don't have an open connection to the peer's home DERP
        // node, see if we have an open connection to a DERP node
        // where we'd heard from that peer already. For instance,
        // perhaps peer's home is Frankfurt, but they dialed our home DERP
        // node in SF to reach us, so we can reply to them using our
        // SF connection rather than dialing Frankfurt.
        if let Some(peer) = peer {
            if let Some(r) = self.derp_route.get(peer) {
                if let Some(ad) = self.active_derp.get_mut(&r.derp_id) {
                    if ad.c == r.dc {
                        ad.last_write = Instant::now();
                        return ad.c.clone();
                    }
                }
            }
        }

        let why = if let Some(peer) = peer {
            format!("{peer:?}")
        } else {
            "home-keep-alive".to_string()
        };
        info!("adding connection to derp-{region_id} for {why}");

        let my_derp = self.conn.my_derp();
        let conn1 = self.conn.clone();
        let ipv6_reported = self.conn.ipv6_reported.clone();

        // building a client does not dial
        let dc = derp::http::ClientBuilder::new()
            .address_family_selector(move || {
                let ipv6_reported = ipv6_reported.clone();
                Box::pin(async move { ipv6_reported.load(Ordering::Relaxed) })
            })
            .can_ack_pings(true)
            .is_preferred(my_derp == region_id)
            .get_region(move || {
                let conn = conn1.clone();
                Box::pin(async move {
                    if conn.is_closing() {
                        // We're closing anyway; return to stop dialing.
                        return None;
                    }
                    conn.get_derp_region(region_id).await
                })
            })
            .build(self.conn.secret_key.clone())
            .expect("will only fail is a `get_region` callback is not supplied");

        let cancel = CancellationToken::new();
        let ad = ActiveDerp {
            c: dc.clone(),
            cancel: cancel.clone(),
            last_write: Instant::now(),
            create_time: Instant::now(),
            reader: ReaderState::new(region_id, cancel, dc.clone()),
        };

        // Insert, to make sure we do not attempt to double connect.
        self.active_derp.insert(region_id, ad);

        // Kickoff a connection establishment in the background
        let dc_spawn = dc.clone();
        tokio::task::spawn(async move {
            // Make sure we can establish a connection.
            if let Err(err) = dc_spawn.connect().await {
                // TODO: what to do?
                warn!("failed to connect to derp server: {:?}", err);
            }
        });

        inc!(MagicsockMetrics, num_derp_conns_added);

        self.log_active_derp();

        if let Some(ref f) = self.conn.on_derp_active {
            // TODO: spawn
            f();
        }

        dc
    }

    /// Called in response to a rebind, closes all DERP connections that don't have a local address in okay_local_ips
    /// and pings all those that do.
    async fn maybe_close_derps_on_rebind(&mut self, okay_local_ips: &[IpAddr]) {
        let mut tasks = Vec::new();
        for (region_id, ad) in &self.active_derp {
            let la = match ad.c.local_addr().await {
                None => {
                    tasks.push((*region_id, "rebind-no-localaddr"));
                    continue;
                }
                Some(la) => la,
            };

            if !okay_local_ips.contains(&la.ip()) {
                tasks.push((*region_id, "rebind-default-route-change"));
                continue;
            }

            let dc = ad.c.clone();
            let region_id = *region_id;
            let msg_sender = self.msg_sender.clone();
            tokio::task::spawn(time::timeout(Duration::from_secs(3), async move {
                if let Err(_err) = dc.ping().await {
                    msg_sender
                        .send(ActorMessage::CloseOrReconnect(
                            region_id,
                            "rebind-ping-fail",
                        ))
                        .await
                        .unwrap();
                    return;
                }
                debug!("post-rebind ping of DERP region {} okay", region_id);
            }));
        }
        for (region_id, why) in tasks {
            self.close_or_reconnect_derp(region_id, why).await;
        }

        self.log_active_derp();
    }

    /// Closes the DERP connection to the provided `region_id` and starts reconnecting it if it's
    /// our current home DERP.
    async fn close_or_reconnect_derp(&mut self, region_id: u16, why: &'static str) {
        self.close_derp(region_id, why).await;
        if self.conn.my_derp() == region_id {
            self.connect_derp(region_id, None).await;
        }
    }

    async fn clean_stale_derp(&mut self) {
        debug!("cleanup {} derps", self.active_derp.len());
        let now = Instant::now();

        let mut to_close = Vec::new();
        for (i, ad) in &self.active_derp {
            if *i == self.conn.my_derp() {
                continue;
            }
            if ad.last_write.duration_since(now) > DERP_INACTIVE_CLEANUP_TIME {
                to_close.push(*i);
            }
        }

        let dirty = !to_close.is_empty();
        debug!(
            "closing {}/{} derps",
            to_close.len(),
            self.active_derp.len()
        );
        for i in to_close {
            self.close_derp(i, "idle").await;
        }
        if dirty {
            self.log_active_derp();
        }
    }

    async fn close_all_derp(&mut self, why: &'static str) {
        if self.active_derp.is_empty() {
            return;
        }
        // Need to collect to avoid double borrow
        let regions: Vec<_> = self.active_derp.keys().copied().collect();
        for region in regions {
            self.close_derp(region, why).await;
        }
        self.log_active_derp();
    }

    async fn close_derp(&mut self, region_id: u16, why: &'static str) {
        if let Some(ad) = self.active_derp.remove(&region_id) {
            debug!(
                "closing connection to derp-{} ({:?}), age {}s",
                region_id,
                why,
                ad.create_time.elapsed().as_secs()
            );

            let ActiveDerp { c, cancel, .. } = ad;
            c.close().await;
            cancel.cancel();

            inc!(MagicsockMetrics, num_derp_conns_removed);
        }
    }

    fn log_active_derp(&self) {
        let now = Instant::now();
        debug!("{} active derp conns{}", self.active_derp.len(), {
            let mut s = String::new();
            if !self.active_derp.is_empty() {
                s += ":";
                for (node, ad) in self.active_derp_sorted() {
                    s += &format!(
                        " derp-{}=cr{},wr{}",
                        node,
                        now.duration_since(ad.create_time).as_secs(),
                        now.duration_since(ad.last_write).as_secs()
                    );
                }
            }
            s
        });
    }

    fn active_derp_sorted(&self) -> impl Iterator<Item = (u16, &'_ ActiveDerp)> + '_ {
        let mut ids: Vec<_> = self.active_derp.keys().copied().collect();
        ids.sort();

        ids.into_iter()
            .map(|id| (id, self.active_derp.get(&id).unwrap()))
    }

    /// Removes a DERP route entry previously added by add_derp_peer_route.
    fn remove_derp_peer_routes(
        &mut self,
        peers: Vec<PublicKey>,
        derp_id: u16,
        dc: &derp::http::Client,
    ) {
        for peer in peers {
            if let hash_map::Entry::Occupied(r) = self.derp_route.entry(peer) {
                if r.get().derp_id == derp_id && &r.get().dc == dc {
                    r.remove();
                }
            }
        }
    }

    /// Adds DERP route entries, noting that peer was seen on DERP node `derp_id`, at least on the
    /// connection identified by `dc`.
    fn add_derp_peer_routes(
        &mut self,
        peers: Vec<PublicKey>,
        derp_id: u16,
        dc: derp::http::Client,
    ) {
        for peer in peers {
            self.derp_route.insert(
                peer,
                DerpRoute {
                    derp_id,
                    dc: dc.clone(),
                },
            );
        }
    }
}

#[derive(derive_more::Debug)]
pub(super) struct DerpReadResult {
    pub(super) region_id: u16,
    pub(super) src: PublicKey,
    /// packet data
    #[debug(skip)]
    pub(super) buf: Bytes,
}

/// Manages reading state for a single derp connection.
#[derive(Debug)]
struct ReaderState {
    region: u16,
    derp_client: derp::http::Client,
    /// The set of senders we know are present on this connection, based on
    /// messages we've received from the server.
    peer_present: HashSet<PublicKey>,
    backoff: backoff::exponential::ExponentialBackoff<backoff::SystemClock>,
    last_packet_time: Option<Instant>,
    last_packet_src: Option<PublicKey>,
    cancel: CancellationToken,
}

#[derive(Debug)]
pub(super) enum ReadResult {
    Yield(DerpReadResult),
    Break,
    Continue,
}

#[derive(Debug)]
pub(super) enum ReadAction {
    None,
    RemovePeerRoutes {
        peers: Vec<PublicKey>,
        region: u16,
        derp_client: derp::http::Client,
    },
    AddPeerRoutes {
        peers: Vec<PublicKey>,
        region: u16,
        derp_client: derp::http::Client,
    },
}

impl ReaderState {
    fn new(region: u16, cancel: CancellationToken, derp_client: derp::http::Client) -> Self {
        ReaderState {
            region,
            derp_client,
            cancel,
            peer_present: HashSet::new(),
            backoff: backoff::exponential::ExponentialBackoffBuilder::new()
                .with_initial_interval(Duration::from_millis(10))
                .with_max_interval(Duration::from_secs(5))
                .build(),
            last_packet_time: None,
            last_packet_src: None,
        }
    }

    async fn recv(&mut self) -> (ReadResult, ReadAction) {
        let msg = tokio::select! {
            msg = self.derp_client.recv_detail() => {
                msg
            }
            _ = self.cancel.cancelled() => {
                return (ReadResult::Break, ReadAction::None);
            }
        };
        debug!(region_id=%self.region, ?msg, "derp.recv received");

        match msg {
            Err(err) => {
                debug!(
                    "[{:?}] derp.recv(derp-{}): {:?}",
                    self.derp_client, self.region, err
                );

                // Forget that all these peers have routes.
                let peers = self.peer_present.drain().collect();
                let action = ReadAction::RemovePeerRoutes {
                    peers,
                    region: self.region,
                    derp_client: self.derp_client.clone(),
                };

                if matches!(
                    err,
                    derp::http::ClientError::Closed | derp::http::ClientError::IPDisabled
                ) {
                    // drop client
                    return (ReadResult::Break, action);
                }

                // If our DERP connection broke, it might be because our network
                // conditions changed. Start that check.
                // TODO:
                // self.re_stun("derp-recv-error").await;

                // Back off a bit before reconnecting.
                match self.backoff.next_backoff() {
                    Some(t) => {
                        debug!("backoff sleep: {}ms", t.as_millis());
                        time::sleep(t).await;
                        (ReadResult::Continue, action)
                    }
                    None => (ReadResult::Break, action),
                }
            }
            Ok((msg, conn_gen)) => {
                // reset
                self.backoff.reset();
                let now = Instant::now();
                if self.last_packet_time.is_none()
                    || self.last_packet_time.as_ref().unwrap().elapsed() > Duration::from_secs(5)
                {
                    self.last_packet_time = Some(now);
                }

                match msg {
                    derp::ReceivedMessage::ServerInfo { .. } => {
                        info!("derp-{} connected; connGen={}", self.region, conn_gen);
                        (ReadResult::Continue, ReadAction::None)
                    }
                    derp::ReceivedMessage::ReceivedPacket { source, data } => {
                        trace!("[DERP] <- {} ({}b)", self.region, data.len());
                        // If this is a new sender we hadn't seen before, remember it and
                        // register a route for this peer.
                        let action = if self.last_packet_src.is_none()
                            || &source != self.last_packet_src.as_ref().unwrap()
                        {
                            // avoid map lookup w/ high throughput single peer
                            self.last_packet_src = Some(source);
                            let mut peers = Vec::new();
                            if !self.peer_present.contains(&source) {
                                self.peer_present.insert(source);
                                peers.push(source);
                            }
                            ReadAction::AddPeerRoutes {
                                peers,
                                region: self.region,
                                derp_client: self.derp_client.clone(),
                            }
                        } else {
                            ReadAction::None
                        };

                        let res = DerpReadResult {
                            region_id: self.region,
                            src: source,
                            buf: data,
                        };
                        (ReadResult::Yield(res), action)
                    }
                    derp::ReceivedMessage::Ping(data) => {
                        // Best effort reply to the ping.
                        let dc = self.derp_client.clone();
                        let region = self.region;
                        tokio::task::spawn(async move {
                            if let Err(err) = dc.send_pong(data).await {
                                info!("derp-{} send_pong error: {:?}", region, err);
                            }
                        });
                        (ReadResult::Continue, ReadAction::None)
                    }
                    derp::ReceivedMessage::Health { .. } => {
                        // health.SetDERPRegionHealth(regionID, m.Problem);
                        (ReadResult::Continue, ReadAction::None)
                    }
                    derp::ReceivedMessage::PeerGone(key) => {
                        let read_action = ReadAction::RemovePeerRoutes {
                            peers: vec![key],
                            region: self.region,
                            derp_client: self.derp_client.clone(),
                        };

                        (ReadResult::Continue, read_action)
                    }
                    _ => {
                        // Ignore.
                        (ReadResult::Continue, ReadAction::None)
                    }
                }
            }
        }
    }
}

/// Combines blobs into packets of at most MAX_PACKET_SIZE.
///
/// Each item in a packet has a little-endian 2-byte length prefix.
pub(super) struct PacketizeIter<I: Iterator, const N: usize> {
    iter: std::iter::Peekable<I>,
    buffer: BytesMut,
}

impl<I: Iterator, const N: usize> PacketizeIter<I, N> {
    /// Create a new new PacketizeIter from something that can be turned into an
    /// iterator of slices, like a `Vec<Bytes>`.
    pub(super) fn new(iter: impl IntoIterator<IntoIter = I>) -> Self {
        Self {
            iter: iter.into_iter().peekable(),
            buffer: BytesMut::with_capacity(N),
        }
    }
}

impl<I: Iterator, const N: usize> Iterator for PacketizeIter<I, N>
where
    I::Item: AsRef<[u8]>,
{
    type Item = Bytes;

    fn next(&mut self) -> Option<Self::Item> {
        use bytes::BufMut;
        while let Some(next_bytes) = self.iter.peek() {
            let next_bytes = next_bytes.as_ref();
            assert!(next_bytes.len() + 2 <= N);
            let next_length: u16 = next_bytes.len().try_into().expect("items < 64k size");
            if self.buffer.len() + next_bytes.len() + 2 > N {
                break;
            }
            self.buffer.put_u16_le(next_length);
            self.buffer.put_slice(next_bytes);
            self.iter.next();
        }
        if !self.buffer.is_empty() {
            Some(self.buffer.split().freeze())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packetize_iter() {
        let empty_vec: Vec<Bytes> = Vec::new();
        let mut iter = PacketizeIter::<_, MAX_PACKET_SIZE>::new(empty_vec);
        assert_eq!(None, iter.next());

        let single_vec = vec!["Hello"];
        let iter = PacketizeIter::<_, MAX_PACKET_SIZE>::new(single_vec);
        let result = iter.collect::<Vec<_>>();
        assert_eq!(1, result.len());
        assert_eq!(&[5, 0, b'H', b'e', b'l', b'l', b'o'], &result[0][..]);

        let spacer = vec![0u8; MAX_PACKET_SIZE - 10];
        let multiple_vec = vec![&b"Hello"[..], &spacer, &b"World"[..]];
        let iter = PacketizeIter::<_, MAX_PACKET_SIZE>::new(multiple_vec);
        let result = iter.collect::<Vec<_>>();
        assert_eq!(2, result.len());
        assert_eq!(&[5, 0, b'H', b'e', b'l', b'l', b'o'], &result[0][..7]);
        assert_eq!(&[5, 0, b'W', b'o', b'r', b'l', b'd'], &result[1][..]);
    }
}
