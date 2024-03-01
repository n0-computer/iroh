use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

use anyhow::Context;
use backoff::backoff::Backoff;
use bytes::{Bytes, BytesMut};
use futures::Future;
use iroh_metrics::{inc, inc_by};
use tokio::{
    sync::{mpsc, oneshot},
    task::{JoinHandle, JoinSet},
    time,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, info_span, trace, warn, Instrument};

use crate::{
    derp::{self, http::ClientError, DerpUrl, ReceivedMessage, MAX_PACKET_SIZE},
    discovery::pkarr_relay_publish::DEFAULT_PKARR_TTL,
    dns::node_info::NodeInfo,
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
        url: DerpUrl,
        contents: DerpContents,
        peer: PublicKey,
    },
    ConnectAsHomeDerp {
        url: DerpUrl,
    },
    MaybeCloseDerpsOnRebind(Vec<IpAddr>),
}

/// Contains fields for an active DERP connection.
#[derive(Debug)]
struct ActiveDerp {
    /// The time of the last request for its write
    /// channel (currently even if there was no write).
    last_write: Instant,
    msg_sender: mpsc::Sender<ActorMessage>,
    /// Contains optional alternate routes to use as an optimization instead of
    /// contacting a peer via their home DERP connection. If they sent us a message
    /// on this DERP connection (which should really only be on our DERP
    /// home connection, or what was once our home), then we remember that route here to optimistically
    /// use instead of creating a new DERP connection back to their home.
    derp_routes: Vec<PublicKey>,
    url: DerpUrl,
    derp_client: derp::http::Client,
    derp_client_receiver: derp::http::ClientReceiver,
    /// The set of senders we know are present on this connection, based on
    /// messages we've received from the server.
    peer_present: HashSet<PublicKey>,
    backoff: backoff::exponential::ExponentialBackoff<backoff::SystemClock>,
    last_packet_time: Option<Instant>,
    last_packet_src: Option<PublicKey>,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum ActiveDerpMessage {
    GetLastWrite(oneshot::Sender<Instant>),
    Ping(oneshot::Sender<Result<Duration, ClientError>>),
    GetLocalAddr(oneshot::Sender<Option<SocketAddr>>),
    GetPeerRoute(PublicKey, oneshot::Sender<Option<derp::http::Client>>),
    GetClient(oneshot::Sender<derp::http::Client>),
    NotePreferred(bool),
    PkarrPublish(pkarr::SignedPacket),
    Shutdown,
}

impl ActiveDerp {
    fn new(
        url: DerpUrl,
        derp_client: derp::http::Client,
        derp_client_receiver: derp::http::ClientReceiver,
        msg_sender: mpsc::Sender<ActorMessage>,
    ) -> Self {
        ActiveDerp {
            last_write: Instant::now(),
            msg_sender,
            derp_routes: Default::default(),
            url,
            peer_present: HashSet::new(),
            backoff: backoff::exponential::ExponentialBackoffBuilder::new()
                .with_initial_interval(Duration::from_millis(10))
                .with_max_interval(Duration::from_secs(5))
                .build(),
            last_packet_time: None,
            last_packet_src: None,
            derp_client,
            derp_client_receiver,
        }
    }

    async fn run(mut self, mut inbox: mpsc::Receiver<ActiveDerpMessage>) -> anyhow::Result<()> {
        self.derp_client
            .connect()
            .await
            .context("initial connection")?;

        loop {
            tokio::select! {
                Some(msg) = inbox.recv() => {
                    trace!("tick: inbox: {:?}", msg);
                    match msg {
                        ActiveDerpMessage::GetLastWrite(r) => {
                            r.send(self.last_write).ok();
                        }
                        ActiveDerpMessage::Ping(r) => {
                            r.send(self.derp_client.ping().await).ok();
                        }
                        ActiveDerpMessage::GetLocalAddr(r) => {
                            r.send(self.derp_client.local_addr().await).ok();
                        }
                        ActiveDerpMessage::GetClient(r) => {
                            self.last_write = Instant::now();
                            r.send(self.derp_client.clone()).ok();
                        }
                        ActiveDerpMessage::NotePreferred(is_preferred) => {
                            self.derp_client.note_preferred(is_preferred).await;
                        }
                        ActiveDerpMessage::PkarrPublish(packet) => {
                            self.derp_client.pkarr_publish(packet).await;
                        }
                        ActiveDerpMessage::GetPeerRoute(peer, r) => {
                            let res = if self.derp_routes.contains(&peer) {
                                Some(self.derp_client.clone())
                            } else {
                                None
                            };
                            r.send(res).ok();
                        }
                        ActiveDerpMessage::Shutdown => {
                            self.derp_client.close().await.ok();
                            break;
                        }
                    }
                }
                msg = self.derp_client_receiver.recv() => {
                    trace!("tick: derp_client_receiver");
                    if let Some(msg) = msg {
                        if self.handle_derp_msg(msg).await == ReadResult::Break {
                            // fatal error
                            self.derp_client.close().await.ok();
                            break;
                        }
                    }
                }
                else => {
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_derp_msg(
        &mut self,
        msg: Result<(ReceivedMessage, usize), ClientError>,
    ) -> ReadResult {
        match msg {
            Err(err) => {
                warn!("recv error {:?}", err);

                // Forget that all these peers have routes.
                let peers: Vec<_> = self.peer_present.drain().collect();
                self.derp_routes.retain(|peer| !peers.contains(peer));

                if matches!(
                    err,
                    derp::http::ClientError::Closed | derp::http::ClientError::IPDisabled
                ) {
                    // drop client
                    return ReadResult::Break;
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
                        ReadResult::Continue
                    }
                    None => ReadResult::Break,
                }
            }
            Ok((msg, conn_gen)) => {
                // reset
                self.backoff.reset();
                let now = Instant::now();
                if self
                    .last_packet_time
                    .as_ref()
                    .map(|t| t.elapsed() > Duration::from_secs(5))
                    .unwrap_or(true)
                {
                    self.last_packet_time = Some(now);
                }

                match msg {
                    derp::ReceivedMessage::ServerInfo { .. } => {
                        info!(%conn_gen, "connected");
                        ReadResult::Continue
                    }
                    derp::ReceivedMessage::ReceivedPacket { source, data } => {
                        trace!(len=%data.len(), "received msg");
                        // If this is a new sender we hadn't seen before, remember it and
                        // register a route for this peer.
                        if self
                            .last_packet_src
                            .as_ref()
                            .map(|p| *p != source)
                            .unwrap_or(true)
                        {
                            // avoid map lookup w/ high throughput single peer
                            self.last_packet_src = Some(source);
                            if !self.peer_present.contains(&source) {
                                self.peer_present.insert(source);
                                self.derp_routes.push(source);
                            }
                        }

                        let res = DerpReadResult {
                            url: self.url.clone(),
                            src: source,
                            buf: data,
                        };
                        if let Err(err) = self.msg_sender.try_send(ActorMessage::ReceiveDerp(res)) {
                            warn!("dropping received DERP packet: {:?}", err);
                        }

                        ReadResult::Continue
                    }
                    derp::ReceivedMessage::Ping(data) => {
                        // Best effort reply to the ping.
                        let dc = self.derp_client.clone();
                        tokio::task::spawn(async move {
                            if let Err(err) = dc.send_pong(data).await {
                                warn!("pong error: {:?}", err);
                            }
                        });
                        ReadResult::Continue
                    }
                    derp::ReceivedMessage::Health { .. } => ReadResult::Continue,
                    derp::ReceivedMessage::PeerGone(key) => {
                        self.derp_routes.retain(|peer| peer != &key);
                        ReadResult::Continue
                    }
                    other => {
                        trace!("ignoring: {:?}", other);
                        // Ignore.
                        ReadResult::Continue
                    }
                }
            }
        }
    }
}

pub(super) struct DerpActor {
    conn: Arc<Inner>,
    /// DERP Url -> connection to the node
    active_derp: BTreeMap<DerpUrl, (mpsc::Sender<ActiveDerpMessage>, JoinHandle<()>)>,
    msg_sender: mpsc::Sender<ActorMessage>,
    ping_tasks: JoinSet<(DerpUrl, bool)>,
    cancel_token: CancellationToken,
}

impl DerpActor {
    pub(super) fn new(conn: Arc<Inner>, msg_sender: mpsc::Sender<ActorMessage>) -> Self {
        let cancel_token = CancellationToken::new();
        DerpActor {
            conn,
            active_derp: Default::default(),
            msg_sender,
            ping_tasks: Default::default(),
            cancel_token,
        }
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    pub(super) async fn run(mut self, mut receiver: mpsc::Receiver<DerpActorMessage>) {
        let mut cleanup_timer = time::interval_at(
            time::Instant::now() + DERP_CLEAN_STALE_INTERVAL,
            DERP_CLEAN_STALE_INTERVAL,
        );

        loop {
            tokio::select! {
                biased;

                _ = self.cancel_token.cancelled() => {
                    trace!("shutting down");
                    break;
                }
                Some(Ok((url, ping_success))) = self.ping_tasks.join_next() => {
                    if !ping_success {
                        with_cancel(
                            self.cancel_token.child_token(),
                            self.close_or_reconnect_derp(&url, "rebind-ping-fail")
                        ).await;
                    }
                }
                Some(msg) = receiver.recv() => {
                    with_cancel(self.cancel_token.child_token(), self.handle_msg(msg)).await;
                }
                _ = cleanup_timer.tick() => {
                    trace!("tick: cleanup");
                    with_cancel(self.cancel_token.child_token(), self.clean_stale_derp()).await;
                }
                else => {
                    trace!("shutting down derp recv loop");
                    break;
                }
            }
        }

        // try shutdown
        self.close_all_derp("conn-close").await;
    }

    async fn handle_msg(&mut self, msg: DerpActorMessage) {
        match msg {
            DerpActorMessage::Send {
                url,
                contents,
                peer,
            } => {
                self.send_derp(&url, contents, peer).await;
            }
            DerpActorMessage::ConnectAsHomeDerp { url } => {
                self.connect_derp_as_home(&url).await;
            }
            DerpActorMessage::MaybeCloseDerpsOnRebind(ifs) => {
                self.maybe_close_derps_on_rebind(&ifs).await;
            }
        }
    }

    async fn note_preferred(&self, my_url: &DerpUrl) {
        futures::future::join_all(self.active_derp.iter().map(|(url, (s, _))| async move {
            let is_preferred = url == my_url;
            s.send(ActiveDerpMessage::NotePreferred(is_preferred))
                .await
                .ok()
        }))
        .await;
    }

    async fn send_derp(&mut self, url: &DerpUrl, contents: DerpContents, peer: PublicKey) {
        trace!(%url, peer = %peer.fmt_short(),len = contents.iter().map(|c| c.len()).sum::<usize>(),  "sending derp");
        // Derp Send
        let derp_client = self.connect_derp(url, Some(&peer)).await;
        for content in &contents {
            trace!(%url, ?peer, "sending {}B", content.len());
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
                    warn!(%url, "send: failed {:?}", err);
                    inc!(MagicsockMetrics, send_derp_error);
                }
            }
        }

        // Wake up the send waker if one is waiting for space in the channel
        let mut wakers = self.conn.network_send_wakers.lock();
        if let Some(waker) = wakers.take() {
            waker.wake();
        }
    }

    /// Returns `true`if the message was sent successfully.
    async fn send_to_active(&mut self, url: &DerpUrl, msg: ActiveDerpMessage) -> bool {
        match self.active_derp.get(url) {
            Some((s, _)) => match s.send(msg).await {
                Ok(_) => true,
                Err(mpsc::error::SendError(_)) => {
                    self.close_derp(url, "sender-closed").await;
                    false
                }
            },
            None => false,
        }
    }

    async fn connect_derp_as_home(&mut self, url: &DerpUrl) {
        self.connect_derp(url, None).await;
        self.note_preferred(url).await;
        if let Err(err) = self.pkarr_announce_to_derp(url).await {
            warn!(?err, %url, "failed to send pkarr self-announce to home derper");
        }
    }

    async fn pkarr_announce_to_derp(&self, my_derp: &DerpUrl) -> anyhow::Result<()> {
        if let Some(_opts) = &self.conn.pkarr_announce {
            let s = self
                .active_derp
                .iter()
                .find_map(|(derp_url, (s, _))| (derp_url == my_derp).then_some(s))
                .context("home derp not in list of active derps")?;
            // TODO: support direct addrs?
            // let addrs = opts.include_addrs.then(|| {
            //     let local_endpoints = self.conn.endpoints.read();
            //     let local_endpoints = local_endpoints.iter().map(|ep| ep.addr);
            //     local_endpoints.collect()
            // });
            let info = NodeInfo::new(self.conn.secret_key.public(), Some(my_derp.clone()));
            let packet = info.to_pkarr_signed_packet(&self.conn.secret_key, DEFAULT_PKARR_TTL)?;
            s.send(ActiveDerpMessage::PkarrPublish(packet)).await?;
        }
        Ok(())
    }

    /// Connect to the given derp node.
    async fn connect_derp(
        &mut self,
        url: &DerpUrl,
        peer: Option<&PublicKey>,
    ) -> derp::http::Client {
        // See if we have a connection open to that DERP node ID first. If so, might as
        // well use it. (It's a little arbitrary whether we use this one vs. the reverse route
        // below when we have both.)

        {
            let (os, or) = oneshot::channel();
            if self
                .send_to_active(url, ActiveDerpMessage::GetClient(os))
                .await
            {
                if let Ok(client) = or.await {
                    return client;
                }
            }
        }

        // If we don't have an open connection to the peer's home DERP
        // node, see if we have an open connection to a DERP node
        // where we'd heard from that peer already. For instance,
        // perhaps peer's home is Frankfurt, but they dialed our home DERP
        // node in SF to reach us, so we can reply to them using our
        // SF connection rather than dialing Frankfurt.
        if let Some(peer) = peer {
            for url in self
                .active_derp
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .into_iter()
            {
                let (os, or) = oneshot::channel();
                if self
                    .send_to_active(&url, ActiveDerpMessage::GetPeerRoute(*peer, os))
                    .await
                {
                    if let Ok(Some(client)) = or.await {
                        return client;
                    }
                }
            }
        }

        let why = if let Some(peer) = peer {
            format!("{peer:?}")
        } else {
            "home-keep-alive".to_string()
        };
        info!("adding connection to derp-{url} for {why}");

        let my_derp = self.conn.my_derp();
        let ipv6_reported = self.conn.ipv6_reported.clone();
        let url = url.clone();
        let url1 = url.clone();

        // building a client does not dial
        let (dc, dc_receiver) = derp::http::ClientBuilder::new(url1.clone())
            .address_family_selector(move || {
                let ipv6_reported = ipv6_reported.clone();
                Box::pin(async move { ipv6_reported.load(Ordering::Relaxed) })
            })
            .can_ack_pings(true)
            .is_preferred(my_derp.as_ref() == Some(&url1))
            .build(self.conn.secret_key.clone());

        let (s, r) = mpsc::channel(64);

        let c = dc.clone();
        let msg_sender = self.msg_sender.clone();
        let url1 = url.clone();
        let handle = tokio::task::spawn(
            async move {
                let ad = ActiveDerp::new(url1, c, dc_receiver, msg_sender);

                if let Err(err) = ad.run(r).await {
                    warn!("connection error: {:?}", err);
                }
            }
            .instrument(info_span!("active-derp", %url)),
        );

        // Insert, to make sure we do not attempt to double connect.
        self.active_derp.insert(url.clone(), (s, handle));

        inc!(MagicsockMetrics, num_derp_conns_added);

        self.log_active_derp();

        dc
    }

    /// Closes the DERP connections not originating from a local IP address.
    ///
    /// Called in response to a rebind, any DERP connection originating from an address
    /// that's not known to be currently a local IP address should be closed.  All the other
    /// DERP connections are pinged.
    async fn maybe_close_derps_on_rebind(&mut self, okay_local_ips: &[IpAddr]) {
        let mut tasks = Vec::new();
        for url in self
            .active_derp
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
        {
            let (os, or) = oneshot::channel();
            let la = if self
                .send_to_active(&url, ActiveDerpMessage::GetLocalAddr(os))
                .await
            {
                match or.await {
                    Ok(None) | Err(_) => {
                        tasks.push((url, "rebind-no-localaddr"));
                        continue;
                    }
                    Ok(Some(la)) => la,
                }
            } else {
                tasks.push((url.clone(), "rebind-no-localaddr"));
                continue;
            };

            if !okay_local_ips.contains(&la.ip()) {
                tasks.push((url, "rebind-default-route-change"));
                continue;
            }

            let (os, or) = oneshot::channel();
            let ping_sent = self.send_to_active(&url, ActiveDerpMessage::Ping(os)).await;

            self.ping_tasks.spawn(async move {
                let ping_success = time::timeout(Duration::from_secs(3), async {
                    if ping_sent {
                        or.await.is_ok()
                    } else {
                        false
                    }
                })
                .await
                .unwrap_or(false);

                (url, ping_success)
            });
        }

        for (url, why) in tasks {
            self.close_or_reconnect_derp(&url, why).await;
        }

        self.log_active_derp();
    }

    /// Closes the DERP connection to the provided `url` and starts reconnecting it if it's
    /// our current home DERP.
    async fn close_or_reconnect_derp(&mut self, url: &DerpUrl, why: &'static str) {
        self.close_derp(url, why).await;
        if self.conn.my_derp().as_ref() == Some(url) {
            self.connect_derp_as_home(url).await;
        }
    }

    async fn clean_stale_derp(&mut self) {
        trace!("checking {} derps for staleness", self.active_derp.len());
        let now = Instant::now();

        let mut to_close = Vec::new();
        for (i, (s, _)) in &self.active_derp {
            if Some(i) == self.conn.my_derp().as_ref() {
                continue;
            }
            let (os, or) = oneshot::channel();
            match s.send(ActiveDerpMessage::GetLastWrite(os)).await {
                Ok(_) => match or.await {
                    Ok(last_write) => {
                        if last_write.duration_since(now) > DERP_INACTIVE_CLEANUP_TIME {
                            to_close.push(i.clone());
                        }
                    }
                    Err(_) => {
                        to_close.push(i.clone());
                    }
                },
                Err(_) => {
                    to_close.push(i.clone());
                }
            }
        }

        let dirty = !to_close.is_empty();
        trace!(
            "closing {} of {} derps",
            to_close.len(),
            self.active_derp.len()
        );
        for i in to_close {
            self.close_derp(&i, "idle").await;
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
        let urls: Vec<_> = self.active_derp.keys().cloned().collect();
        for url in urls {
            self.close_derp(&url, why).await;
        }
        self.log_active_derp();
    }

    async fn close_derp(&mut self, url: &DerpUrl, why: &'static str) {
        if let Some((s, t)) = self.active_derp.remove(url) {
            debug!(%url, "closing connection: {}", why);

            s.send(ActiveDerpMessage::Shutdown).await.ok();
            t.abort(); // ensure the task is shutdown

            inc!(MagicsockMetrics, num_derp_conns_removed);
        }
    }

    fn log_active_derp(&self) {
        debug!("{} active derp conns{}", self.active_derp.len(), {
            let mut s = String::new();
            if !self.active_derp.is_empty() {
                s += ":";
                for node in self.active_derp_sorted() {
                    s += &format!(" derp-{}", node,);
                }
            }
            s
        });
    }

    fn active_derp_sorted(&self) -> impl Iterator<Item = DerpUrl> {
        let mut ids: Vec<_> = self.active_derp.keys().cloned().collect();
        ids.sort();

        ids.into_iter()
    }
}

#[derive(derive_more::Debug)]
pub(super) struct DerpReadResult {
    pub(super) url: DerpUrl,
    pub(super) src: PublicKey,
    /// packet data
    #[debug(skip)]
    pub(super) buf: Bytes,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ReadResult {
    Break,
    Continue,
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

async fn with_cancel<F>(token: CancellationToken, f: F)
where
    F: Future<Output = ()>,
{
    tokio::select! {
        _ = token.cancelled_owned() => {
            // abort
        }
        _ = f => {
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
