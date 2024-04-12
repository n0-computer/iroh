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
    key::{PublicKey, PUBLIC_KEY_LENGTH},
    relay::{self, http::ClientError, ReceivedMessage, RelayUrl, MAX_PACKET_SIZE},
};

use super::{ActorMessage, MagicSockInner};
use super::{Metrics as MagicsockMetrics, RelayContents};

/// How long a non-home relay connection needs to be idle (last written to) before we close it.
const RELAY_INACTIVE_CLEANUP_TIME: Duration = Duration::from_secs(60);

/// How often `clean_stale_relay` runs when there are potentially-stale relay connections to close.
const RELAY_CLEAN_STALE_INTERVAL: Duration = Duration::from_secs(15);

pub(super) enum RelayActorMessage {
    Send {
        url: RelayUrl,
        contents: RelayContents,
        peer: PublicKey,
    },
    MaybeCloseRelaysOnRebind(Vec<IpAddr>),
    SetHome {
        url: RelayUrl,
    },
}

/// Contains fields for an active relay connection.
#[derive(Debug)]
struct ActiveRelay {
    /// The time of the last request for its write
    /// channel (currently even if there was no write).
    last_write: Instant,
    msg_sender: mpsc::Sender<ActorMessage>,
    /// Contains optional alternate routes to use as an optimization instead of
    /// contacting a peer via their home relay connection. If they sent us a message
    /// on this relay connection (which should really only be on our relay
    /// home connection, or what was once our home), then we remember that route here to optimistically
    /// use instead of creating a new relay connection back to their home.
    relay_routes: Vec<PublicKey>,
    url: RelayUrl,
    relay_client: relay::http::Client,
    relay_client_receiver: relay::http::ClientReceiver,
    /// The set of senders we know are present on this connection, based on
    /// messages we've received from the server.
    peer_present: HashSet<PublicKey>,
    backoff: backoff::exponential::ExponentialBackoff<backoff::SystemClock>,
    last_packet_time: Option<Instant>,
    last_packet_src: Option<PublicKey>,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum ActiveRelayMessage {
    GetLastWrite(oneshot::Sender<Instant>),
    Ping(oneshot::Sender<Result<Duration, ClientError>>),
    GetLocalAddr(oneshot::Sender<Option<SocketAddr>>),
    GetPeerRoute(PublicKey, oneshot::Sender<Option<relay::http::Client>>),
    GetClient(oneshot::Sender<relay::http::Client>),
    NotePreferred(bool),
    Shutdown,
}

impl ActiveRelay {
    fn new(
        url: RelayUrl,
        relay_client: relay::http::Client,
        relay_client_receiver: relay::http::ClientReceiver,
        msg_sender: mpsc::Sender<ActorMessage>,
    ) -> Self {
        ActiveRelay {
            last_write: Instant::now(),
            msg_sender,
            relay_routes: Default::default(),
            url,
            peer_present: HashSet::new(),
            backoff: backoff::exponential::ExponentialBackoffBuilder::new()
                .with_initial_interval(Duration::from_millis(10))
                .with_max_interval(Duration::from_secs(5))
                .build(),
            last_packet_time: None,
            last_packet_src: None,
            relay_client,
            relay_client_receiver,
        }
    }

    async fn run(mut self, mut inbox: mpsc::Receiver<ActiveRelayMessage>) -> anyhow::Result<()> {
        debug!("initial dial {}", self.url);
        self.relay_client
            .connect()
            .await
            .context("initial connection")?;

        loop {
            tokio::select! {
                Some(msg) = inbox.recv() => {
                    trace!("tick: inbox: {:?}", msg);
                    match msg {
                        ActiveRelayMessage::GetLastWrite(r) => {
                            r.send(self.last_write).ok();
                        }
                        ActiveRelayMessage::Ping(r) => {
                            r.send(self.relay_client.ping().await).ok();
                        }
                        ActiveRelayMessage::GetLocalAddr(r) => {
                            r.send(self.relay_client.local_addr().await).ok();
                        }
                        ActiveRelayMessage::GetClient(r) => {
                            self.last_write = Instant::now();
                            r.send(self.relay_client.clone()).ok();
                        }
                        ActiveRelayMessage::NotePreferred(is_preferred) => {
                            self.relay_client.note_preferred(is_preferred).await;
                        }
                        ActiveRelayMessage::GetPeerRoute(peer, r) => {
                            let res = if self.relay_routes.contains(&peer) {
                                Some(self.relay_client.clone())
                            } else {
                                None
                            };
                            r.send(res).ok();
                        }
                        ActiveRelayMessage::Shutdown => {
                            self.relay_client.close().await.ok();
                            break;
                        }
                    }
                }
                msg = self.relay_client_receiver.recv() => {
                    trace!("tick: relay_client_receiver");
                    if let Some(msg) = msg {
                        if self.handle_relay_msg(msg).await == ReadResult::Break {
                            // fatal error
                            self.relay_client.close().await.ok();
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

    async fn handle_relay_msg(
        &mut self,
        msg: Result<(ReceivedMessage, usize), ClientError>,
    ) -> ReadResult {
        match msg {
            Err(err) => {
                warn!("recv error {:?}", err);

                // Forget that all these peers have routes.
                let peers: Vec<_> = self.peer_present.drain().collect();
                self.relay_routes.retain(|peer| !peers.contains(peer));

                if matches!(
                    err,
                    relay::http::ClientError::Closed | relay::http::ClientError::IPDisabled
                ) {
                    // drop client
                    return ReadResult::Break;
                }

                // If our relay connection broke, it might be because our network
                // conditions changed. Start that check.
                // TODO:
                // self.re_stun("relay-recv-error").await;

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
                    relay::ReceivedMessage::ServerInfo { .. } => {
                        info!(%conn_gen, "connected");
                        ReadResult::Continue
                    }
                    relay::ReceivedMessage::ReceivedPacket { source, data } => {
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
                                self.relay_routes.push(source);
                            }
                        }

                        let res = RelayReadResult {
                            url: self.url.clone(),
                            src: source,
                            buf: data,
                        };
                        if let Err(err) = self.msg_sender.try_send(ActorMessage::ReceiveRelay(res))
                        {
                            warn!("dropping received relay packet: {:?}", err);
                        }

                        ReadResult::Continue
                    }
                    relay::ReceivedMessage::Ping(data) => {
                        // Best effort reply to the ping.
                        let dc = self.relay_client.clone();
                        tokio::task::spawn(async move {
                            if let Err(err) = dc.send_pong(data).await {
                                warn!("pong error: {:?}", err);
                            }
                        });
                        ReadResult::Continue
                    }
                    relay::ReceivedMessage::Health { .. } => ReadResult::Continue,
                    relay::ReceivedMessage::PeerGone(key) => {
                        self.relay_routes.retain(|peer| peer != &key);
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

pub(super) struct RelayActor {
    msock: Arc<MagicSockInner>,
    /// relay Url -> connection to the node
    active_relay: BTreeMap<RelayUrl, (mpsc::Sender<ActiveRelayMessage>, JoinHandle<()>)>,
    msg_sender: mpsc::Sender<ActorMessage>,
    ping_tasks: JoinSet<(RelayUrl, bool)>,
    cancel_token: CancellationToken,
}

impl RelayActor {
    pub(super) fn new(msock: Arc<MagicSockInner>, msg_sender: mpsc::Sender<ActorMessage>) -> Self {
        let cancel_token = CancellationToken::new();
        Self {
            msock,
            active_relay: Default::default(),
            msg_sender,
            ping_tasks: Default::default(),
            cancel_token,
        }
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    pub(super) async fn run(mut self, mut receiver: mpsc::Receiver<RelayActorMessage>) {
        let mut cleanup_timer = time::interval_at(
            time::Instant::now() + RELAY_CLEAN_STALE_INTERVAL,
            RELAY_CLEAN_STALE_INTERVAL,
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
                            self.close_or_reconnect_relay(&url, "rebind-ping-fail")
                        ).await;
                    }
                }
                Some(msg) = receiver.recv() => {
                    with_cancel(self.cancel_token.child_token(), self.handle_msg(msg)).await;
                }
                _ = cleanup_timer.tick() => {
                    trace!("tick: cleanup");
                    with_cancel(self.cancel_token.child_token(), self.clean_stale_relay()).await;
                }
                else => {
                    trace!("shutting down relay recv loop");
                    break;
                }
            }
        }

        // try shutdown
        self.close_all_relay("conn-close").await;
    }

    async fn handle_msg(&mut self, msg: RelayActorMessage) {
        match msg {
            RelayActorMessage::Send {
                url,
                contents,
                peer,
            } => {
                self.send_relay(&url, contents, peer).await;
            }
            RelayActorMessage::SetHome { url } => {
                self.note_preferred(&url).await;
                self.connect_relay(&url, None).await;
            }
            RelayActorMessage::MaybeCloseRelaysOnRebind(ifs) => {
                self.maybe_close_relays_on_rebind(&ifs).await;
            }
        }
    }

    async fn note_preferred(&self, my_url: &RelayUrl) {
        futures::future::join_all(self.active_relay.iter().map(|(url, (s, _))| async move {
            let is_preferred = url == my_url;
            s.send(ActiveRelayMessage::NotePreferred(is_preferred))
                .await
                .ok()
        }))
        .await;
    }

    async fn send_relay(&mut self, url: &RelayUrl, contents: RelayContents, peer: PublicKey) {
        trace!(%url, peer = %peer.fmt_short(),len = contents.iter().map(|c| c.len()).sum::<usize>(),  "sending over relay");
        // Relay Send
        let relay_client = self.connect_relay(url, Some(&peer)).await;
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
            match relay_client.send(peer, packet).await {
                Ok(_) => {
                    inc_by!(MagicsockMetrics, send_relay, total_bytes);
                }
                Err(err) => {
                    warn!(%url, "send: failed {:?}", err);
                    inc!(MagicsockMetrics, send_relay_error);
                }
            }
        }

        // Wake up the send waker if one is waiting for space in the channel
        let mut wakers = self.msock.network_send_wakers.lock();
        if let Some(waker) = wakers.take() {
            waker.wake();
        }
    }

    /// Returns `true`if the message was sent successfully.
    async fn send_to_active(&mut self, url: &RelayUrl, msg: ActiveRelayMessage) -> bool {
        let res = self.active_relay.get(url);
        match res {
            Some((s, _)) => match s.send(msg).await {
                Ok(_) => true,
                Err(mpsc::error::SendError(_)) => {
                    self.close_relay(url, "sender-closed").await;
                    false
                }
            },
            None => false,
        }
    }

    /// Connect to the given relay node.
    async fn connect_relay(
        &mut self,
        url: &RelayUrl,
        peer: Option<&PublicKey>,
    ) -> relay::http::Client {
        debug!("connect relay {} for peer {:?}", url, peer);
        // See if we have a connection open to that relay node ID first. If so, might as
        // well use it. (It's a little arbitrary whether we use this one vs. the reverse route
        // below when we have both.)

        {
            let (os, or) = oneshot::channel();
            if self
                .send_to_active(url, ActiveRelayMessage::GetClient(os))
                .await
            {
                if let Ok(client) = or.await {
                    return client;
                }
            }
        }

        // If we don't have an open connection to the peer's home relay
        // node, see if we have an open connection to a relay node
        // where we'd heard from that peer already. For instance,
        // perhaps peer's home is Frankfurt, but they dialed our home relay
        // node in SF to reach us, so we can reply to them using our
        // SF connection rather than dialing Frankfurt.
        if let Some(peer) = peer {
            for url in self
                .active_relay
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .into_iter()
            {
                let (os, or) = oneshot::channel();
                if self
                    .send_to_active(&url, ActiveRelayMessage::GetPeerRoute(*peer, os))
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
        info!("adding connection to relay: {url} for {why}");

        let my_relay = self.msock.my_relay();
        let ipv6_reported = self.msock.ipv6_reported.clone();
        let url = url.clone();
        let url1 = url.clone();

        // building a client dials the relay
        let builder = relay::http::ClientBuilder::new(url1.clone())
            .address_family_selector(move || {
                let ipv6_reported = ipv6_reported.clone();
                Box::pin(async move { ipv6_reported.load(Ordering::Relaxed) })
            })
            .can_ack_pings(true)
            .is_preferred(my_relay.as_ref() == Some(&url1));

        #[cfg(any(test, feature = "test-utils"))]
        let builder = builder.insecure_skip_cert_verify(self.msock.insecure_skip_relay_cert_verify);

        let (dc, dc_receiver) =
            builder.build(self.msock.secret_key.clone(), self.msock.dns_resolver.clone());

        let (s, r) = mpsc::channel(64);

        let c = dc.clone();
        let msg_sender = self.msg_sender.clone();
        let url1 = url.clone();
        let handle = tokio::task::spawn(
            async move {
                let ad = ActiveRelay::new(url1, c, dc_receiver, msg_sender);

                if let Err(err) = ad.run(r).await {
                    warn!("connection error: {:?}", err);
                }
            }
            .instrument(info_span!("active-relay", %url)),
        );

        // Insert, to make sure we do not attempt to double connect.
        self.active_relay.insert(url.clone(), (s, handle));

        inc!(MagicsockMetrics, num_relay_conns_added);

        self.log_active_relay();

        dc
    }

    /// Closes the relay connections not originating from a local IP address.
    ///
    /// Called in response to a rebind, any relay connection originating from an address
    /// that's not known to be currently a local IP address should be closed.  All the other
    /// relay connections are pinged.
    async fn maybe_close_relays_on_rebind(&mut self, okay_local_ips: &[IpAddr]) {
        let mut tasks = Vec::new();
        for url in self
            .active_relay
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
        {
            let (os, or) = oneshot::channel();
            let la = if self
                .send_to_active(&url, ActiveRelayMessage::GetLocalAddr(os))
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
            let ping_sent = self
                .send_to_active(&url, ActiveRelayMessage::Ping(os))
                .await;

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
            self.close_or_reconnect_relay(&url, why).await;
        }

        self.log_active_relay();
    }

    /// Closes the relay connection to the provided `url` and starts reconnecting it if it's
    /// our current home relay.
    async fn close_or_reconnect_relay(&mut self, url: &RelayUrl, why: &'static str) {
        self.close_relay(url, why).await;
        if self.msock.my_relay().as_ref() == Some(url) {
            self.connect_relay(url, None).await;
        }
    }

    async fn clean_stale_relay(&mut self) {
        trace!("checking {} relays for staleness", self.active_relay.len());
        let now = Instant::now();

        let mut to_close = Vec::new();
        for (i, (s, _)) in &self.active_relay {
            if Some(i) == self.msock.my_relay().as_ref() {
                continue;
            }
            let (os, or) = oneshot::channel();
            match s.send(ActiveRelayMessage::GetLastWrite(os)).await {
                Ok(_) => match or.await {
                    Ok(last_write) => {
                        if last_write.duration_since(now) > RELAY_INACTIVE_CLEANUP_TIME {
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
            "closing {} of {} relays",
            to_close.len(),
            self.active_relay.len()
        );
        for i in to_close {
            self.close_relay(&i, "idle").await;
        }
        if dirty {
            self.log_active_relay();
        }
    }

    async fn close_all_relay(&mut self, why: &'static str) {
        if self.active_relay.is_empty() {
            return;
        }
        // Need to collect to avoid double borrow
        let urls: Vec<_> = self.active_relay.keys().cloned().collect();
        for url in urls {
            self.close_relay(&url, why).await;
        }
        self.log_active_relay();
    }

    async fn close_relay(&mut self, url: &RelayUrl, why: &'static str) {
        if let Some((s, t)) = self.active_relay.remove(url) {
            debug!(%url, "closing connection: {}", why);

            s.send(ActiveRelayMessage::Shutdown).await.ok();
            t.abort(); // ensure the task is shutdown

            inc!(MagicsockMetrics, num_relay_conns_removed);
        }
    }

    fn log_active_relay(&self) {
        debug!("{} active relay conns{}", self.active_relay.len(), {
            let mut s = String::new();
            if !self.active_relay.is_empty() {
                s += ":";
                for node in self.active_relay_sorted() {
                    s += &format!(" relay-{}", node,);
                }
            }
            s
        });
    }

    fn active_relay_sorted(&self) -> impl Iterator<Item = RelayUrl> {
        let mut ids: Vec<_> = self.active_relay.keys().cloned().collect();
        ids.sort();

        ids.into_iter()
    }
}

#[derive(derive_more::Debug)]
pub(super) struct RelayReadResult {
    pub(super) url: RelayUrl,
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
