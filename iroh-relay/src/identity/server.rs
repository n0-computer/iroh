use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use iroh_identity::Registry;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use super::*;

/// Opt-in identity relay service with an explicit credential and peer policy.
///
/// This policy is independent of the legacy relay's Ed25519 access control.
/// The audience must equal the canonical relay URL used by clients.
#[derive(Clone, Debug)]
pub struct Service(Arc<Inner>);

#[derive(derive_more::Debug)]
struct Inner {
    audience: RelayUrl,
    registry: Arc<Registry>,
    /// Registered sessions keyed by identity. The session number lets a
    /// replaced session's cleanup leave its successor untouched.
    clients: Mutex<HashMap<PeerId, (u64, mpsc::Sender<Bytes>)>>,
    sessions: AtomicU64,
    capacity: Arc<Semaphore>,
    cancel: CancellationToken,
    sources: Mutex<HashMap<Option<IpAddr>, Source>>,
    source_prune: Mutex<Option<tokio::time::Instant>>,
}

const SOURCE_WINDOW: Duration = Duration::from_secs(60);
const MAX_SOURCES: usize = 4096;
const SOURCE_REQUESTS: usize = 120;
const SOURCE_CONCURRENT: usize = 16;
const SOURCE_BYTES: usize = 64 * 1024 * 1024;
const SOURCE_PACKETS: usize = 32768;

#[derive(Debug)]
struct Source {
    window: tokio::time::Instant,
    requests: usize,
    active: usize,
    traffic_window: tokio::time::Instant,
    bytes: usize,
    packets: usize,
}

/// Admission survives upgrades and is released on cancellation or disconnect.
pub(crate) struct SourceLease(Service, Option<IpAddr>);

impl SourceLease {
    fn traffic(&self, bytes: usize) -> bool {
        let mut sources = self.0.0.sources.lock().expect("sources poisoned");
        let source = sources.get_mut(&self.1).expect("source lease exists");
        let now = tokio::time::Instant::now();
        if now.duration_since(source.traffic_window) >= Duration::from_secs(1) {
            source.traffic_window = now;
            source.bytes = 0;
            source.packets = 0;
        }
        source.bytes = source.bytes.saturating_add(bytes);
        source.packets = source.packets.saturating_add(1);
        source.bytes <= SOURCE_BYTES && source.packets <= SOURCE_PACKETS
    }
}

impl Drop for SourceLease {
    fn drop(&mut self) {
        self.0
            .0
            .sources
            .lock()
            .expect("sources poisoned")
            .get_mut(&self.1)
            .expect("source lease exists")
            .active -= 1;
    }
}

struct Registration {
    service: Service,
    peer: PeerId,
    session: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut clients = self
            .service
            .0
            .clients
            .lock()
            .expect("relay clients poisoned");
        if clients
            .get(&self.peer)
            .is_some_and(|(session, _)| *session == self.session)
        {
            clients.remove(&self.peer);
        }
    }
}

impl Service {
    /// Enable typed registration with a bounded number of concurrent sessions.
    ///
    /// Identity relay upgrades and sessions share limits per canonical source IP:
    /// 120 admissions per minute, 16 concurrent operations, and relay ingress of
    /// 64 MiB / 32,768 frames per second. Traffic excess disconnects the session;
    /// HTTP admission excess returns 429. Windows are fixed, not sliding.
    /// Source state is bounded to 4096 entries; inactive entries are reclaimable
    /// after a minute.
    ///
    /// A new registration for an already registered identity replaces the
    /// previous session, so a client whose connection died silently can
    /// reconnect. Idle sessions are pinged and dropped when they stop answering.
    pub fn new(audience: RelayUrl, registry: Arc<Registry>, max_sessions: usize) -> Self {
        Self(Arc::new(Inner {
            audience,
            registry,
            clients: Mutex::new(HashMap::new()),
            sessions: AtomicU64::new(0),
            capacity: Arc::new(Semaphore::new(max_sessions)),
            cancel: CancellationToken::new(),
            sources: Mutex::new(HashMap::new()),
            source_prune: Mutex::new(None),
        }))
    }

    /// Disconnect current clients and refuse subsequent sessions.
    pub fn shutdown(&self) {
        self.0.cancel.cancel();
    }

    /// Reserve one of the bounded sessions before completing an upgrade, so a
    /// relay at capacity answers with an HTTP error instead of a dead socket.
    pub(crate) fn reserve_session(&self) -> Option<OwnedSemaphorePermit> {
        if self.0.cancel.is_cancelled() {
            return None;
        }
        self.0.capacity.clone().try_acquire_owned().ok()
    }

    pub(crate) fn admit(&self, source: Option<IpAddr>) -> Option<SourceLease> {
        if self.0.cancel.is_cancelled() {
            return None;
        }
        let source = source.map(|ip| ip.to_canonical());
        let now = tokio::time::Instant::now();
        let mut sources = self.0.sources.lock().expect("sources poisoned");
        if !sources.contains_key(&source) && sources.len() >= MAX_SOURCES {
            let mut prune = self.0.source_prune.lock().expect("source prune poisoned");
            if prune.is_some_and(|deadline| now < deadline) {
                return None;
            }
            *prune = Some(now + Duration::from_secs(1));
            sources.retain(|_, s| s.active > 0 || now.duration_since(s.window) < SOURCE_WINDOW);
            if sources.len() >= MAX_SOURCES {
                return None;
            }
        }
        let state = sources.entry(source).or_insert(Source {
            window: now,
            requests: 0,
            active: 0,
            traffic_window: now,
            bytes: 0,
            packets: 0,
        });
        if now.duration_since(state.window) >= SOURCE_WINDOW {
            state.window = now;
            state.requests = 0;
        }
        if state.requests >= SOURCE_REQUESTS || state.active >= SOURCE_CONCURRENT {
            return None;
        }
        state.requests += 1;
        state.active += 1;
        Some(SourceLease(self.clone(), source))
    }

    pub(crate) async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
        source: SourceLease,
        permit: OwnedSemaphorePermit,
    ) -> Result<(), Error> {
        self.0
            .cancel
            .run_until_cancelled(self.serve(stream, source, permit))
            .await
            .ok_or(Error::Closed)?
    }

    async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
        source: SourceLease,
        _permit: OwnedSemaphorePermit,
    ) -> Result<(), Error> {
        let mut ws = tokio_websockets::ServerBuilder::new()
            .limits(tokio_websockets::Limits::default().max_payload_len(Some(MAX_FRAME)))
            .serve(stream);
        let (registration, mut outgoing) = tokio::time::timeout(TIMEOUT, async {
            let nonce: [u8; 32] = rand::random();
            let mut challenge = vec![0];
            challenge.extend_from_slice(&nonce);
            ws.send(Message::binary(challenge)).await.map_err(error)?;
            let auth = read(&mut ws).await?;
            if auth.len() < 6 || auth[0] != 1 {
                return Err(Error::Protocol("invalid registration"));
            }
            let len = u32::from_be_bytes(auth[1..5].try_into().expect("checked length")) as usize;
            if len > 8192 || 5 + len >= auth.len() || auth.len() - 5 - len > 16384 {
                return Err(Error::Protocol("invalid registration length"));
            }
            let public = &auth[5..5 + len];
            let peer = self.0.registry.identify(public)?;
            let verified = self.0.registry.verify_proof(
                public,
                &proof(&self.0.audience, &nonce, peer),
                &auth[5 + len..],
            )?;
            if verified != peer {
                return Err(Error::IdentityMismatch);
            }
            let (tx, rx) = mpsc::channel(256);
            let session = self.0.sessions.fetch_add(1, Ordering::Relaxed);
            // A proven credential replaces any earlier session for the same
            // identity. Dropping the old sender ends that session's serve loop.
            self.0
                .clients
                .lock()
                .expect("relay clients poisoned")
                .insert(peer, (session, tx));
            let registration = Registration {
                service: self.clone(),
                peer,
                session,
            };
            ws.send(Message::binary(vec![2])).await.map_err(error)?;
            Ok((registration, rx))
        })
        .await
        .map_err(error)??;
        let (mut sink, mut stream) = n0_future::split::split(ws);
        let mut keepalive = Keepalive::new();
        loop {
            tokio::select! {
                frame = outgoing.recv() => {
                    let frame = frame.ok_or(Error::Protocol("identity registration replaced"))?;
                    tokio::time::timeout(TIMEOUT, sink.send(Message::binary(frame))).await.map_err(error)?.map_err(error)?;
                }
                message = stream.next() => {
                    let message = message.ok_or(Error::Closed)?.map_err(error)?;
                    keepalive.received();
                    if !source.traffic(message.as_payload().len()) {
                        return Err(Error::Protocol("source traffic limit exceeded"));
                    }
                    if message.is_close() { return Ok(()); }
                    if message.is_binary() {
                        let (destination, contents) = parse_datagram(message.into_payload().into())?;
                        let frame = datagram(registration.peer, &contents)?;
                        let clients = self.0.clients.lock().expect("relay clients poisoned");
                        if let Some((_, tx)) = clients.get(&destination) { let _ = tx.try_send(frame); }
                    } else if message.is_text() { return Err(Error::Protocol("unexpected text frame")); }
                }
                result = keepalive.tick() => {
                    result?;
                    tokio::time::timeout(TIMEOUT, sink.send(Message::ping(Bytes::new()))).await.map_err(error)?.map_err(error)?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Socket = WebSocketStream<tokio::io::DuplexStream>;

    #[test]
    fn source_limits_survive_reconnect_and_release_cancelled_requests() {
        let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
        let service = Service::new("https://relay.example/".parse().unwrap(), registry, 32);
        let source = Some("192.0.2.1".parse().unwrap());
        let mapped = Some("::ffff:192.0.2.1".parse().unwrap());
        let mut leases: Vec<_> = (0..SOURCE_CONCURRENT)
            .map(|_| service.admit(source).unwrap())
            .collect();
        assert!(service.admit(mapped).is_none());
        assert!(service.admit(Some("192.0.2.2".parse().unwrap())).is_some());
        assert!(leases[0].traffic(SOURCE_BYTES));
        assert!(!leases[1].traffic(1));
        leases.clear();
        let reconnected = service.admit(mapped).unwrap();
        assert!(!reconnected.traffic(1));
        drop(reconnected);
        for _ in SOURCE_CONCURRENT + 1..SOURCE_REQUESTS {
            drop(service.admit(source).unwrap());
        }
        assert!(service.admit(source).is_none());
        {
            let mut sources = service.0.sources.lock().unwrap();
            let state = sources.get_mut(&source).unwrap();
            state.window -= SOURCE_WINDOW;
            state.traffic_window -= Duration::from_secs(1);
        }
        let recovered = service.admit(source).unwrap();
        assert!(recovered.traffic(1));
        service.shutdown();
        assert!(service.admit(source).is_none());
    }

    #[test]
    fn source_table_is_bounded_and_reclaims_only_idle_entries() {
        let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
        let service = Service::new("https://relay.example/".parse().unwrap(), registry, 32);
        let active = service.admit(None).unwrap();
        for n in 1..MAX_SOURCES {
            drop(
                service
                    .admit(Some(std::net::Ipv4Addr::from(n as u32).into()))
                    .unwrap(),
            );
        }
        let next = Some("192.0.2.1".parse().unwrap());
        assert!(service.admit(next).is_none());
        for state in service.0.sources.lock().unwrap().values_mut() {
            state.window -= SOURCE_WINDOW;
        }
        *service.0.source_prune.lock().unwrap() = None;
        let recovered = service.admit(next).unwrap();
        assert_eq!(service.0.sources.lock().unwrap().len(), 2);
        assert!(active.traffic(1));
        drop(recovered);
    }

    #[test]
    fn session_capacity_is_reserved_before_the_upgrade_completes() {
        let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
        let service = Service::new("https://relay.example/".parse().unwrap(), registry, 1);
        let held = service.reserve_session().unwrap();
        assert!(service.reserve_session().is_none());
        drop(held);
        let _again = service.reserve_session().unwrap();
        service.shutdown();
        assert!(service.reserve_session().is_none());
    }

    async fn open(
        service: &Service,
    ) -> (Socket, tokio::task::JoinHandle<Result<(), Error>>, Bytes) {
        let (client, server) = tokio::io::duplex(MAX_FRAME * 2);
        let service = service.clone();
        let task = tokio::spawn(async move {
            let source = service.admit(None).unwrap();
            let permit = service.reserve_session().unwrap();
            service.accept(server, source, permit).await
        });
        let mut socket = tokio_websockets::ClientBuilder::new().take_over(client);
        let challenge = read(&mut socket).await.unwrap();
        assert_eq!(challenge.len(), 33);
        assert_eq!(challenge[0], 0);
        (socket, task, challenge)
    }

    fn auth(identity: &LocalIdentity, audience: &RelayUrl, challenge: &[u8]) -> Vec<u8> {
        let public = identity.public_key();
        let mut bytes = vec![1];
        bytes.extend_from_slice(&(public.as_ref().len() as u32).to_be_bytes());
        bytes.extend_from_slice(public.as_ref());
        bytes.extend_from_slice(
            &identity
                .sign(&proof(audience, &challenge[1..], identity.id()))
                .unwrap(),
        );
        bytes
    }

    #[tokio::test]
    async fn registration_rejects_replay_wrong_audience_and_corrupted_proof() {
        let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
        let identity = LocalIdentity::generate_ml_dsa65(&registry).unwrap();
        let audience: RelayUrl = "https://relay.example/".parse().unwrap();
        let service = Service::new(audience.clone(), registry, 1);
        let (mut socket, task, first) = open(&service).await;
        let captured = auth(&identity, &audience, &first);
        socket
            .send(Message::binary(captured.clone()))
            .await
            .unwrap();
        assert_eq!(read(&mut socket).await.unwrap().as_ref(), [2]);
        drop(socket);
        let _ = task.await.unwrap();

        for mode in 0..4 {
            let (mut socket, task, challenge) = open(&service).await;
            assert_ne!(challenge, first);
            let frame = match mode {
                0 => captured.clone(),
                1 => auth(
                    &identity,
                    &"https://other.example/".parse().unwrap(),
                    &challenge,
                ),
                2 => {
                    let mut bytes = auth(&identity, &audience, &challenge);
                    *bytes.last_mut().unwrap() ^= 1;
                    bytes
                }
                _ => vec![1, 255, 255, 255, 255, 0],
            };
            socket.send(Message::binary(frame)).await.unwrap();
            assert!(read(&mut socket).await.is_err());
            assert!(task.await.unwrap().is_err());
            assert!(service.0.clients.lock().unwrap().is_empty());
        }
        // Rejected sessions must release their capacity as well as their pin.
        let (mut socket, task, challenge) = open(&service).await;
        socket
            .send(Message::binary(auth(&identity, &audience, &challenge)))
            .await
            .unwrap();
        assert_eq!(read(&mut socket).await.unwrap().as_ref(), [2]);
        service.shutdown();
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn a_new_registration_replaces_the_stale_session_for_the_same_identity() {
        let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
        let identity = LocalIdentity::generate_ml_dsa65(&registry).unwrap();
        let sender = LocalIdentity::generate_ml_dsa65(&registry).unwrap();
        let audience: RelayUrl = "https://relay.example/".parse().unwrap();
        let service = Service::new(audience.clone(), registry, 4);
        // The first session never sends a close frame, like a peer whose
        // network vanished.
        let (mut stale, stale_task, challenge) = open(&service).await;
        stale
            .send(Message::binary(auth(&identity, &audience, &challenge)))
            .await
            .unwrap();
        assert_eq!(read(&mut stale).await.unwrap().as_ref(), [2]);

        let (mut fresh, fresh_task, challenge) = open(&service).await;
        fresh
            .send(Message::binary(auth(&identity, &audience, &challenge)))
            .await
            .unwrap();
        assert_eq!(read(&mut fresh).await.unwrap().as_ref(), [2]);
        assert!(stale_task.await.unwrap().is_err());
        assert_eq!(service.0.clients.lock().unwrap().len(), 1);

        // Traffic for the identity reaches the replacement session only.
        let (mut other, other_task, challenge) = open(&service).await;
        other
            .send(Message::binary(auth(&sender, &audience, &challenge)))
            .await
            .unwrap();
        assert_eq!(read(&mut other).await.unwrap().as_ref(), [2]);
        other
            .send(Message::binary(datagram(identity.id(), b"hello").unwrap()))
            .await
            .unwrap();
        let (from, contents) = parse_datagram(read(&mut fresh).await.unwrap()).unwrap();
        assert_eq!(from, sender.id());
        assert_eq!(contents.as_ref(), b"hello");

        fresh.close().await.unwrap();
        assert!(fresh_task.await.unwrap().is_ok());
        assert_eq!(service.0.clients.lock().unwrap().len(), 1);
        other.close().await.unwrap();
        assert!(other_task.await.unwrap().is_ok());
        assert!(service.0.clients.lock().unwrap().is_empty());
    }
}
