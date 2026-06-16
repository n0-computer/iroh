//! A small connection pool for TCP and DNS-over-TLS queries.
//!
//! UDP is connectionless and DNS-over-HTTPS pools inside `reqwest`, so only
//! plain-TCP and DoT connections are pooled here. Reusing a connection
//! amortizes the TCP (and, for DoT, TLS) handshake across repeated queries to
//! the same nameserver.
//!
//! A connection is checked out for exclusive use (one in-flight query at a
//! time, no pipelining) and returned on success. Two things keep idle
//! connections from accumulating:
//!
//! - On checkout, connections older than [`IDLE_TIMEOUT`] are discarded rather
//!   than handed out, and at most [`MAX_IDLE_PER_KEY`] are kept per nameserver.
//! - A background task ([`reap_loop`]) sweeps every [`REAP_INTERVAL`] and drops
//!   idle connections that no checkout has touched, so a nameserver queried
//!   once and never again does not pin a socket open forever.
//!
//! The task is spawned lazily on the first check-in (always inside an async
//! query, hence inside a runtime) and aborted when the pool is dropped.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock},
};

use n0_future::{
    task::{AbortOnDropHandle, spawn},
    time::{self, Duration, Instant},
};
use tokio::net::TcpStream;

/// Idle connections older than this are discarded instead of reused.
const IDLE_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum idle connections kept per pool key.
const MAX_IDLE_PER_KEY: usize = 2;
/// How often the background task sweeps idle connections.
const REAP_INTERVAL: Duration = IDLE_TIMEOUT;

/// An established DNS-over-TLS stream.
#[cfg(with_crypto_provider)]
pub(super) type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;

/// Pool key for a DoT connection: the address plus the TLS server name, so a
/// connection is never reused for a different SNI name.
#[cfg(with_crypto_provider)]
pub(super) type TlsKey = (SocketAddr, Option<String>);

/// A pooled idle connection and when it was last returned to the pool.
struct Idle<S> {
    stream: S,
    last_used: Instant,
}

impl<S> Idle<S> {
    fn new(stream: S) -> Self {
        Self {
            stream,
            last_used: Instant::now(),
        }
    }

    fn is_stale(&self) -> bool {
        self.last_used.elapsed() >= IDLE_TIMEOUT
    }
}

/// The pooled connections, shared between the [`ConnPool`] and its reaper task.
#[derive(Default)]
struct Inner {
    tcp: Mutex<HashMap<SocketAddr, Vec<Idle<TcpStream>>>>,
    #[cfg(with_crypto_provider)]
    tls: Mutex<HashMap<TlsKey, Vec<Idle<TlsStream>>>>,
}

impl Inner {
    /// Drops every idle connection past [`IDLE_TIMEOUT`] and any key left empty.
    fn reap(&self) {
        reap_map(&self.tcp);
        #[cfg(with_crypto_provider)]
        reap_map(&self.tls);
    }
}

/// A pool of idle TCP and DoT connections, keyed by nameserver.
pub(super) struct ConnPool {
    inner: Arc<Inner>,
    /// The idle-connection reaper, spawned on first check-in and aborted on drop.
    reaper: OnceLock<AbortOnDropHandle<()>>,
}

impl std::fmt::Debug for ConnPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnPool").finish_non_exhaustive()
    }
}

impl ConnPool {
    pub(super) fn new() -> Self {
        Self {
            inner: Arc::new(Inner::default()),
            reaper: OnceLock::new(),
        }
    }

    /// Takes an idle TCP connection to `addr`, if a fresh one is pooled.
    pub(super) fn checkout_tcp(&self, addr: SocketAddr) -> Option<TcpStream> {
        take_fresh(self.inner.tcp.lock().expect("poisoned").get_mut(&addr)?)
    }

    /// Returns a healthy TCP connection to the pool for reuse.
    pub(super) fn checkin_tcp(&self, addr: SocketAddr, stream: TcpStream) {
        push_capped(
            self.inner
                .tcp
                .lock()
                .expect("poisoned")
                .entry(addr)
                .or_default(),
            stream,
        );
        self.ensure_reaper();
    }

    /// Takes an idle DoT connection for `key`, if a fresh one is pooled.
    #[cfg(with_crypto_provider)]
    pub(super) fn checkout_tls(&self, key: &TlsKey) -> Option<TlsStream> {
        take_fresh(self.inner.tls.lock().expect("poisoned").get_mut(key)?)
    }

    /// Returns a healthy DoT connection to the pool for reuse.
    #[cfg(with_crypto_provider)]
    pub(super) fn checkin_tls(&self, key: TlsKey, stream: TlsStream) {
        push_capped(
            self.inner
                .tls
                .lock()
                .expect("poisoned")
                .entry(key)
                .or_default(),
            stream,
        );
        self.ensure_reaper();
    }

    /// Spawns the reaper task on first use. Check-in always runs inside an async
    /// query, so a runtime is guaranteed to be present.
    fn ensure_reaper(&self) {
        self.reaper.get_or_init(|| {
            let inner = Arc::clone(&self.inner);
            AbortOnDropHandle::new(spawn(reap_loop(inner)))
        });
    }
}

/// Periodically drops idle connections until the pool is dropped (which aborts
/// this task via its [`AbortOnDropHandle`]).
async fn reap_loop(inner: Arc<Inner>) {
    loop {
        time::sleep(REAP_INTERVAL).await;
        inner.reap();
    }
}

/// Pops the most-recently-used connection still within [`IDLE_TIMEOUT`],
/// discarding any staler ones encountered along the way.
fn take_fresh<S>(idle: &mut Vec<Idle<S>>) -> Option<S> {
    while let Some(conn) = idle.pop() {
        if !conn.is_stale() {
            return Some(conn.stream);
        }
    }
    None
}

/// Returns a connection to the pool, dropping the oldest if the key is at cap.
fn push_capped<S>(idle: &mut Vec<Idle<S>>, stream: S) {
    idle.push(Idle::new(stream));
    if idle.len() > MAX_IDLE_PER_KEY {
        idle.remove(0);
    }
}

/// Drops every stale connection in `map`, then removes any key left empty.
fn reap_map<K, S>(map: &Mutex<HashMap<K, Vec<Idle<S>>>>) {
    map.lock().expect("poisoned").retain(|_, idle| {
        idle.retain(|conn| !conn.is_stale());
        !idle.is_empty()
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TCP connection plus its accepted server end, kept alive so the client
    /// side is not reset.
    async fn loopback_pair() -> (TcpStream, SocketAddr, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (client.unwrap(), addr, accepted.unwrap().0)
    }

    fn tcp_idle_count(pool: &ConnPool) -> usize {
        pool.inner.tcp.lock().unwrap().values().map(Vec::len).sum()
    }

    #[tokio::test]
    async fn take_fresh_returns_mru_and_drops_stale() {
        let mut idle = vec![
            Idle {
                stream: 1u32,
                last_used: Instant::now() - IDLE_TIMEOUT * 2,
            },
            Idle::new(2u32),
        ];
        // The most-recently-used (back) fresh connection comes out first.
        assert_eq!(take_fresh(&mut idle), Some(2));
        // Only the stale one is left, and it is discarded rather than returned.
        assert_eq!(take_fresh(&mut idle), None);
        assert!(idle.is_empty());
    }

    #[tokio::test]
    async fn push_capped_drops_oldest_over_cap() {
        let mut idle = Vec::new();
        for i in 0..(MAX_IDLE_PER_KEY as u32 + 1) {
            push_capped(&mut idle, i);
        }
        assert_eq!(idle.len(), MAX_IDLE_PER_KEY);
        // The very first (oldest) connection was evicted.
        assert_eq!(idle.first().map(|c| c.stream), Some(1));
    }

    #[tokio::test]
    async fn reap_map_drops_stale_then_empty_keys() {
        let map: Mutex<HashMap<u8, Vec<Idle<u32>>>> = Mutex::new(HashMap::new());
        {
            let mut m = map.lock().unwrap();
            m.insert(
                1,
                vec![Idle {
                    stream: 10,
                    last_used: Instant::now() - IDLE_TIMEOUT * 2,
                }],
            );
            m.insert(2, vec![Idle::new(20)]);
        }
        reap_map(&map);
        let m = map.lock().unwrap();
        // Key 1 had only a stale connection, so it is gone entirely.
        assert!(!m.contains_key(&1));
        // Key 2's fresh connection survives.
        assert_eq!(m.get(&2).map(Vec::len), Some(1));
    }

    #[tokio::test]
    async fn tcp_checkout_checkin_roundtrip() {
        let (client, addr, _server) = loopback_pair().await;

        let pool = ConnPool::new();
        assert!(pool.checkout_tcp(addr).is_none());
        pool.checkin_tcp(addr, client);
        assert!(pool.checkout_tcp(addr).is_some());
        assert!(pool.checkout_tcp(addr).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn reaper_evicts_untouched_idle_connections() {
        let (client, addr, _server) = loopback_pair().await;

        let pool = ConnPool::new();
        pool.checkin_tcp(addr, client);
        assert_eq!(tcp_idle_count(&pool), 1);

        // Advance past the idle timeout so the reaper sweeps the connection even
        // though nothing checks it out. (`start_paused` auto-advances the clock.)
        time::sleep(IDLE_TIMEOUT + REAP_INTERVAL).await;
        tokio::task::yield_now().await;

        assert_eq!(tcp_idle_count(&pool), 0);
    }
}
