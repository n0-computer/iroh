//! Example for using an iroh hook to collect information about remote endpoints.
//!
//! This implements a [`RemoteMap`] which collects information about all connections and paths from an iroh endpoint.
//! The remote map can be cloned and inspected from other tasks at any time. It contains both data about all
//! currently active connections, and an aggregate status for each remote that remains available even after
//! all connections to the endpoint have been closed.

use std::time::{Duration, SystemTime};

use iroh::{Endpoint, EndpointAddr, endpoint::presets};
use n0_error::{Result, StackResultExt, StdResultExt, ensure_any};
use n0_future::IterExt;
use tracing::{Instrument, info, info_span};

use crate::remote_map::RemoteMap;

const ALPN: &[u8] = b"iroh/test";

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Create the remote map and hook.
    let (hook, remote_map) = RemoteMap::new();

    // Bind our endpoint and install the remote map hook.
    let server = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .hooks(hook)
        .bind()
        .instrument(info_span!("server"))
        .await?;
    // Wait for our endpoint to be fully online.
    server.online().await;
    let server_addr = server.addr();

    // Spawn a task that creates `count` client endpoints that each connect to our server.
    let count = 3;
    let client_task = tokio::spawn(run_clients(server_addr, count));

    // Spawn a task that prints info from the remote map while some connections are active.
    // You can use this info to make decisions about remotes.
    let _inspect_task = tokio::task::spawn({
        let remote_map = remote_map.clone();
        async move {
            // Wait a bit.
            tokio::time::sleep(Duration::from_millis(500)).await;
            println!("== while connections are active == ");
            log_active(&remote_map);
            log_aggregate(&remote_map);
            println!();
        }
    });

    // Let the server accept `count` connections in parallel.
    // The server keeps all connections open for at least 500 milliseconds.
    std::iter::repeat_with(async || {
        let conn = server
            .accept()
            .await
            .context("server endpoint closed")?
            .await?;
        info!("accepted");
        let mut s = conn.open_uni().await.anyerr()?;
        // wait a bit.
        tokio::time::sleep(Duration::from_millis(500)).await;
        s.write_all(b"hi").await.anyerr()?;
        s.finish().anyerr()?;
        conn.closed().await;
        info!("closed");
        n0_error::Ok(())
    })
    .take(count)
    .enumerate()
    .map(|(i, fut)| fut.instrument(info_span!("server-conn", %i)))
    .try_join_all()
    .await?;

    // Print the remote map again.
    println!("== all connections closed ==");
    log_active(&remote_map);
    log_aggregate(&remote_map);

    server.close().await;
    client_task.await.std_context("client")?.context("client")?;

    Ok(())
}

/// Uses the current connection info to print info about a remote.
///
/// Uses the info about *currently active* connections, which return `None` if no connections are active.
fn log_active(remote_map: &RemoteMap) {
    println!("current remote state:");
    for (id, info) in remote_map.read().iter() {
        println!(
            "[{}] is_active {}, connections {}, ip_path {:?}, relay_path {:?}, current_min_rtt {:?}",
            id.fmt_short(),
            info.is_active(),
            info.active_connections(),
            info.has_ip_path(),
            info.has_relay_path(),
            info.current_min_rtt(),
        );
    }
}

/// Uses the aggregated info to print info about a remote.
///
/// The aggregated info is updated for all connection and path changes, and stays at the latest values
/// even if all connections are closed.
fn log_aggregate(remote_map: &RemoteMap) {
    println!("aggregate remote state:");
    for (id, info) in remote_map.read().iter() {
        let aggregate = info.aggregate();
        println!(
            "[{}] min_rtt {:?}, max_rtt {:?}, ip_path {:?}, relay_path {}, last_update {:?} ago",
            id.fmt_short(),
            aggregate.rtt_min,
            aggregate.rtt_max,
            aggregate.ip_path,
            aggregate.relay_path,
            SystemTime::now()
                .duration_since(aggregate.last_update)
                .unwrap_or_default()
        );
    }
}

async fn run_clients(server_addr: EndpointAddr, count: usize) -> Result {
    std::iter::repeat_with(async || {
        let client = Endpoint::builder(presets::N0)
            .bind()
            .instrument(info_span!("client"))
            .await?;
        let conn = client.connect(server_addr.clone(), ALPN).await?;
        info!("connected");
        let mut s = conn.accept_uni().await.anyerr()?;
        let data = s.read_to_end(2).await.anyerr()?;
        ensure_any!(data == b"hi", "unexpected data");
        conn.close(23u32.into(), b"bye");
        info!("closed");
        client.close().await;
        n0_error::Ok(())
    })
    .take(count)
    .enumerate()
    .map(|(i, fut)| fut.instrument(info_span!("client", %i)))
    .try_join_all()
    .await?;
    Ok(())
}

mod remote_map {
    //! Implementation of a remote map and hook to track information about all remote endpoints to which an iroh endpoint
    //! has connections with.

    use std::{
        collections::HashMap,
        sync::{Arc, RwLock, RwLockReadGuard},
        time::{Duration, SystemTime},
    };

    use iroh::{
        EndpointId, TransportAddr,
        endpoint::{
            AfterHandshakeOutcome, Connection, EndpointHooks, PathEvent, WeakConnectionHandle,
        },
    };
    use n0_future::{StreamExt, task::AbortOnDropHandle};
    use tokio::{sync::mpsc, task::JoinSet};
    use tracing::{Instrument, debug, info, info_span};

    /// Information about a remote info.
    #[derive(Debug, Default)]
    pub struct RemoteInfo {
        aggregate: Aggregate,
        connections: HashMap<u64, WeakConnectionHandle>,
    }

    /// Aggregate information about a remote info.
    #[derive(Debug)]
    pub struct Aggregate {
        /// Minimal RTT observed over all paths to this remote.
        pub rtt_min: Duration,
        /// Maximal RTT observed over all paths to this remote.
        pub rtt_max: Duration,
        /// Whether we ever had an IP path to this remote.
        pub ip_path: bool,
        /// Whether we ever had a relay path to this remote.
        pub relay_path: bool,
        /// Time this aggregate was last updated.
        pub last_update: SystemTime,
    }

    impl Default for Aggregate {
        fn default() -> Self {
            Self {
                rtt_min: Duration::MAX,
                rtt_max: Duration::ZERO,
                ip_path: false,
                relay_path: false,
                last_update: SystemTime::UNIX_EPOCH,
            }
        }
    }

    impl Aggregate {
        fn update(&mut self, addr: TransportAddr, stats: iroh::endpoint::PathStats) {
            self.last_update = SystemTime::now();
            self.ip_path |= addr.is_ip();
            self.relay_path |= addr.is_relay();
            debug!("path update {addr} {stats:?}");
            self.rtt_min = self.rtt_min.min(stats.rtt);
            self.rtt_max = self.rtt_max.max(stats.rtt);
        }
    }

    impl RemoteInfo {
        /// Returns an aggregate of stats for this remote.
        ///
        /// This includes info from closed connections.
        pub fn aggregate(&self) -> &Aggregate {
            &self.aggregate
        }

        /// Returns the minimal RTT of all currently active paths.
        ///
        /// Returns `None` if there are no active connections.
        pub fn current_min_rtt(&self) -> Option<Duration> {
            self.upgraded()
                .filter_map(|c| c.paths().iter().map(|p| p.rtt()).min())
                .min()
        }

        /// Returns whether any active connection to the remote has an active IP path.
        pub fn has_ip_path(&self) -> bool {
            self.upgraded().any(|c| c.paths().iter().any(|p| p.is_ip()))
        }

        /// Returns whether any active connection to the remote has an active relay path.
        pub fn has_relay_path(&self) -> bool {
            self.upgraded()
                .any(|c| c.paths().iter().any(|p| p.is_relay()))
        }

        /// Returns `true` if there are active connections to this remote.
        pub fn is_active(&self) -> bool {
            self.active_connections() > 0
        }

        /// Returns the number of active connections to this remote.
        pub fn active_connections(&self) -> usize {
            self.upgraded().count()
        }

        /// Returns an iterator over all active handles upgraded to a [`Connection`].
        fn upgraded(&self) -> impl Iterator<Item = Connection> {
            self.connections
                .values()
                .filter_map(WeakConnectionHandle::upgrade)
        }
    }

    type RemoteMapInner = Arc<RwLock<HashMap<EndpointId, RemoteInfo>>>;

    /// Contains information about remote nodes our endpoint has or had connections with.
    #[derive(Clone, Debug)]
    pub struct RemoteMap {
        map: RemoteMapInner,
        _task: Arc<AbortOnDropHandle<()>>,
    }

    /// Hook to collect information about remote endpoints from an endpoint.
    #[derive(Debug)]
    pub struct RemoteMapHook {
        tx: mpsc::Sender<TrackedConnection>,
    }

    /// Pairing of a connection's remote endpoint id, captured at handshake time, with a
    /// weak handle to the connection. The `remote_id` is captured eagerly because
    /// [`WeakConnectionHandle`] only exposes [`upgrade`] and [`closed`].
    ///
    /// [`upgrade`]: WeakConnectionHandle::upgrade
    /// [`closed`]: WeakConnectionHandle::closed
    #[derive(Debug, Clone)]
    pub struct TrackedConnection {
        pub remote_id: EndpointId,
        pub handle: WeakConnectionHandle,
    }

    impl EndpointHooks for RemoteMapHook {
        async fn after_handshake(&self, conn: &Connection) -> AfterHandshakeOutcome {
            info!(remote=%conn.remote_id().fmt_short(), "after_handshake");
            // We track the connection via a weak handle so this map does not keep the
            // connection alive past the application's last reference to it.
            let tracked = TrackedConnection {
                remote_id: conn.remote_id(),
                handle: conn.weak_handle(),
            };
            self.tx.send(tracked).await.ok();
            AfterHandshakeOutcome::Accept
        }
    }

    impl RemoteMap {
        /// Creates a new [`RemoteMapHook`] and [`RemoteMap`].
        pub fn new() -> (RemoteMapHook, Self) {
            Self::with_max_retention(Duration::from_secs(60 * 5))
        }

        /// Creates a new [`RemoteMapHook`] and [`RemoteMap`] and configure the retention time.
        ///
        /// `retention_time` is the time entries for remote endpoints remain in the map after the last connection has closed.
        pub fn with_max_retention(retention_time: Duration) -> (RemoteMapHook, Self) {
            let (tx, rx) = mpsc::channel(8);
            let map = RemoteMapInner::default();
            let task = tokio::spawn(
                Self::run(rx, map.clone(), retention_time)
                    .instrument(info_span!("remote-map-task")),
            );
            let map = Self {
                map,
                _task: Arc::new(AbortOnDropHandle::new(task)),
            };
            let hook = RemoteMapHook { tx };
            (hook, map)
        }

        /// Read the current state of the remote map.
        ///
        /// Returns a [`RwLockReadGuard`] with the actual remote map. Don't hold over await points!
        pub fn read(&self) -> RwLockReadGuard<'_, HashMap<EndpointId, RemoteInfo>> {
            self.map.read().expect("poisoned")
        }

        async fn run(
            mut rx: mpsc::Receiver<TrackedConnection>,
            map: RemoteMapInner,
            retention_time: Duration,
        ) {
            let mut tasks = JoinSet::new();
            let mut conn_id = 0;

            // Spawn a task to clear expired entries.
            let expiry_task = tasks.spawn(Self::clear_expired(retention_time, map.clone()));

            // Main loop
            loop {
                tokio::select! {
                    Some(conn) = rx.recv() => {
                        conn_id += 1;
                        Self::on_connection(&mut tasks, map.clone(), conn_id, conn);
                    }
                    Some(res) = tasks.join_next(), if !tasks.is_empty() => {
                        res.expect("conn close task panicked");
                    }
                    else => break,
                }
            }

            // Abort expiry task and join remaining tasks.
            expiry_task.abort();
            while let Some(res) = tasks.join_next().await {
                if let Err(err) = &res
                    && !err.is_cancelled()
                {
                    res.expect("conn close task panicked");
                }
            }
        }

        fn on_connection(
            tasks: &mut JoinSet<()>,
            map: RemoteMapInner,
            conn_id: u64,
            conn: TrackedConnection,
        ) {
            // Store conn info for full introspection possibility.
            {
                let mut inner = map.write().expect("poisoned");
                inner
                    .entry(conn.remote_id)
                    .or_default()
                    .connections
                    .insert(conn_id, conn.handle.clone());
            }

            // Track path changes to update stats aggregate.
            if let Some(mut path_events) = conn.handle.upgrade().map(|conn| conn.path_events()) {
                tasks.spawn(
                    async move {
                        while let Some(event) = path_events.next().await {
                            let mut inner = map.write().expect("poisoned");
                            let info = inner.entry(conn.remote_id).or_default();
                            match event {
                                PathEvent::Closed {
                                    remote_addr,
                                    last_stats,
                                    ..
                                } => {
                                    info.aggregate.update(remote_addr, *last_stats);
                                }
                                _ => {
                                    if let Some(conn) = conn.handle.upgrade() {
                                        for path in conn.paths().iter() {
                                            info.aggregate
                                                .update(path.remote_addr().clone(), path.stats());
                                        }
                                    }
                                }
                            }
                        }
                        let mut inner = map.write().expect("poisoned");
                        let info = inner.entry(conn.remote_id).or_default();
                        info.connections.remove(&conn_id);
                        info.aggregate.last_update = SystemTime::now();
                    }
                    .instrument(tracing::Span::current()),
                );
            }
        }

        async fn clear_expired(
            retention_time: Duration,
            map: Arc<RwLock<HashMap<iroh::PublicKey, RemoteInfo>>>,
        ) {
            let mut interval = tokio::time::interval(retention_time);
            loop {
                interval.tick().await;
                let now = SystemTime::now();
                let mut inner = map.write().expect("poisoned");
                inner.retain(|_remote, info| {
                    info.is_active()
                        || now
                            .duration_since(info.aggregate().last_update)
                            .map(|age| age < retention_time)
                            .unwrap_or(true)
                });
            }
        }
    }
}
