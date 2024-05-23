//! A connection manager to ensure a single connection between each pair of peers.

use std::{
    collections::HashMap,
    pin::Pin,
    task::{ready, Context, Poll, Waker},
};

use futures_lite::{Future, Stream};
use futures_util::FutureExt;
use tokio::{
    sync::mpsc,
    task::{AbortHandle, JoinSet},
};
use tracing::{error, warn};

use crate::{
    endpoint::{get_remote_node_id, Connection},
    Endpoint, NodeId,
};

const DUPLICATE_REASON: &[u8] = b"abort_duplicate";
const DUPLICATE_CODE: u32 = 123;

/// Whether we accepted the connection or initiated it.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ConnDirection {
    /// We accepted this connection from the other peer.
    Accept,
    /// We initiated this connection by connecting to the other peer.
    Dial,
}

/// A new connection as emitted from [`ConnManager`].
#[derive(Debug, Clone, derive_more::Deref)]
pub struct ConnInfo {
    /// The QUIC connection.
    #[deref]
    pub conn: Connection,
    /// The node id of the other peer.
    pub node_id: NodeId,
    /// Whether we accepted or initiated this connection.
    pub direction: ConnDirection,
}

/// A sender to push new connections into a [`ConnManager`].
///
/// See [`ConnManager::handle_connection_sender`] for details.
#[derive(Debug, Clone)]
pub struct HandleConnectionSender {
    tx: mpsc::Sender<Connection>,
}

impl HandleConnectionSender {
    /// Send a new connection to the [`ConnManager`].
    pub async fn send(&self, conn: Connection) -> anyhow::Result<()> {
        self.tx.send(conn).await?;
        Ok(())
    }
}

/// The error returned from [`ConnManager::poll_next`].
#[derive(thiserror::Error, Debug)]
#[error("Connection to node {} direction {:?} failed: {:?}", self.node_id, self.direction, self.reason)]
pub struct ConnectError {
    /// The node id of the peer to which the connection failed.
    pub node_id: NodeId,
    /// The direction of the connection.
    pub direction: ConnDirection,
    /// The actual error that ocurred.
    #[source]
    pub reason: anyhow::Error,
}

/// A connection manager that ensures that only a single connection between two peers prevails.
///
/// You can start to dial peers by calling [`ConnManager::dial`]. Note that the method only takes a
/// node id; if you have more addressing info, add it to the endpoint directly with
/// [`Endpoint::add_node_addr`] before calling `dial`;
///
/// The [`ConnManager`] does not accept connections from the endpoint by itself. Instead, you
/// should run an accept loop yourself, and push connections with a matching ALPN into the manager
/// with [`ConnManager::handle_connection`] or [`ConnManager::handle_connection_sender`].
///
/// The [`ConnManager`] is a [`Stream`] that yields all connections from both accepting and dialing.
///
/// Before accepting incoming connections, the [`ConnManager`] makes sure that, if we are dialing
/// the same node, only one of the connections will prevail. In this case, the accepting side
/// rejects the connection if the peer's node id sorts higher than their own node id.
///
/// To make this reliable even if the dials happen exactly at the same time, a single unidirectional
/// stream is opened, on which a single byte is sent. This additional rountrip ensures that no
/// double connections can prevail.
#[derive(Debug)]
pub struct ConnManager {
    endpoint: Endpoint,
    alpn: &'static [u8],
    active: HashMap<NodeId, ConnInfo>,
    pending: HashMap<NodeId, PendingState>,
    tasks: JoinSet<(NodeId, Result<Connection, InitError>)>,
    accept_tx: mpsc::Sender<Connection>,
    accept_rx: mpsc::Receiver<Connection>,
    waker: Option<Waker>,
}

impl ConnManager {
    /// Create a new connection manager.
    pub fn new(endpoint: Endpoint, alpn: &'static [u8]) -> Self {
        let (accept_tx, accept_rx) = mpsc::channel(128);
        Self {
            endpoint,
            alpn,
            active: Default::default(),
            accept_tx,
            accept_rx,
            tasks: JoinSet::new(),
            pending: HashMap::new(),
            waker: None,
        }
    }

    /// Start to dial a node.
    ///
    /// This is a no-op if the a connection to the node is already active or if we are currently
    /// dialing the node already.
    ///
    /// Returns `true` if this is initiates connecting to the node.
    pub fn dial(&mut self, node_id: NodeId) -> bool {
        if self.is_pending(&node_id) || self.is_connected(&node_id) {
            false
        } else {
            self.spawn(
                node_id,
                ConnDirection::Dial,
                connect_task(self.endpoint.clone(), node_id, self.alpn),
            );
            true
        }
    }

    /// Accept a connection.
    ///
    /// This does not check the connection's ALPN, so you should make sure that the ALPN matches
    /// the [`ConnManager`]'s execpected ALPN before passing the connection to the sender.
    ///
    /// If we are currently dialing the node, the connection will be dropped if the peer's node id
    /// sorty higher than our node id. Otherwise, the connection will be returned.
    pub fn handle_connection(&mut self, conn: quinn::Connection) -> anyhow::Result<()> {
        let node_id = get_remote_node_id(&conn)?;
        // We are already connected: drop the connection, keep using the existing conn.
        if self.is_connected(&node_id) {
            return Ok(());
        }

        let accept = match self.pending.get(&node_id) {
            // We are currently dialing the node, but the incoming conn "wins": accept and abort
            // our dial.
            Some(state)
                if state.direction == ConnDirection::Dial && node_id > self.endpoint.node_id() =>
            {
                state.abort_handle.abort();
                true
            }
            // We are currently processing a connection for this node: do not accept a second conn.
            Some(_state) => false,
            // The connection is new: accept.
            None => true,
        };

        if accept {
            self.spawn(node_id, ConnDirection::Accept, accept_task(conn));
        } else {
            conn.close(DUPLICATE_CODE.into(), DUPLICATE_REASON);
        }
        Ok(())
    }

    /// Get a sender to push new connections towards the [`ConnManager`]
    ///
    /// This does not check the connection's ALPN, so you should make sure that the ALPN matches
    /// the [`ConnManager`]'s execpected ALPN before passing the connection to the sender.
    ///
    /// If we are currently dialing the node, the connection will be dropped if the peer's node id
    /// sorty higher than our node id. Otherwise, the connection will be yielded from the manager
    /// stream.
    pub fn handle_connection_sender(&self) -> HandleConnectionSender {
        let tx = self.accept_tx.clone();
        HandleConnectionSender { tx }
    }

    /// Remove the connection to a node.
    ///
    /// Also aborts pending dials to the node, if existing.
    ///
    /// Returns the connection if it existed.
    pub fn remove(&mut self, node_id: &NodeId) -> Option<ConnInfo> {
        if let Some(state) = self.pending.remove(node_id) {
            state.abort_handle.abort();
        }
        self.active.remove(node_id)
    }

    /// Returns the connection to a node, if connected.
    pub fn get(&self, node_id: &NodeId) -> Option<&ConnInfo> {
        self.active.get(node_id)
    }

    /// Returns `true` if we are currently establishing a connection to the node.
    pub fn is_pending(&self, node_id: &NodeId) -> bool {
        self.pending.contains_key(node_id)
    }

    /// Returns `true` if we are connected to the node.
    pub fn is_connected(&self, node_id: &NodeId) -> bool {
        self.active.contains_key(node_id)
    }

    fn spawn(
        &mut self,
        node_id: NodeId,
        direction: ConnDirection,
        fut: impl Future<Output = Result<Connection, InitError>> + Send + 'static,
    ) {
        let abort_handle = self.tasks.spawn(fut.map(move |res| (node_id, res)));
        let pending_state = PendingState {
            direction,
            abort_handle,
        };
        self.pending.insert(node_id, pending_state);
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

impl Stream for ConnManager {
    type Item = Result<ConnInfo, ConnectError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Create new tasks for incoming connections.
        while let Poll::Ready(Some(conn)) = Pin::new(&mut self.accept_rx).poll_recv(cx) {
            if let Err(error) = self.handle_connection(conn) {
                warn!(?error, "skipping invalid connection attempt");
            }
        }

        // Poll for finished tasks,
        loop {
            let join_res = ready!(self.tasks.poll_join_next(cx));
            let (node_id, res) = match join_res {
                None => {
                    self.waker = Some(cx.waker().to_owned());
                    return Poll::Pending;
                }
                Some(Err(err)) if err.is_cancelled() => continue,
                Some(Err(err)) => {
                    // TODO: unreachable?
                    warn!("connection manager task paniced with {err:?}");
                    continue;
                }
                Some(Ok(res)) => res,
            };
            match res {
                Err(InitError::IsDuplicate) => continue,
                Err(InitError::Other(reason)) => {
                    let Some(PendingState { direction, .. }) = self.pending.remove(&node_id) else {
                        // TODO: unreachable?
                        warn!(node_id=%node_id.fmt_short(), "missing pending state, dropping connection");
                        continue;
                    };
                    let err = ConnectError {
                        node_id,
                        reason,
                        direction,
                    };
                    break Poll::Ready(Some(Err(err)));
                }
                Ok(conn) => {
                    let Some(PendingState { direction, .. }) = self.pending.remove(&node_id) else {
                        // TODO: unreachable?
                        warn!(node_id=%node_id.fmt_short(), "missing pending state, dropping connection");
                        continue;
                    };
                    let info = ConnInfo {
                        conn,
                        node_id,
                        direction,
                    };
                    self.active.insert(node_id, info.clone());
                    break Poll::Ready(Some(Ok(info)));
                }
            }
        }
    }
}

async fn accept_task(conn: Connection) -> Result<Connection, InitError> {
    let mut stream = conn.open_uni().await?;
    stream.write_all(&[0]).await?;
    stream.finish().await?;
    Ok(conn)
}

async fn connect_task(
    ep: Endpoint,
    node_id: NodeId,
    alpn: &'static [u8],
) -> Result<Connection, InitError> {
    let conn = ep.connect_by_node_id(&node_id, alpn).await?;
    let mut stream = conn.accept_uni().await?;
    stream.read_to_end(1).await?;
    Ok(conn)
}

#[derive(Debug)]
struct PendingState {
    direction: ConnDirection,
    abort_handle: AbortHandle,
}

#[derive(Debug)]
enum InitError {
    IsDuplicate,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for InitError {
    fn from(value: anyhow::Error) -> Self {
        Self::Other(value)
    }
}

impl From<quinn::ConnectionError> for InitError {
    fn from(value: quinn::ConnectionError) -> Self {
        match &value {
            quinn::ConnectionError::ApplicationClosed(err)
                if &err.reason[..] == DUPLICATE_REASON
                    && err.error_code == DUPLICATE_CODE.into() =>
            {
                Self::IsDuplicate
            }
            _ => Self::Other(value.into()),
        }
    }
}

impl From<quinn::ReadToEndError> for InitError {
    fn from(value: quinn::ReadToEndError) -> Self {
        match value {
            quinn::ReadToEndError::Read(quinn::ReadError::ConnectionLost(err)) => err.into(),
            err => Self::Other(err.into()),
        }
    }
}

impl From<quinn::WriteError> for InitError {
    fn from(value: quinn::WriteError) -> Self {
        match value {
            quinn::WriteError::ConnectionLost(err) => err.into(),
            err => Self::Other(err.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures_lite::StreamExt;
    use tokio::task::JoinSet;

    use crate::test_utils::TestEndpointBuilder;

    use super::{ConnManager, HandleConnectionSender};

    const TEST_ALPN: &[u8] = b"test";

    async fn accept_loop(
        ep: crate::Endpoint,
        accept_sender: HandleConnectionSender,
    ) -> anyhow::Result<()> {
        while let Some(conn) = ep.accept().await {
            let conn = conn.await?;
            tracing::debug!(me=%ep.node_id().fmt_short(), "conn incoming");
            accept_sender.send(conn).await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_conn_manager() -> anyhow::Result<()> {
        let _guard = iroh_test::logging::setup();
        let mut builder = TestEndpointBuilder::run().await?;

        let alpns = vec![TEST_ALPN.to_vec()];
        let ep1 = builder.create_endpoint(alpns.clone()).await?;
        let ep2 = builder.create_endpoint(alpns.clone()).await?;
        let n1 = ep1.node_id();
        let n2 = ep2.node_id();
        tracing::info!(?n1, ?n2, "endpoints created");
        builder.on_node(&n1, Duration::from_secs(2)).await?;
        builder.on_node(&n2, Duration::from_secs(2)).await?;

        let mut conn_manager1 = ConnManager::new(ep1.clone(), TEST_ALPN);
        let mut conn_manager2 = ConnManager::new(ep2.clone(), TEST_ALPN);

        let accept1 = conn_manager1.handle_connection_sender();
        let accept2 = conn_manager2.handle_connection_sender();
        let mut tasks = JoinSet::new();
        tasks.spawn(accept_loop(ep1, accept1));
        tasks.spawn(accept_loop(ep2, accept2));

        for i in 0u8..20 {
            assert!(conn_manager1.get(&n2).is_none());
            assert!(conn_manager2.get(&n1).is_none());

            tracing::info!(i, "start dial");
            conn_manager1.dial(n2);
            conn_manager2.dial(n1);
            let (conn1, conn2) = tokio::join!(conn_manager1.next(), conn_manager2.next());
            let conn1 = conn1.unwrap().unwrap();
            let conn2 = conn2.unwrap().unwrap();

            tracing::info!(?conn1.direction, "conn1");
            tracing::info!(?conn2.direction, "conn2");
            assert!(conn1.direction != conn2.direction);
            assert_eq!(conn1.node_id, n2);
            assert_eq!(conn2.node_id, n1);

            let mut s1 = conn1.open_uni().await.unwrap();
            s1.write_all(&[i]).await?;
            s1.finish().await?;

            let mut s2 = conn2.accept_uni().await.unwrap();
            let x = s2.read_to_end(1).await.unwrap();

            assert_eq!(&x, &[i]);
            assert!(conn_manager1.remove(&n2).is_some());
            assert!(conn_manager2.remove(&n1).is_some());
        }

        tasks.abort_all();

        Ok(())
    }
}
