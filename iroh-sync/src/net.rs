//! Network implementation of the iroh-sync protocol

use std::{
    future::Future,
    time::{Duration, Instant},
};

use iroh_net::{key::PublicKey, magic_endpoint::get_peer_id, MagicEndpoint, PeerAddr};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{
    net::codec::{run_alice, BobState},
    store,
    sync::AsyncReplica as Replica,
    NamespaceId, SyncOutcome,
};

#[cfg(feature = "metrics")]
use crate::metrics::Metrics;
#[cfg(feature = "metrics")]
use iroh_metrics::inc;

/// The ALPN identifier for the iroh-sync protocol
pub const SYNC_ALPN: &[u8] = b"/iroh-sync/1";

mod codec;

/// Connect to a peer and sync a replica
pub async fn connect_and_sync<S: store::Store>(
    endpoint: &MagicEndpoint,
    replica: &Replica<S::Instance>,
    peer: PeerAddr,
) -> Result<SyncFinished, ConnectError> {
    let t_start = Instant::now();
    let peer_id = peer.peer_id;
    debug!(peer = %peer_id.fmt_short(), "sync[dial]: connect");
    let namespace = replica.namespace();
    let connection = endpoint
        .connect(peer, SYNC_ALPN)
        .await
        .map_err(ConnectError::connect)?;

    let (mut send_stream, mut recv_stream) =
        connection.open_bi().await.map_err(ConnectError::connect)?;

    let t_connect = t_start.elapsed();
    debug!(peer = %peer_id.fmt_short(), namespace = %namespace.fmt_short(), ?t_connect, "sync[dial]: connected");

    let res = run_alice::<S, _, _>(&mut send_stream, &mut recv_stream, replica, peer_id).await;

    send_stream.finish().await.map_err(ConnectError::close)?;
    recv_stream
        .read_to_end(0)
        .await
        .map_err(ConnectError::close)?;

    #[cfg(feature = "metrics")]
    if res.is_ok() {
        inc!(Metrics, sync_via_connect_success);
    } else {
        inc!(Metrics, sync_via_connect_failure);
    }

    let t_process = t_start.elapsed() - t_connect;
    match &res {
        Ok(res) => {
            debug!(
                peer = %peer_id.fmt_short(),
                namespace = %namespace.fmt_short(),
                ?t_connect,
                ?t_process,
                sent = %res.num_sent,
                recv = %res.num_recv,
                "sync[dial]: done, sucess"
            );
        }
        Err(err) => {
            debug!(
                peer = %peer_id.fmt_short(),
                namespace = %namespace.fmt_short(),
                ?t_connect,
                ?t_process,
                ?err,
                "sync[dial]: done, failed"
            );
        }
    }

    let outcome = res?;

    let timings = Timings {
        connect: t_connect,
        process: t_process,
    };

    let res = SyncFinished {
        namespace,
        peer: peer_id,
        outcome,
        timings,
    };

    Ok(res)
}

/// What to do with incoming sync requests
pub type AcceptOutcome<S> = Result<Replica<<S as store::Store>::Instance>, AbortReason>;

/// Handle an iroh-sync connection and sync all shared documents in the replica store.
pub async fn handle_connection<S, F, Fut>(
    connecting: quinn::Connecting,
    accept_cb: F,
) -> Result<SyncFinished, AcceptError>
where
    S: store::Store,
    F: Fn(NamespaceId, PublicKey) -> Fut,
    Fut: Future<Output = anyhow::Result<AcceptOutcome<S>>>,
{
    let t_start = Instant::now();
    let connection = connecting.await.map_err(AcceptError::connect)?;
    let peer = get_peer_id(&connection)
        .await
        .map_err(AcceptError::connect)?;
    let (mut send_stream, mut recv_stream) = connection
        .accept_bi()
        .await
        .map_err(|e| AcceptError::open(peer, e))?;

    let t_connect = t_start.elapsed();
    debug!(?peer, ?t_connect, "sync[accept]: handle");

    let mut state = BobState::<S>::new(peer);
    let res = state
        .run(&mut send_stream, &mut recv_stream, accept_cb)
        .await;

    #[cfg(feature = "metrics")]
    if res.is_ok() {
        inc!(Metrics, sync_via_accept_success);
    } else {
        inc!(Metrics, sync_via_accept_failure);
    }

    let namespace = state.namespace();
    let progress = state.into_outcome();

    send_stream
        .finish()
        .await
        .map_err(|error| AcceptError::close(peer, namespace, error))?;
    recv_stream
        .read_to_end(0)
        .await
        .map_err(|error| AcceptError::close(peer, namespace, error))?;

    let t_process = t_start.elapsed() - t_connect;
    let namespace = res?;

    debug!(
        peer = %peer.fmt_short(),
        namespace = %namespace.fmt_short(),
        ?t_process,
        ?t_connect,
        sent = %progress.num_sent,
        recv = %progress.num_recv,
        "sync[accept]: done, success"
    );

    let timings = Timings {
        connect: t_connect,
        process: t_process,
    };

    let res = SyncFinished {
        namespace,
        outcome: progress,
        peer,
        timings,
    };

    Ok(res)
}

/// Details of a finished sync operation.
#[derive(Debug, Clone)]
pub struct SyncFinished {
    /// The namespace that was synced.
    pub namespace: NamespaceId,
    /// The peer we syned with.
    pub peer: PublicKey,
    /// The outcome of the sync operation
    pub outcome: SyncOutcome,
    /// The time this operation took
    pub timings: Timings,
}

/// Time a sync operation took
#[derive(Debug, Default, Clone)]
pub struct Timings {
    /// Time to establish connection
    pub connect: Duration,
    /// Time to run sync exchange
    pub process: Duration,
}

/// Errors that may occur on handling incoming sync connections.
#[derive(thiserror::Error, Debug)]
#[allow(missing_docs)]
pub enum AcceptError {
    /// Failed to establish connection
    #[error("Failed to establish connection")]
    Connect {
        #[source]
        error: anyhow::Error,
    },
    /// Failed to open replica
    #[error("Failed to open replica with {peer:?}")]
    Open {
        peer: PublicKey,
        #[source]
        error: anyhow::Error,
    },
    /// We aborted the sync request.
    #[error("Aborted sync of {namespace:?} with {peer:?}: {reason:?}")]
    Abort {
        peer: PublicKey,
        namespace: NamespaceId,
        reason: AbortReason,
    },
    /// Failed to run sync
    #[error("Failed to sync {namespace:?} with {peer:?}")]
    Sync {
        peer: PublicKey,
        namespace: Option<NamespaceId>,
        #[source]
        error: anyhow::Error,
    },
    /// Failed to close
    #[error("Failed to close {namespace:?} with {peer:?}")]
    Close {
        peer: PublicKey,
        namespace: Option<NamespaceId>,
        #[source]
        error: anyhow::Error,
    },
}

/// Errors that may occur on outgoing sync requests.
#[derive(thiserror::Error, Debug)]
#[allow(missing_docs)]
pub enum ConnectError {
    /// Failed to establish connection
    #[error("Failed to establish connection")]
    Connect {
        #[source]
        error: anyhow::Error,
    },
    /// The remote peer aborted the sync request.
    #[error("Remote peer aborted sync: {0:?}")]
    RemoteAbort(AbortReason),
    /// Failed to run sync
    #[error("Failed to sync")]
    Sync {
        #[source]
        error: anyhow::Error,
    },
    /// Failed to close
    #[error("Failed to close connection1")]
    Close {
        #[source]
        error: anyhow::Error,
    },
}

/// Reason why we aborted an incoming sync request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AbortReason {
    /// Namespace is not avaiable.
    NotAvailable,
    /// We are already syncing this namespace.
    AlreadySyncing,
}

impl AcceptError {
    fn connect(error: impl Into<anyhow::Error>) -> Self {
        Self::Connect {
            error: error.into(),
        }
    }
    fn open(peer: PublicKey, error: impl Into<anyhow::Error>) -> Self {
        Self::Open {
            peer,
            error: error.into(),
        }
    }
    pub(crate) fn sync(
        peer: PublicKey,
        namespace: Option<NamespaceId>,
        error: impl Into<anyhow::Error>,
    ) -> Self {
        Self::Sync {
            peer,
            namespace,
            error: error.into(),
        }
    }
    fn close(
        peer: PublicKey,
        namespace: Option<NamespaceId>,
        error: impl Into<anyhow::Error>,
    ) -> Self {
        Self::Close {
            peer,
            namespace,
            error: error.into(),
        }
    }
    /// Get the peer's node ID (if available)
    pub fn peer(&self) -> Option<PublicKey> {
        match self {
            AcceptError::Connect { .. } => None,
            AcceptError::Open { peer, .. } => Some(*peer),
            AcceptError::Sync { peer, .. } => Some(*peer),
            AcceptError::Close { peer, .. } => Some(*peer),
            AcceptError::Abort { peer, .. } => Some(*peer),
        }
    }

    /// Get the namespace (if available)
    pub fn namespace(&self) -> Option<NamespaceId> {
        match self {
            AcceptError::Connect { .. } => None,
            AcceptError::Open { .. } => None,
            AcceptError::Sync { namespace, .. } => namespace.to_owned(),
            AcceptError::Close { namespace, .. } => namespace.to_owned(),
            AcceptError::Abort { namespace, .. } => Some(*namespace),
        }
    }
}

impl ConnectError {
    fn connect(error: impl Into<anyhow::Error>) -> Self {
        Self::Connect {
            error: error.into(),
        }
    }
    fn close(error: impl Into<anyhow::Error>) -> Self {
        Self::Close {
            error: error.into(),
        }
    }
    pub(crate) fn sync(error: impl Into<anyhow::Error>) -> Self {
        Self::Sync {
            error: error.into(),
        }
    }
    pub(crate) fn remote_abort(reason: AbortReason) -> Self {
        Self::RemoteAbort(reason)
    }
}
