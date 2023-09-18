//! Network implementation of the iroh-sync protocol

use std::{future::Future, net::SocketAddr};

use anyhow::{Context, Result};
use iroh_net::{key::PublicKey, magic_endpoint::get_peer_id, MagicEndpoint};
use tracing::debug;

use crate::{
    net::codec::{run_alice, run_bob},
    store,
    sync::Replica,
    NamespaceId,
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
    doc: &Replica<S::Instance>,
    peer: PublicKey,
    derp_region: Option<u16>,
    addrs: &[SocketAddr],
) -> Result<()> {
    debug!(peer = ?peer, "sync (via connect): start");
    let namespace = doc.namespace();
    let connection = endpoint
        .connect(peer, SYNC_ALPN, derp_region, addrs)
        .await
        .context("failed to establish connection")?;
    debug!(?peer, ?namespace, "sync (via connect): connected");
    let (mut send_stream, mut recv_stream) = connection.open_bi().await?;
    let res = run_alice::<S, _, _>(&mut send_stream, &mut recv_stream, doc, peer).await;
    send_stream.finish().await?;
    recv_stream.read_to_end(0).await?;

    #[cfg(feature = "metrics")]
    if res.is_ok() {
        inc!(Metrics, sync_via_connect_success);
    } else {
        inc!(Metrics, sync_via_connect_failure);
    }

    debug!(peer = ?peer, ?res, "sync (via connect): done");
    res
}

/// What to do with incoming sync requests
#[derive(Debug)]
pub enum AcceptOutcome<S: store::Store> {
    /// This namespace is not available for sync.
    NotAvailable,
    /// This namespace is already syncing, therefore abort.
    AlreadySyncing,
    /// Accept the sync request.
    Accept(Replica<S::Instance>),
}

impl<S: store::Store> From<Option<Replica<S::Instance>>> for AcceptOutcome<S> {
    fn from(replica: Option<Replica<S::Instance>>) -> Self {
        match replica {
            Some(replica) => AcceptOutcome::Accept(replica),
            None => AcceptOutcome::NotAvailable,
        }
    }
}

/// Handle an iroh-sync connection and sync all shared documents in the replica store.
pub async fn handle_connection<S, F, Fut>(
    connecting: quinn::Connecting,
    accept_cb: F,
) -> std::result::Result<(NamespaceId, PublicKey), SyncError>
where
    S: store::Store,
    F: Fn(NamespaceId, PublicKey) -> Fut,
    Fut: Future<Output = anyhow::Result<AcceptOutcome<S>>>,
{
    let connection = connecting.await.map_err(SyncError::connect)?;
    let peer = get_peer_id(&connection).await.map_err(SyncError::connect)?;
    let (mut send_stream, mut recv_stream) = connection
        .accept_bi()
        .await
        .map_err(|error| SyncError::open(peer, error))?;
    debug!(peer = ?peer, "sync (via accept): start");

    let res = run_bob::<S, _, _, _, _>(&mut send_stream, &mut recv_stream, accept_cb, peer).await;

    #[cfg(feature = "metrics")]
    if res.is_ok() {
        inc!(Metrics, sync_via_accept_success);
    } else {
        inc!(Metrics, sync_via_accept_failure);
    }

    debug!(peer = ?peer, ?res, "sync (via accept): done");

    let namespace = res?;
    send_stream
        .finish()
        .await
        .map_err(|error| SyncError::close(peer, namespace, error))?;
    recv_stream
        .read_to_end(0)
        .await
        .map_err(|error| SyncError::close(peer, namespace, error))?;
    Ok((namespace, peer))
}

/// Failure reasons for sync.
#[derive(thiserror::Error, Debug)]
#[allow(missing_docs)]
pub enum SyncError {
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
        namespace: NamespaceId,
        #[source]
        error: anyhow::Error,
    },
}

impl SyncError {
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
    fn close(peer: PublicKey, namespace: NamespaceId, error: impl Into<anyhow::Error>) -> Self {
        Self::Close {
            peer,
            namespace,
            error: error.into(),
        }
    }
    /// Get the peer's node ID (if available)
    pub fn peer(&self) -> Option<PublicKey> {
        match self {
            SyncError::Connect { .. } => None,
            SyncError::Open { peer, .. } => Some(*peer),
            SyncError::Sync { peer, .. } => Some(*peer),
            SyncError::Close { peer, .. } => Some(*peer),
        }
    }

    /// Get the namespace (if available)
    pub fn namespace(&self) -> Option<NamespaceId> {
        match self {
            SyncError::Connect { .. } => None,
            SyncError::Open { .. } => None,
            SyncError::Sync { namespace, .. } => namespace.to_owned(),
            SyncError::Close { namespace, .. } => Some(*namespace),
        }
    }
}
