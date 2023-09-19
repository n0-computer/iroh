//! Network implementation of the iroh-sync protocol

use anyhow::{Context, Result};
use iroh_net::{magic_endpoint::get_peer_id, MagicEndpoint, NodeAddr};
use tracing::debug;

use crate::{
    net::codec::{run_alice, run_bob},
    store,
    sync::Replica,
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
    addr: NodeAddr,
) -> anyhow::Result<()> {
    let node_id = addr.node_id;
    debug!("sync with peer {}: start", node_id);
    let connection = endpoint
        .connect(addr, SYNC_ALPN)
        .await
        .context("dial_and_sync")?;
    let (mut send_stream, mut recv_stream) = connection.open_bi().await?;
    let res = run_alice::<S, _, _>(&mut send_stream, &mut recv_stream, doc, node_id).await;

    #[cfg(feature = "metrics")]
    if res.is_ok() {
        inc!(Metrics, initial_sync_success);
    } else {
        inc!(Metrics, initial_sync_failed);
    }

    debug!("sync with peer {}: finish {:?}", node_id, res);
    res
}

/// Handle an iroh-sync connection and sync all shared documents in the replica store.
pub async fn handle_connection<S: store::Store>(
    connecting: quinn::Connecting,
    replica_store: S,
) -> Result<()> {
    let connection = connecting.await?;
    let peer_id = get_peer_id(&connection).await?;
    let (mut send_stream, mut recv_stream) = connection.accept_bi().await?;
    debug!(peer = ?peer_id, "incoming sync: start");

    let res = run_bob(&mut send_stream, &mut recv_stream, replica_store, peer_id).await;

    #[cfg(feature = "metrics")]
    if res.is_ok() {
        inc!(Metrics, initial_sync_success);
    } else {
        inc!(Metrics, initial_sync_failed);
    }

    res?;
    send_stream.finish().await?;

    debug!(peer = ?peer_id, "incoming sync: done");

    Ok(())
}
