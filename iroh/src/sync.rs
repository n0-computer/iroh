//! Implementation of the iroh-sync protocol

use std::net::SocketAddr;

use anyhow::{Context, Result};
use iroh_net::{key::PublicKey, magic_endpoint::get_peer_id, MagicEndpoint};
use iroh_sync::{store, sync::Replica};
use tracing::debug;

#[cfg(feature = "metrics")]
use crate::metrics::Metrics;
use crate::sync::codec::{run_alice, run_bob};
#[cfg(feature = "metrics")]
use iroh_metrics::inc;

/// The ALPN identifier for the iroh-sync protocol
pub const SYNC_ALPN: &[u8] = b"/iroh-sync/1";

mod codec;
mod engine;
mod live;
pub mod rpc;

pub use engine::*;
pub use live::*;

/// Connect to a peer and sync a replica
pub async fn connect_and_sync<S: store::Store>(
    endpoint: &MagicEndpoint,
    doc: &Replica<S::Instance>,
    peer_id: PublicKey,
    derp_region: Option<u16>,
    addrs: &[SocketAddr],
) -> anyhow::Result<()> {
    debug!("sync with peer {}: start", peer_id);
    let connection = endpoint
        .connect(peer_id, SYNC_ALPN, derp_region, addrs)
        .await
        .context("dial_and_sync")?;
    let (mut send_stream, mut recv_stream) = connection.open_bi().await?;
    let res = run_alice::<S, _, _>(&mut send_stream, &mut recv_stream, doc, peer_id).await;

    #[cfg(feature = "metrics")]
    if res.is_ok() {
        inc!(Metrics, initial_sync_success);
    } else {
        inc!(Metrics, initial_sync_failed);
    }

    debug!("sync with peer {}: finish {:?}", peer_id, res);
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
