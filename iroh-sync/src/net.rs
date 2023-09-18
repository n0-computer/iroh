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
    peer_id: PublicKey,
    derp_region: Option<u16>,
    addrs: &[SocketAddr],
) -> anyhow::Result<()> {
    debug!(peer = ?peer_id, "sync (via connect): start");
    let connection = endpoint
        .connect(peer_id, SYNC_ALPN, derp_region, addrs)
        .await
        .context("dial_and_sync")?;
    debug!(peer = ?peer_id, "sync (via connect): connected");
    let (mut send_stream, mut recv_stream) = connection.open_bi().await?;
    let res = run_alice::<S, _, _>(&mut send_stream, &mut recv_stream, doc, peer_id).await;

    #[cfg(feature = "metrics")]
    if res.is_ok() {
        inc!(Metrics, initial_sync_success);
    } else {
        inc!(Metrics, initial_sync_failed);
    }

    debug!(peer = ?peer_id, ?res, "sync (via connect): done");
    res
}

/// Handle an iroh-sync connection and sync all shared documents in the replica store.
pub async fn handle_connection<S, F, Fut>(
    connecting: quinn::Connecting,
    request_replica_cb: F,
) -> Result<(NamespaceId, PublicKey)>
where
    S: store::Store,
    F: Fn(NamespaceId, PublicKey) -> Fut,
    Fut: Future<Output = Option<Replica<S::Instance>>>,
{
    let connection = connecting.await?;
    let peer_id = get_peer_id(&connection).await?;
    let (mut send_stream, mut recv_stream) = connection.accept_bi().await?;
    debug!(peer = ?peer_id, "sync (via accept): start");

    let res = run_bob::<S, _, _, _, _>(
        &mut send_stream,
        &mut recv_stream,
        request_replica_cb,
        peer_id,
    )
    .await;

    #[cfg(feature = "metrics")]
    if res.is_ok() {
        inc!(Metrics, initial_sync_success);
    } else {
        inc!(Metrics, initial_sync_failed);
    }

    debug!(peer = ?peer_id, ?res, "sync (via accept): done");

    let namespace = res?;
    send_stream.finish().await?;

    Ok((namespace, peer_id))
}
