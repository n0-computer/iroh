//! Internal utilities to support testing.

use anyhow::Result;
use tokio::sync::oneshot;
use tracing::{error_span, info_span, Instrument};

use crate::key::SecretKey;
use crate::relay::{DerpMap, DerpNode, DerpUrl};

/// A drop guard to clean up test infrastructure.
///
/// After dropping the test infrastructure will asynchronously shutdown and release its
/// resources.
// Nightly sees the sender as dead code currently, but we only rely on Drop of the
// sender.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct CleanupDropGuard(pub(crate) oneshot::Sender<()>);

/// Runs a relay server with STUN enabled suitable for tests.
///
/// The returned `Url` is the url of the relay server in the returned [`DerpMap`], it
/// is always `Some` as that is how the [`MagicEndpoint::connect`] API expects it.
///
/// [`MagicEndpoint::connect`]: crate::magic_endpoint::MagicEndpoint
pub(crate) async fn run_relay_server() -> Result<(DerpMap, DerpUrl, CleanupDropGuard)> {
    let server_key = SecretKey::generate();
    let me = server_key.public().fmt_short();
    let tls_config = crate::relay::http::make_tls_config();
    let server = crate::relay::http::ServerBuilder::new("127.0.0.1:0".parse().unwrap())
        .secret_key(Some(server_key))
        .tls_config(Some(tls_config))
        .spawn()
        .instrument(error_span!("relay server", %me))
        .await?;

    let https_addr = server.addr();
    println!("relay listening on {:?}", https_addr);

    let (stun_addr, _, stun_drop_guard) = crate::stun::test::serve(server.addr().ip()).await?;
    let url: DerpUrl = format!("https://localhost:{}", https_addr.port())
        .parse()
        .unwrap();
    let m = DerpMap::from_nodes([DerpNode {
        url: url.clone(),
        stun_only: false,
        stun_port: stun_addr.port(),
    }])
    .expect("hardcoded");

    let (tx, rx) = oneshot::channel();
    tokio::spawn(
        async move {
            let _stun_cleanup = stun_drop_guard; // move into this closure

            // Wait until we're dropped or receive a message.
            rx.await.ok();
            server.shutdown().await;
        }
        .instrument(info_span!("relay-stun-cleanup")),
    );

    Ok((m, url, CleanupDropGuard(tx)))
}
