//! Internal utilities to support testing.

use anyhow::Result;
use tokio::sync::oneshot;
use tracing::{info_span, Instrument};

use crate::derp::{DerpMap, DerpNode, DerpRegion, UseIpv4, UseIpv6};
use crate::key::SecretKey;

/// A drop guard to clean up test infrastructure.
///
/// After dropping the test infrastructure will asynchronously shutdown and release its
/// resources.
#[derive(Debug)]
pub(crate) struct CleanupDropGuard(pub(crate) oneshot::Sender<()>);

/// Runs a  DERP server with STUN enabled suitable for tests.
///
/// The returned `u16` is the region ID of the DERP server in the returned [`DerpMap`], it
/// is always `Some` as that is how the [`MagicEndpoint::connect`] API expects it.
///
/// [`MagicEndpoint::connect`]: crate::magic_endpoint::MagicEndpoint
pub(crate) async fn run_derper() -> Result<(DerpMap, u16, CleanupDropGuard)> {
    // TODO: pass a mesh_key?

    let server_key = SecretKey::generate();
    let tls_config = crate::derp::http::make_tls_config();
    let server = crate::derp::http::ServerBuilder::new("127.0.0.1:0".parse().unwrap())
        .secret_key(Some(server_key))
        .tls_config(Some(tls_config))
        .spawn()
        .await?;

    let https_addr = server.addr();
    println!("DERP listening on {:?}", https_addr);

    let (stun_addr, _, stun_drop_guard) = crate::stun::test::serve(server.addr().ip()).await?;
    let region_id = 1;
    let m = DerpMap::from_regions([DerpRegion {
        region_id,
        region_code: "test".into(),
        nodes: vec![DerpNode {
            name: "t1".into(),
            region_id,
            // In test mode, the DERP client does not validate HTTPS certs, so the host
            // name is irrelevant, but the port is used.
            url: format!("https://test-node.invalid:{}", https_addr.port())
                .parse()
                .unwrap(),
            stun_only: false,
            stun_port: stun_addr.port(),
            ipv4: UseIpv4::Some("127.0.0.1".parse().unwrap()),
            ipv6: UseIpv6::Disabled,
        }
        .into()],
        avoid: false,
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
        .instrument(info_span!("derp-stun-cleanup")),
    );

    Ok((m, region_id, CleanupDropGuard(tx)))
}
