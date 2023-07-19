//! Internal utilities to support testing.

use std::net::IpAddr;

use anyhow::Result;
use tokio::sync::oneshot;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::derp::{DerpMap, DerpNode, DerpRegion, UseIpv4, UseIpv6};

/// Configures logging for the current test.
///
/// This configures logging that will interact well with tests: logs will be captured by the
/// test framework and only printed on failure.
///
/// The logging is unfiltered, it logs all crates and modules on TRACE level.  If that's too
/// much consider if your test is too large (or write a version that allows filtering...).
#[must_use = "The tracing guard must only be dropped at the end of the test"]
#[allow(dead_code)]
pub(crate) fn setup_logging() -> tracing::subscriber::DefaultGuard {
    let var = std::env::var_os("RUST_LOG");
    let trace_log_layer = match var {
        Some(_) => None,
        None => Some(
            tracing_subscriber::fmt::layer()
                .with_writer(|| TestWriter)
                .with_filter(LevelFilter::TRACE),
        ),
    };
    let env_log_layer = var.map(|_| {
        tracing_subscriber::fmt::layer()
            .with_writer(|| TestWriter)
            .with_filter(EnvFilter::from_default_env())
    });
    tracing_subscriber::registry()
        .with(trace_log_layer)
        .with(env_log_layer)
        .set_default()
}

/// A tracing writer that interacts well with test output capture.
///
/// Using this writer will make sure that the output is captured normally and only printed
/// when the test fails.  See [`setup_logging`] to actually use this.
#[derive(Debug)]
struct TestWriter;

impl std::io::Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        print!(
            "{}",
            std::str::from_utf8(buf).expect("tried to log invalid UTF-8")
        );
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().flush()
    }
}

/// Runs a  DERP server with STUN enabled suitable for tests.
///
/// The returned `oneshot::Sender<()>` is a drop guard: the server will be shut down when
/// dropped.  You could also explicitly send a value to achieve the same if you so desire.
///
/// The returned `u16` is the region ID of the DERP server in the returned [`DerpMap`], it
/// is always `Some` as that is how the [`MagicEndpoint::connect`] API expects it.
///
/// [`MagicEndpoint::connect`]: crate::magic_endpoint::MagicEndpoint
pub async fn run_derp_and_stun(
    stun_ip: IpAddr,
) -> Result<(DerpMap, Option<u16>, oneshot::Sender<()>)> {
    // TODO: pass a mesh_key?

    let server_key = crate::key::node::SecretKey::generate();
    let tls_config = crate::derp::http::make_tls_config();
    let server = crate::derp::http::ServerBuilder::new("127.0.0.1:0".parse().unwrap())
        .secret_key(Some(server_key))
        .tls_config(Some(tls_config))
        .spawn()
        .await?;

    let https_addr = server.addr();
    println!("DERP listening on {:?}", https_addr);

    let (stun_addr, _, stun_cleanup) = crate::stun::test::serve(stun_ip).await?;
    let region_id = 1;
    let m = DerpMap {
        regions: [(
            1,
            DerpRegion {
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
                    stun_test_ip: Some(stun_addr.ip()),
                }],
                avoid: false,
            },
        )]
        .into_iter()
        .collect(),
    };

    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        // Wait until we're dropped or receive a message.
        rx.await.ok();
        stun_cleanup.send(()).ok(); // If receiver is gone it's already cleaned up.
        server.shutdown().await;
    });

    Ok((m, Some(region_id), tx))
}
