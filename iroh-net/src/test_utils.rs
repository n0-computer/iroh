//! Internal utilities to support testing.

use std::net::IpAddr;

use anyhow::Result;
use tokio::runtime::RuntimeFlavor;
use tokio::sync::oneshot;
use tracing::level_filters::LevelFilter;
use tracing::{info_span, Instrument};
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::derp::{DerpMap, DerpNode, DerpRegion, UseIpv4, UseIpv6};
use crate::tls::Keypair;

/// Configures logging for the current test, **single-threaded runtime only**.
///
/// This setup can be used for any sync test or async test using a single-threaded tokio
/// runtime (the default).  For multi-threaded runtimes use [`with_logging`].
///
/// This configures logging that will interact well with tests: logs will be captured by the
/// test framework and only printed on failure.
///
/// The logging is unfiltered, it logs all crates and modules on TRACE level.  If that's too
/// much consider if your test is too large (or write a version that allows filtering...).
///
/// # Example
///
/// ```no_run
/// #[tokio::test]
/// async fn test_something() {
///     let _guard = crate::test_utils::setup_logging();
///     assert!(true);
/// }
#[must_use = "The tracing guard must only be dropped at the end of the test"]
#[allow(dead_code)]
pub(crate) fn setup_logging() -> tracing::subscriber::DefaultGuard {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        match handle.runtime_flavor() {
            RuntimeFlavor::CurrentThread => (),
            RuntimeFlavor::MultiThread => {
                panic!("setup_logging() does not work in a multi-threaded tokio runtime");
            }
            _ => panic!("unknown runtime flavour"),
        }
    }
    testing_subscriber().set_default()
}

// /// Invoke the future with test logging configured.
// ///
// /// This can be used to execute any future which uses tracing for logging, it sets up the
// /// logging as [`setup_logging`] does but in a way which will work for both single and
// /// multi-threaded tokio runtimes.
// pub(crate) async fn with_logging<F: Future>(f: F) -> F::Output {
//     f.with_subscriber(testing_subscriber()).await
// }

/// Returns the a [`tracing::Subscriber`] configured for our tests.
///
/// This subscriber will ensure that log output is captured by the test's default output
/// capturing and thus is only shown with the test on failure.  By default it uses
/// `RUST_LOG=trace` as configuration but you can specify the `RUST_LOG` environment
/// variable explicitly to override this.
///
/// To use this in a tokio multi-threaded runtime use:
///
/// ```no_run
/// use tracing_future::WithSubscriber;
/// use crate::test_utils::testing_subscriber;
///
/// #[tokio::test(flavor = "multi_thread")]
/// async fn test_something() -> Result<()> {
///    async move {
///        Ok(())
///    }.with_subscriber(testing_subscriber()).await
/// }
/// ```
pub(crate) fn testing_subscriber() -> impl tracing::Subscriber {
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
pub(crate) async fn run_derp_and_stun(
    stun_ip: IpAddr,
) -> Result<(DerpMap, Option<u16>, CleanupDropGuard)> {
    // TODO: pass a mesh_key?

    let server_key = Keypair::generate();
    let tls_config = crate::derp::http::make_tls_config();
    let server = crate::derp::http::ServerBuilder::new("127.0.0.1:0".parse().unwrap())
        .secret_key(Some(server_key))
        .tls_config(Some(tls_config))
        .spawn()
        .await?;

    let https_addr = server.addr();
    println!("DERP listening on {:?}", https_addr);

    let (stun_addr, _, stun_drop_guard) = crate::stun::test::serve(stun_ip).await?;
    let region_id = 1;
    let m: DerpMap = [DerpRegion {
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
    }]
    .into();

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

    Ok((m, Some(region_id), CleanupDropGuard(tx)))
}
