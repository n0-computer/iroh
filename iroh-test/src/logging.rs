//! Logging during tests.

use tokio::runtime::RuntimeFlavor;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Configures logging for the current test, **single-threaded runtime only**.
///
/// This setup can be used for any sync test or async test using a single-threaded tokio
/// runtime (the default).
///
/// This configures logging that will interact well with tests: logs will be captured by the
/// test framework and only printed on failure.
///
/// The logging is unfiltered, it logs all crates and modules on TRACE level.  If that's too
/// much consider if your test is too large (or write a version that allows filtering...).
///
/// # Example
///
/// ```
/// #[tokio::test]
/// async fn test_something() {
///     let _guard = iroh_test::logging::setup();
///     assert!(true);
/// }
#[must_use = "The tracing guard must only be dropped at the end of the test"]
pub fn setup() -> tracing::subscriber::DefaultGuard {
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
/// ```ignore
/// use tracing_future::WithSubscriber;
/// use iroh_test::logging::testing_subscriber;
///
/// #[tokio::test(flavor = "multi_thread")]
/// async fn test_something() -> Result<()> {
///    async move {
///        Ok(())
///    }.with_subscriber(testing_subscriber()).await
/// }
/// ```
pub fn testing_subscriber() -> impl tracing::Subscriber {
    let var = std::env::var_os("RUST_LOG");
    let trace_log_layer = match var {
        Some(_) => None,
        None => Some(
            tracing_subscriber::fmt::layer()
                .event_format(tracing_subscriber::fmt::format().with_line_number(true))
                .with_writer(|| TestWriter)
                .with_filter(LevelFilter::TRACE),
        ),
    };
    let env_log_layer = var.map(|_| {
        tracing_subscriber::fmt::layer()
            .event_format(tracing_subscriber::fmt::format().with_line_number(true))
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
/// when the test fails.  See [`setup`] to actually use this.
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
