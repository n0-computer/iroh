//! Internal utilities to support testing.

use tracing::level_filters::LevelFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Configures logging for the current test.
///
/// This configures logging that will interact well with tests: logs will be captured by the
/// test framework and only printed on failure.
///
/// The logging is unfiltered, it logs all crates and modules on TRACE level.  If that's too
/// much consider if your test is too large (or write a version that allows filtering...).
#[must_use = "The tracing guard must only be dropped at the end of the test"]
pub(crate) fn setup_logging() -> tracing::subscriber::DefaultGuard {
    let var = std::env::var_os("RUST_LOG");
    let trace_log_layer = match var {
        Some(_) => None,
        None => Some(
            tracing_subscriber::fmt::layer()
                .with_span_events(FmtSpan::CLOSE)
                .with_writer(|| TestWriter)
                .with_filter(LevelFilter::TRACE),
        ),
    };
    let env_log_layer = var.map(|_| {
        tracing_subscriber::fmt::layer()
            .with_span_events(FmtSpan::CLOSE)
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
