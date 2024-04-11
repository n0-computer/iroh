use std::{num::NonZeroUsize, path::Path};

use derive_more::FromStr;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use tracing_appender::{non_blocking, rolling};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, Layer};

/// Initialize logging both in the terminal and file based.
///
/// The terminal based logging layer will:
/// - use the defauilt [`fmt::format::Format`].
/// - log to [`std::io::Stderr`]
///
/// The file base logging layer will:
/// - use the defauilt [`fmt::format::Format`] save for:
///   - including line numbers.
///   - not using ansi colors.
/// - create log files in the `logs` dir inside the given `iroh_data_root`.
/// - rotate files every [`Self::rotation`].
/// - keep at most [`Self::max_files`] log files.
/// - use the filtering defined by [`Self::rust_log`].
/// - create log files with the name `iroh-<ROTATION_BASED_NAME>.log` (ex: iroh-2024-02-02.log)
pub(crate) fn init_terminal_and_file_logging(
    file_log_config: &FileLogging,
    logs_dir: &Path,
) -> anyhow::Result<non_blocking::WorkerGuard> {
    let terminal_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(tracing_subscriber::EnvFilter::from_default_env());
    let (file_layer, guard) = {
        let FileLogging {
            rust_log,
            max_files,
            rotation,
        } = file_log_config;

        let (file_logger, guard) = {
            let rotation = match rotation {
                Rotation::Hourly => rolling::Rotation::HOURLY,
                Rotation::Daily => rolling::Rotation::DAILY,
                Rotation::Never => rolling::Rotation::NEVER,
            };
            let logs_path = logs_dir.join("logs");

            let file_appender = rolling::Builder::new()
                .rotation(rotation)
                .max_log_files(max_files.get())
                .filename_prefix("iroh")
                .filename_suffix("log")
                .build(logs_path)?;
            non_blocking(file_appender)
        };

        let layer = fmt::Layer::new()
            .with_ansi(false)
            .with_line_number(true)
            .with_writer(file_logger)
            .with_filter(rust_log.layer());
        (layer, guard)
    };
    tracing_subscriber::registry()
        .with(file_layer)
        .with(terminal_layer)
        .try_init()?;
    Ok(guard)
}

/// Initialize logging in the terminal.
///
/// This will:
/// - use the defauilt [`fmt::format::Format`].
/// - log to [`std::io::Stderr`]
pub(crate) fn init_terminal_logging() -> anyhow::Result<()> {
    let terminal_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(tracing_subscriber::EnvFilter::from_default_env());
    tracing_subscriber::registry()
        .with(terminal_layer)
        .try_init()?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct FileLogging {
    /// RUST_LOG directive to filter file logs.
    pub(crate) rust_log: EnvFilter,
    /// Maximum number of files to keep.
    pub(crate) max_files: NonZeroUsize,
    /// How often should a new log file be produced.
    pub(crate) rotation: Rotation,
}

impl Default for FileLogging {
    fn default() -> Self {
        let filter = EnvFilter::default();
        Self {
            rust_log: filter,
            max_files: NonZeroUsize::new(8).expect("clearly non zero"),
            rotation: Rotation::default(),
        }
    }
}

/// Wrapper to obtain a [`tracing_subscriber::EnvFilter`] that satisfies required bounds.
#[derive(
    Debug, Clone, PartialEq, Eq, SerializeDisplay, DeserializeFromStr, derive_more::Display,
)]
#[display("{_0}")]
pub(crate) struct EnvFilter(String);

impl FromStr for EnvFilter {
    type Err = <tracing_subscriber::EnvFilter as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // validate the RUST_LOG statement
        let _valid_env = tracing_subscriber::EnvFilter::from_str(s)?;
        Ok(EnvFilter(s.into()))
    }
}

impl Default for EnvFilter {
    fn default() -> Self {
        // rustyline is annoying
        Self("rustyline=warn,debug".into())
    }
}

impl EnvFilter {
    pub(crate) fn layer(&self) -> tracing_subscriber::EnvFilter {
        tracing_subscriber::EnvFilter::from_str(&self.0).expect("validated RUST_LOG statement")
    }
}

/// Hoe often should a new file be created for file logs.
/// Akin to [`tracing_appender::rolling::Rotation`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
pub(crate) enum Rotation {
    #[default]
    Hourly,
    Daily,
    Never,
}
