//! Utilities for logging
use std::{env, path::Path};

use derive_more::FromStr;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use tracing_appender::{non_blocking, rolling};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, Layer};

/// `RUST_LOG` statement used by default in file logging.
// rustyline is annoying
pub(crate) const DEFAULT_FILE_RUST_LOG: &str = "rustyline=warn,debug";

/// Parse `<bin>_FILE_RUST_LOG` as [`tracing_subscriber::EnvFilter`]. Returns `None` if not
/// present.
pub fn env_file_rust_log(bin: &'static str) -> Option<anyhow::Result<EnvFilter>> {
    let env_file_rust_log = format!("{}_FILE_RUST_LOG", bin.to_uppercase());
    match env::var(env_file_rust_log) {
        Ok(s) => Some(crate::logging::EnvFilter::from_str(&s).map_err(Into::into)),
        Err(e) => match e {
            env::VarError::NotPresent => None,
            e @ env::VarError::NotUnicode(_) => Some(Err(e.into())),
        },
    }
}

/// Initialize logging both in the terminal and file based.
///
/// The terminal based logging layer will:
/// - use the default [`fmt::format::Format`].
/// - log to [`std::io::Stderr`]
///
/// The file base logging layer will:
/// - use the default [`fmt::format::Format`] save for:
///   - including line numbers.
///   - not using ansi colors.
/// - create log files in the [`FileLogging::dir`] directory. If not provided, the `logs` dir
///   inside the given `logs_root` is used.
/// - rotate files every [`FileLogging::rotation`].
/// - keep at most [`FileLogging::max_files`] log files.
/// - use the filtering defined by [`FileLogging::rust_log`]. When not provided, the default
///   `DEFAULT_FILE_RUST_LOG` is used.
/// - create log files with the name `iroh-<ROTATION_BASED_NAME>.log` (ex: iroh-2024-02-02.log)
pub fn init_terminal_and_file_logging(
    file_log_config: &FileLogging,
    logs_root: &Path,
) -> anyhow::Result<non_blocking::WorkerGuard> {
    let terminal_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(tracing_subscriber::EnvFilter::from_default_env());
    let (file_layer, guard) = {
        let FileLogging {
            rust_log,
            max_files,
            rotation,
            dir,
        } = file_log_config;

        let filter = rust_log.layer();

        let (file_logger, guard) = {
            let file_appender = if *max_files == 0 || &filter.to_string() == "off" {
                fmt::writer::OptionalWriter::none()
            } else {
                let rotation = match rotation {
                    Rotation::Hourly => rolling::Rotation::HOURLY,
                    Rotation::Daily => rolling::Rotation::DAILY,
                    Rotation::Never => rolling::Rotation::NEVER,
                };

                // prefer the directory set in the config file over the default
                let logs_path = dir.clone().unwrap_or_else(|| logs_root.join("logs"));

                let file_appender = rolling::Builder::new()
                    .rotation(rotation)
                    .max_log_files(*max_files)
                    .filename_prefix("iroh")
                    .filename_suffix("log")
                    .build(logs_path)?;
                fmt::writer::OptionalWriter::some(file_appender)
            };
            non_blocking(file_appender)
        };

        let layer = fmt::Layer::new()
            .with_ansi(false)
            .with_line_number(true)
            .with_writer(file_logger)
            .with_filter(filter);
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
/// - use the default [`fmt::format::Format`].
/// - log to [`std::io::Stderr`]
pub fn init_terminal_logging() -> anyhow::Result<()> {
    let terminal_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(tracing_subscriber::EnvFilter::from_default_env());
    tracing_subscriber::registry()
        .with(terminal_layer)
        .try_init()?;
    Ok(())
}

/// Configuration for the logfiles.
// Please note that this is documented in the `iroh.computer` repository under
// `src/app/docs/reference/config/page.mdx`.  Any changes to this need to be updated there.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileLogging {
    /// RUST_LOG directive to filter file logs.
    pub rust_log: EnvFilter,
    /// Maximum number of files to keep.
    pub max_files: usize,
    /// How often should a new log file be produced.
    pub rotation: Rotation,
    /// Where to store log files.
    pub dir: Option<std::path::PathBuf>,
}

impl Default for FileLogging {
    fn default() -> Self {
        Self {
            rust_log: EnvFilter::default(),
            max_files: 4,
            rotation: Rotation::default(),
            dir: None,
        }
    }
}

/// Wrapper to obtain a [`tracing_subscriber::EnvFilter`] that satisfies required bounds.
#[derive(
    Debug, Clone, PartialEq, Eq, SerializeDisplay, DeserializeFromStr, derive_more::Display,
)]
#[display("{_0}")]
pub struct EnvFilter(String);

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
        Self(DEFAULT_FILE_RUST_LOG.into())
    }
}

impl EnvFilter {
    pub(crate) fn layer(&self) -> tracing_subscriber::EnvFilter {
        tracing_subscriber::EnvFilter::from_str(&self.0).expect("validated RUST_LOG statement")
    }
}

/// How often should a new file be created for file logs.
///
/// Akin to [`tracing_appender::rolling::Rotation`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
#[allow(missing_docs)]
pub enum Rotation {
    #[default]
    Hourly,
    Daily,
    Never,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that the default file logging `RUST_LOG` statement produces a valid layer.
    #[test]
    fn test_default_file_rust_log() {
        let _ = EnvFilter::default().layer();
    }
}
