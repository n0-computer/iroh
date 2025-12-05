//! Utils for emitting qlog files from iroh endpoint.

use std::path::{Path, PathBuf};
#[cfg(feature = "qlog")]
use std::sync::Arc;

use crate::endpoint::QuicTransportConfig;
use n0_error::Result;
#[cfg(feature = "qlog")]
use n0_future::time::Instant;

#[cfg(feature = "qlog")]
use crate::endpoint::QlogFileFactory;

/// Builder to create one or more related qlog configs.
///
/// This struct is available independently of feature flags, but if the "qlog" feature is not enabled
/// it does not do anything.
#[derive(Debug, Clone)]
pub struct QlogFileGroup {
    #[cfg(feature = "qlog")]
    directory: PathBuf,
    #[cfg(feature = "qlog")]
    title: String,
    #[cfg(feature = "qlog")]
    start: Instant,
}

impl QlogFileGroup {
    /// Creates a new [`QlogFileGroup`] that is only enabled if feature flags and environment variables match.
    ///
    /// The qlog files will be written to `CARGO_MANIFEST_DIR/qlog`.
    ///
    /// The [`QlogFileGroup`] can be used independent of feature flags, but it will only emit qlog files
    /// if the "qlog" feature is enabled and the environment variable IROH_TEST_QLOG is set to 1.
    pub fn from_env(title: impl ToString) -> Self {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("qlog");
        Self::new(directory, title)
    }

    /// Creates a new [`QlogFileGroup`] that writes qlog files to the specified directory.
    ///
    /// The [`QlogFileGroup] can be used independent of feature flags, but it will only emit qlog files
    /// if the "qlog" feature is enabled and the environment variable IROH_TEST_QLOG is set to 1.
    pub fn new(directory: impl AsRef<Path>, title: impl ToString) -> Self {
        #[cfg(not(feature = "qlog"))]
        let this = {
            let _ = (directory, title);
            Self {}
        };

        #[cfg(feature = "qlog")]
        let this = Self {
            title: title.to_string(),
            directory: directory.as_ref().to_owned(),
            start: Instant::now(),
        };

        this
    }

    /// Creates a [`QuicTransportConfig`] that emits qlog files, if enabled.
    ///
    /// If the "qlog" feature is enabled, and the environment variable IROH_TEST_QLOG is set,
    /// this returns a transport config that writes qlog configs to the configured output directory.
    /// Otherwise, a default transport config is returned.
    pub fn create(&self, name: impl ToString) -> Result<QuicTransportConfig> {
        let mut config = QuicTransportConfig::default();

        #[cfg(feature = "qlog")]
        if std::env::var("IROH_TEST_QLOG").is_ok() {
            let prefix = format!("{}.{}", self.title, name.to_string());
            let factory = QlogFileFactory::new(self.directory.clone())
                .with_prefix(prefix)
                .with_start_instant(self.start.into());
            config.qlog_factory(Arc::new(factory));
        }

        Ok(config)
    }
}
