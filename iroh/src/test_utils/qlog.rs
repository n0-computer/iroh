//! Utils for emitting qlog files from iroh endpoint.

use std::path::{Path, PathBuf};
#[cfg(feature = "qlog")]
use std::sync::Arc;

use n0_error::Result;
#[cfg(feature = "qlog")]
use n0_future::time::Instant;
use quinn::TransportConfig;

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

    /// Creates a [`TransportConfig`] that emits qlog files, if enabled.
    ///
    /// If the "qlog" feature is enabled, and the environment variable IROH_TEST_QLOG is set to "1",
    /// this returns a transport config that writes qlog configs to the configured output directory.
    /// Otherwise, a default transport config is returned.
    pub fn create(&self, name: impl ToString) -> Result<TransportConfig> {
        let config = if std::env::var("IROH_TEST_QLOG").ok().as_deref() == Some("1") {
            self.transport_config(name.to_string())?
        } else {
            TransportConfig::default()
        };
        Ok(config)
    }

    fn transport_config(&self, name: String) -> Result<TransportConfig> {
        let mut transport_config = TransportConfig::default();
        #[cfg(feature = "qlog")]
        {
            let qlog = self.qlog_factory(name);
            transport_config.qlog_factory(Arc::new(qlog));
        }
        Ok(transport_config)
    }

    #[cfg(feature = "qlog")]
    fn qlog_factory(&self, name: String) -> QlogFileFactory {
        let prefix = format!("{}.{}", self.title, name);
        QlogFileFactory::new(self.directory.clone())
            .with_prefix(prefix)
            .with_start_instant(self.start)
    }
}
