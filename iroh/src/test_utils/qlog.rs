//! Utils for emitting qlog files from iroh endpoint.

use std::path::{Path, PathBuf};
#[cfg(feature = "qlog")]
use std::time::Instant;

use n0_error::Result;
use quinn::TransportConfig;
#[cfg(feature = "qlog")]
pub use quinn_proto::{QlogConfig, VantagePointType};

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
            let _ = directory;
            let _ = title;
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

    /// Creates a [`TransportConfig`] that emits qlog files with a client vantage point, if enabled.
    ///
    /// If the "qlog" feature is enabled, and the environment variable IROH_TEST_QLOG is set to "1",
    /// this returns a transport config that writes qlog configs to the configured output directory.
    /// Otherwise, a default transport config is returned.
    pub fn client(&self, name: impl ToString) -> Result<TransportConfig> {
        #[cfg(not(feature = "qlog"))]
        let config = {
            let _ = name;
            TransportConfig::default()
        };

        #[cfg(feature = "qlog")]
        let config = if std::env::var("IROH_TEST_QLOG").ok().as_deref() == Some("1") {
            self.transport_config(name.to_string(), VantagePointType::Client)?
        } else {
            TransportConfig::default()
        };
        Ok(config)
    }

    /// Creates a [`TransportConfig`] that emits qlog files with a server vantage point, if enabled.
    ///
    /// If the "qlog" feature is enabled, and the environment variable IROH_TEST_QLOG is set to "1",
    /// this returns a transport config that writes qlog configs to the configured output directory.
    /// Otherwise, a default transport config is returned.
    pub fn server(&self, name: impl ToString) -> Result<TransportConfig> {
        #[cfg(not(feature = "qlog"))]
        let config = {
            let _ = name;
            TransportConfig::default()
        };

        #[cfg(feature = "qlog")]
        let config = if std::env::var("IROH_TEST_QLOG").ok().as_deref() == Some("1") {
            self.transport_config(name.to_string(), VantagePointType::Server)?
        } else {
            TransportConfig::default()
        };
        Ok(config)
    }

    /// Creates a qlog config with a client vantage point.
    #[cfg(feature = "qlog")]
    pub fn client_config(&self, name: impl ToString) -> Result<QlogConfig> {
        self.qlog_config(name.to_string(), VantagePointType::Client)
    }

    /// Creates a qlog config with a server vantage point.
    #[cfg(feature = "qlog")]
    pub fn server_config(&self, name: impl ToString) -> Result<QlogConfig> {
        self.qlog_config(name.to_string(), VantagePointType::Server)
    }

    /// Creates a qlog config with given vantage point.
    #[cfg(feature = "qlog")]
    pub fn transport_config(
        &self,
        name: String,
        vantage_point: VantagePointType,
    ) -> Result<TransportConfig> {
        let mut transport_config = TransportConfig::default();
        let qlog = self.qlog_config(name, vantage_point)?;
        transport_config.qlog_stream(qlog.into_stream());
        Ok(transport_config)
    }

    #[cfg(feature = "qlog")]
    fn qlog_config(&self, name: String, vantage_point: VantagePointType) -> Result<QlogConfig> {
        let full_name = format!("{}.{}", self.title, name);
        let file_name = format!("{full_name}.qlog");
        let file_path = self.directory.join(file_name);
        std::fs::create_dir_all(file_path.parent().expect("joined above"))?;
        let file = std::fs::File::create(file_path)?;
        let writer = std::io::BufWriter::new(file);

        let mut qlog = quinn::QlogConfig::default();
        qlog.vantage_point(vantage_point, Some(name.clone()))
            .start_time(self.start)
            .writer(Box::new(writer))
            .title(Some(full_name));
        Ok(qlog)
    }
}
