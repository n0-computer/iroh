//! Options for creating a report gen client.

pub(crate) use imp::Options;

#[cfg(not(wasm_browser))]
mod imp {
    use std::collections::BTreeSet;

    use crate::net_report::{NetReportConfig, QuicConfig, probes::Probe};

    /// Options for running probes
    ///
    /// By default, will run Https probes.
    ///
    /// Use [`Options::quic_config`] to enable  QUIC address discovery.
    #[derive(Debug, Clone)]
    pub(crate) struct Options {
        /// The configuration needed to launch QUIC address discovery probes.
        ///
        /// If not provided, will not run QUIC address discovery.
        pub(crate) quic_config: Option<QuicConfig>,
        /// TLS config for HTTPS probes.
        pub(crate) tls_config: rustls::ClientConfig,
        /// User-facing configuration.
        pub(crate) user_config: NetReportConfig,
    }

    impl Options {
        pub(crate) fn new(tls_config: rustls::ClientConfig) -> Self {
            Self {
                quic_config: None,
                tls_config,
                user_config: NetReportConfig::default(),
            }
        }
        /// Enable quic probes
        pub(crate) fn quic_config(mut self, quic_config: Option<QuicConfig>) -> Self {
            self.quic_config = quic_config;
            self
        }

        /// Set the net report configuration.
        pub(crate) fn net_report_config(mut self, config: NetReportConfig) -> Self {
            self.user_config = config;
            self
        }

        /// Turn the options into set of valid protocols
        pub(crate) fn as_protocols(&self) -> BTreeSet<Probe> {
            let mut protocols = BTreeSet::new();
            if let Some(ref quic) = self.quic_config {
                if quic.ipv4 {
                    protocols.insert(Probe::QadIpv4);
                }
                if quic.ipv6 {
                    protocols.insert(Probe::QadIpv6);
                }
            }
            if self.user_config.https_probes {
                protocols.insert(Probe::Https);
            }
            protocols
        }
    }
}

#[cfg(wasm_browser)]
mod imp {
    use std::collections::BTreeSet;

    use crate::net_report::{NetReportConfig, Probe};

    /// Options for running probes (in browsers).
    ///
    /// Only HTTPS probes are supported in browsers.
    /// These are run by default.
    #[derive(Debug, Clone)]
    pub(crate) struct Options {
        /// User-facing configuration.
        pub(crate) user_config: NetReportConfig,
    }

    impl Default for Options {
        fn default() -> Self {
            Self {
                user_config: NetReportConfig::default(),
            }
        }
    }

    impl Options {
        /// Set the net report configuration.
        pub(crate) fn net_report_config(mut self, config: NetReportConfig) -> Self {
            self.user_config = config;
            self
        }

        /// Turn the options into set of valid protocols
        pub(crate) fn as_protocols(&self) -> BTreeSet<Probe> {
            let mut protocols = BTreeSet::new();
            if self.user_config.https_probes {
                protocols.insert(Probe::Https);
            }
            protocols
        }
    }
}
