//! Options for creating a report gen client.

pub(crate) use imp::Options;

#[cfg(not(wasm_browser))]
mod imp {
    use std::collections::BTreeSet;

    use crate::net_report::{QuicConfig, probes::Probe};

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
        /// Enable https probes
        ///
        /// On by default
        pub(crate) https: bool,

        #[cfg(any(test, feature = "test-utils"))]
        pub(crate) insecure_skip_relay_cert_verify: bool,
    }

    impl Default for Options {
        fn default() -> Self {
            Self {
                quic_config: None,
                https: true,
                #[cfg(any(test, feature = "test-utils"))]
                insecure_skip_relay_cert_verify: false,
            }
        }
    }

    impl Options {
        /// Enable quic probes
        pub(crate) fn quic_config(mut self, quic_config: Option<QuicConfig>) -> Self {
            self.quic_config = quic_config;
            self
        }

        /// Skip cert verification
        #[cfg(any(test, feature = "test-utils"))]
        pub(crate) fn insecure_skip_relay_cert_verify(mut self, skip: bool) -> Self {
            self.insecure_skip_relay_cert_verify = skip;
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
            if self.https {
                protocols.insert(Probe::Https);
            }
            protocols
        }
    }
}

#[cfg(wasm_browser)]
mod imp {
    use std::collections::BTreeSet;

    use crate::net_report::Probe;

    /// Options for running probes (in browsers).
    ///
    /// Only HTTPS probes are supported in browsers.
    /// These are run by default.
    #[derive(Debug, Clone)]
    pub(crate) struct Options {
        /// Enable https probes
        ///
        /// On by default
        pub(crate) https: bool,
    }

    impl Default for Options {
        fn default() -> Self {
            Self { https: true }
        }
    }

    impl Options {
        /// Create an [`Options`] that disables all probes
        pub(crate) fn disabled() -> Self {
            Self { https: false }
        }

        /// Enable or disable https probe
        pub(crate) fn https(mut self, enable: bool) -> Self {
            self.https = enable;
            self
        }

        /// Turn the options into set of valid protocols
        pub(crate) fn as_protocols(&self) -> BTreeSet<Probe> {
            let mut protocols = BTreeSet::new();
            if self.https {
                protocols.insert(Probe::Https);
            }
            protocols
        }
    }
}
