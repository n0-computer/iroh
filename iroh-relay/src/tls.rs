//! TLS verification configuration for iroh and iroh-relay.

use std::{io, sync::Arc};

use rustls::{
    client::{ClientConfig, WebPkiServerVerifier, danger::ServerCertVerifier},
    crypto::CryptoProvider,
};
use webpki_types::CertificateDer;

/// Configures the trusted CA root certificates for non-iroh TLS connections.
///
/// These roots are used whenever iroh establishes standard TLS connections to
/// external services, such as iroh relays, pkarr servers, or DNS-over-HTTPS
/// resolvers.
///
/// The configured Certificate Authority (CA) roots are only used for verifying
/// the validity of TLS certificates presented by those external services. These
/// CAs don't need to be trusted for the integrity or authenticity of native
/// iroh connections, which rely on iroh's own cryptographic authentication mechanisms.
#[derive(Debug, Clone)]
pub struct CaRootsConfig {
    mode: Mode,
    extra_roots: Vec<CertificateDer<'static>>,
}

#[derive(derive_more::Debug, Clone)]
enum Mode {
    /// Use a compiled-in copy of the root certificates trusted by Mozilla.
    ///
    /// See [`webpki_roots`].
    EmbeddedWebPki,
    /// Use the operating system's certificate facilities for verifying the validity of TLS certificates.
    ///
    /// See [`rustls_platform_verifier`] for details how roots are retrieved on different platforms.
    #[cfg(feature = "platform-verifier")]
    System,
    /// Only trust explicitly set root certificates.
    ExtraRootsOnly,
    /// INSECURE: Do not verify server certificates at all.
    ///
    /// May only be used in tests or local development setups.
    #[cfg(any(test, feature = "test-utils"))]
    InsecureSkipVerify,
    /// Use a callback to create a [`ClientConfig`] used in all TLS requests.
    Custom {
        #[debug("Arc<dyn Fn>")]
        make_client_config:
            Arc<dyn 'static + Send + Sync + Fn(Arc<CryptoProvider>) -> io::Result<ClientConfig>>,
    },
}

impl Default for CaRootsConfig {
    fn default() -> Self {
        Self {
            mode: Mode::EmbeddedWebPki,
            extra_roots: vec![],
        }
    }
}

impl CaRootsConfig {
    /// Uses the operating system's certificate facilities for verifying the validity of TLS certificates.
    ///
    /// See [`rustls_platform_verifier`] for details how trust anchors are retrieved on different platforms.
    ///
    /// Note: Additional certificates added via [`Self::with_extra_roots`] will be ignored on Android due to
    /// missing support in [`rustls`].
    #[cfg(feature = "platform-verifier")]
    pub fn system() -> Self {
        Self {
            mode: Mode::System,
            extra_roots: Vec::new(),
        }
    }

    /// Uses a compiled-in copy of the root certificates trusted by Mozilla.
    ///
    /// See [`webpki_roots`] for details.
    pub fn embedded() -> Self {
        Self {
            mode: Mode::EmbeddedWebPki,
            extra_roots: Vec::new(),
        }
    }

    /// INSECURE: Do not verify server certificates at all.
    ///
    /// May only be used in tests or local development setups.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn insecure_skip_verify() -> Self {
        Self {
            mode: Mode::InsecureSkipVerify,
            extra_roots: Vec::new(),
        }
    }

    /// Only trusts the explicitly set root certificates.
    pub fn custom_roots(roots: impl IntoIterator<Item = CertificateDer<'static>>) -> Self {
        Self {
            mode: Mode::ExtraRootsOnly,
            extra_roots: roots.into_iter().collect(),
        }
    }

    /// Creates a [`CaRootsConfig`] that uses a callback function to create a [`ClientConfig`].
    ///
    /// This is an advanced feature and you should only use this if none of the other constructor
    /// functions cover your needs. Wrongly implementing the callback may lead to insecure connections
    /// being accepted.
    ///
    /// The [`CryptoProvider`] passed to the callback should be used for all cryptographic operations.
    ///
    /// ## Example
    ///
    /// This example implements the behavior of [`Self::embedded`] via [`Self::custom_client_config_builder`].
    ///
    /// ```rust
    /// # use std::sync::Arc;
    /// # use iroh_relay::tls::CaRootsConfig;
    /// let root_store = Arc::new(rustls::RootCertStore {
    ///     roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    /// });
    /// let ca_roots_config =
    ///     CaRootsConfig::custom_client_config_builder(Arc::new(move |crypto_provider| {
    ///         let client_config = rustls::ClientConfig::builder_with_provider(crypto_provider)
    ///             .with_safe_default_protocol_versions()
    ///             .expect("protocols supported by crypto provider")
    ///             .with_root_certificates(root_store.clone())
    ///             .with_no_client_auth();
    ///         Ok(client_config)
    ///     }));
    /// ```
    pub fn custom_client_config_builder(
        make_client_config: Arc<
            dyn 'static + Send + Sync + Fn(Arc<CryptoProvider>) -> io::Result<ClientConfig>,
        >,
    ) -> Self {
        Self {
            mode: Mode::Custom { make_client_config },
            extra_roots: Vec::new(),
        }
    }

    /// Adds additional root certificates to the list of trusted certificates.
    ///
    /// Ignored when using [`Self::custom_client_config_builder`].
    pub fn with_extra_roots(
        mut self,
        extra_roots: impl IntoIterator<Item = CertificateDer<'static>>,
    ) -> Self {
        self.extra_roots.extend(extra_roots);
        self
    }

    /// Builds a [`ClientConfig`] from this config.
    pub fn client_config(&self, crypto_provider: Arc<CryptoProvider>) -> io::Result<ClientConfig> {
        let verifier: Arc<dyn ServerCertVerifier> = match self.mode {
            #[cfg(feature = "platform-verifier")]
            Mode::System => {
                #[cfg(not(target_os = "android"))]
                let verifier = rustls_platform_verifier::Verifier::new_with_extra_roots(
                    self.extra_roots.clone(),
                    crypto_provider.clone(),
                );
                #[cfg(target_os = "android")]
                let verifier = rustls_platform_verifier::Verifier::new(crypto_provider.clone());
                Arc::new(verifier.map_err(io::Error::other)?)
            }
            Mode::EmbeddedWebPki => {
                let mut root_store = rustls::RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                };
                root_store.add_parsable_certificates(self.extra_roots.clone());
                WebPkiServerVerifier::builder_with_provider(
                    Arc::new(root_store),
                    crypto_provider.clone(),
                )
                .build()
                .map_err(io::Error::other)?
            }
            Mode::ExtraRootsOnly => {
                let mut root_store = rustls::RootCertStore { roots: vec![] };
                root_store.add_parsable_certificates(self.extra_roots.clone());
                WebPkiServerVerifier::builder_with_provider(
                    Arc::new(root_store),
                    crypto_provider.clone(),
                )
                .build()
                .map_err(io::Error::other)?
            }
            #[cfg(any(test, feature = "test-utils"))]
            Mode::InsecureSkipVerify => Arc::new(no_cert_verifier::NoCertVerifier {
                crypto_provider: crypto_provider.clone(),
            }),
            Mode::Custom {
                ref make_client_config,
            } => return make_client_config(crypto_provider),
        };
        let config = ClientConfig::builder_with_provider(crypto_provider)
            .with_safe_default_protocol_versions()
            .expect("protocols supported by ring")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Ok(config)
    }
}

/// Returns the default crypto provider, if enabled via a feature flag.
///
/// Prefers to ring over aws-lc-rs if both are enabled.
#[cfg(feature = "tls-ring")]
pub fn default_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Returns the default crypto provider, if enabled via a feature flag.
///
/// Prefers to ring over aws-lc-rs if both are enabled.
#[cfg(all(feature = "tls-aws-lc-rs", not(feature = "tls-ring")))]
pub fn default_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

#[cfg(all(any(test, feature = "test-utils"), with_crypto_provider))]
/// Creates a client config that trusts any servers without verifying their TLS certificate.
///
/// Should be used for testing local relay setups only.
pub fn make_dangerous_client_config() -> rustls::ClientConfig {
    tracing::warn!(
        "Insecure config: SSL certificates from relay servers will be trusted without verification"
    );
    let crypto_provider = crate::tls::default_provider();
    rustls::client::ClientConfig::builder_with_provider(crypto_provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("protocols supported by ring")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(no_cert_verifier::NoCertVerifier {
            crypto_provider,
        }))
        .with_no_client_auth()
}

#[cfg(any(test, feature = "test-utils"))]
mod no_cert_verifier {
    use std::sync::Arc;

    use rustls::{
        client::danger::{ServerCertVerified, ServerCertVerifier},
        crypto::CryptoProvider,
        pki_types::{CertificateDer, ServerName},
    };

    /// Used to allow self signed certificates in tests
    #[derive(Debug)]
    pub(super) struct NoCertVerifier {
        pub(super) crypto_provider: Arc<CryptoProvider>,
    }

    impl ServerCertVerifier for NoCertVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer,
            _intermediates: &[CertificateDer],
            _server_name: &ServerName,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.crypto_provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}
