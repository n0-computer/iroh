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
pub struct CaTlsConfig {
    mode: Mode,
    extra_roots: Vec<CertificateDer<'static>>,
}

/// Renamed to [`CaTlsConfig`].
#[deprecated(since = "1.0.0", note = "Renamed to `CaTlsConfig`")]
pub type CaRootsConfig = CaTlsConfig;

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
    /// Use a callback to create a [`ServerCertVerifier`].
    CustomServerCertVerifier {
        #[debug("Arc<dyn Fn>")]
        builder: ServerCertVerifierBuilder,
    },
    /// INSECURE: Do not verify server certificates at all.
    ///
    /// May only be used in tests or local development setups.
    #[cfg(any(test, feature = "test-utils"))]
    InsecureSkipVerify,
}

impl Default for CaTlsConfig {
    fn default() -> Self {
        Self {
            mode: Mode::EmbeddedWebPki,
            extra_roots: vec![],
        }
    }
}

impl CaTlsConfig {
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

    /// Renamed to [`Self::custom_roots`].
    #[deprecated(since = "1.0.0", note = "Renamed to `custom_roots`")]
    pub fn custom(roots: impl IntoIterator<Item = CertificateDer<'static>>) -> Self {
        Self::custom_roots(roots)
    }

    /// Creates a [`CaTlsConfig`] that uses a callback function to create a [`ServerCertVerifier`].
    ///
    /// This is an advanced feature and you should only use this if none of the other constructor
    /// functions cover your needs. Wrongly implementing the callback may lead to insecure connections
    /// being accepted.
    ///
    /// The [`CryptoProvider`] passed to the callback should be used for all cryptographic operations.
    ///
    /// ## Example
    ///
    /// This example implements the behavior of [`Self::embedded`] via [`Self::custom_server_cert_verifier`].
    ///
    /// ```rust
    /// # use std::{io, sync::Arc};
    /// # use iroh_relay::tls::CaTlsConfig;
    /// # use rustls::client::WebPkiServerVerifier;
    /// let tls_config = CaTlsConfig::custom_server_cert_verifier(Arc::new(move |crypto_provider| {
    ///     let root_store = Arc::new(rustls::RootCertStore {
    ///         roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    ///     });
    ///     let verifier = WebPkiServerVerifier::builder_with_provider(root_store, crypto_provider)
    ///         .build()
    ///         .map_err(io::Error::other)?;
    ///     Ok(verifier)
    /// }));
    /// ```
    pub fn custom_server_cert_verifier(builder: ServerCertVerifierBuilder) -> Self {
        Self {
            mode: Mode::CustomServerCertVerifier { builder },
            extra_roots: Vec::new(),
        }
    }

    /// Adds additional root certificates to the list of trusted certificates.
    ///
    /// Ignored when using [`Self::custom_server_cert_verifier`].
    pub fn with_extra_roots(
        mut self,
        extra_roots: impl IntoIterator<Item = CertificateDer<'static>>,
    ) -> Self {
        self.extra_roots.extend(extra_roots);
        self
    }

    /// Builds a [`ServerCertVerifier`] from this config.
    pub fn server_cert_verifier(
        &self,
        crypto_provider: Arc<CryptoProvider>,
    ) -> io::Result<Arc<dyn ServerCertVerifier>> {
        Ok(match self.mode {
            #[cfg(feature = "platform-verifier")]
            Mode::System => {
                #[cfg(not(target_os = "android"))]
                let verifier = rustls_platform_verifier::Verifier::new_with_extra_roots(
                    self.extra_roots.clone(),
                    crypto_provider,
                );
                #[cfg(target_os = "android")]
                let verifier = rustls_platform_verifier::Verifier::new(crypto_provider);
                Arc::new(verifier.map_err(io::Error::other)?)
            }
            Mode::EmbeddedWebPki => {
                let mut root_store = rustls::RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                };
                root_store.add_parsable_certificates(self.extra_roots.clone());
                WebPkiServerVerifier::builder_with_provider(Arc::new(root_store), crypto_provider)
                    .build()
                    .map_err(io::Error::other)?
            }
            Mode::ExtraRootsOnly => {
                let mut root_store = rustls::RootCertStore { roots: vec![] };
                root_store.add_parsable_certificates(self.extra_roots.clone());
                WebPkiServerVerifier::builder_with_provider(Arc::new(root_store), crypto_provider)
                    .build()
                    .map_err(io::Error::other)?
            }
            Mode::CustomServerCertVerifier { ref builder } => builder(crypto_provider)?,
            #[cfg(any(test, feature = "test-utils"))]
            Mode::InsecureSkipVerify => {
                tracing::warn!(
                    "Insecure TLS config: server certificates will be trusted without verification"
                );
                Arc::new(no_cert_verifier::NoCertVerifier { crypto_provider })
            }
        })
    }

    /// Builds a [`ClientConfig`] from this config.
    pub fn client_config(&self, crypto_provider: Arc<CryptoProvider>) -> io::Result<ClientConfig> {
        let verifier = self.server_cert_verifier(crypto_provider.clone())?;
        let config = ClientConfig::builder_with_provider(crypto_provider)
            .with_safe_default_protocol_versions()
            .expect(
                "configured crypto provider is missing support for required TLS protocol versions",
            )
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Ok(config)
    }
}

/// Function to build a [`ServerCertVerifier`] from a [`CryptoProvider`].
///
/// See [`CaTlsConfig::custom_server_cert_verifier].
pub type ServerCertVerifierBuilder = Arc<
    dyn Fn(Arc<CryptoProvider>) -> io::Result<Arc<dyn ServerCertVerifier>> + Send + Sync + 'static,
>;

/// Returns the default crypto provider, if enabled via a feature flag.
///
/// Prefers `ring` over `aws-lc-rs` if both are enabled.
#[cfg(feature = "tls-ring")]
pub fn default_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Returns the default crypto provider, if enabled via a feature flag.
///
/// Prefers `ring` over `aws-lc-rs` if both are enabled.
#[cfg(all(feature = "tls-aws-lc-rs", not(feature = "tls-ring")))]
pub fn default_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Creates a client config that trusts any servers without verifying their TLS certificate.
///
/// Should be used for testing local relay setups only.
#[cfg(all(any(test, feature = "test-utils"), with_crypto_provider))]
pub fn make_dangerous_client_config() -> ClientConfig {
    CaTlsConfig::insecure_skip_verify()
        .client_config(default_provider())
        .expect("infallible")
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
