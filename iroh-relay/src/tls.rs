//! TLS verification configuration for iroh and iroh-relay.

use std::{io, sync::Arc};

use rustls::{
    client::{ClientConfig, WebPkiServerVerifier, danger::ServerCertVerifier},
    crypto::CryptoProvider,
};
use webpki_types::CertificateDer;

/// Configuration for verifying TLS certificates for HTTPS and other non-iroh TLS connections.
#[derive(Debug, Clone)]
pub struct WebTlsConfig {
    inner: ClientConfig,
}

impl Default for WebTlsConfig {
    fn default() -> Self {
        // TODO: Building the default config is fallible if we use system certs.
        // What should we do?
        // - Use WebPki roots by default, then the expect is infallible
        // - Do not provide a default method, have a fallible new()
        WebTlsConfigBuilder::default()
            .build()
            .expect("Failed to build default TLS config")
    }
}

impl WebTlsConfig {
    /// INSECURE: Creates a TLS config that does not verify server certificates at all.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn insecure_skip_verify() -> Self {
        WebTlsConfigBuilder::with_verifier(CaRootConfig::InsecureSkipVerify)
            .build()
            .expect("infallible")
    }

    /// Returns a builder to build a TLS config.
    pub fn builder(verifier: CaRootConfig) -> WebTlsConfigBuilder {
        WebTlsConfigBuilder::with_verifier(verifier)
    }

    /// Returns a reference to the [`rustls::ClientConfig`].
    pub fn inner(&self) -> &ClientConfig {
        &self.inner
    }
}

/// TLS configuration builder.
/// TODO: more docs
#[derive(Debug, Clone)]
pub struct WebTlsConfigBuilder {
    /// Configuration for verifying TLS certificates.
    ///
    /// Note that this is *not* used for iroh connections, but for all other TLS connections.
    pub verifier: Arc<CaRootConfig>,
    /// The crypto provider to use.
    pub crypto_provider: Arc<CryptoProvider>,
}

impl Default for WebTlsConfigBuilder {
    fn default() -> Self {
        Self {
            verifier: Arc::new(CaRootConfig::default()),
            crypto_provider: default_provider(),
        }
    }
}

impl WebTlsConfigBuilder {
    /// Creates a new [`WebTlsConfig`] with a verifier and the default crypto provider.
    pub fn with_verifier(verifier: CaRootConfig) -> Self {
        Self {
            verifier: Arc::new(verifier),
            crypto_provider: default_provider(),
        }
    }

    /// Builds a [`ClientConfig`].
    pub fn build(&self) -> io::Result<WebTlsConfig> {
        let verifier = self.verifier.build(self.crypto_provider.clone())?;
        let config = ClientConfig::builder_with_provider(self.crypto_provider.clone())
            .with_safe_default_protocol_versions()
            .expect("protocols supported by ring")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Ok(WebTlsConfig { inner: config })
    }
}

/// Configures the trust roots for verifying the validity of TLS certificates.
///
/// This is used throughout iroh whenever TLS connections are established that are not iroh connections.
///
/// This includes the connection to iroh relays, to pkarr servers, and DNS resolution over HTTPS.
#[derive(Debug, Clone)]
pub enum CaRootConfig {
    /// Use a compiled-in copy of the root certificates trusted by Mozilla.
    ///
    /// See [`webpki_roots`].
    EmbeddedWebPki {
        /// Additional root certificates to trust.
        extra_roots: Vec<CertificateDer<'static>>,
    },
    /// Use the operating system’s certificate facilities for verifying the validity of TLS certificates.
    ///
    /// See [`rustls_platform_verifier`] for details how roots are retrieved on different platforms.
    System {
        /// Additional root certificates to trust.
        #[cfg(not(target_os = "android"))]
        extra_roots: Vec<CertificateDer<'static>>,
    },
    /// Only trust explicitly set root certificates.
    Custom {
        /// The root certificates to trust.
        roots: Vec<CertificateDer<'static>>,
    },
    /// INSECURE: Do not verify server certificates at all.
    ///
    /// May only be used in tests or local development setups.
    #[cfg(any(test, feature = "test-utils"))]
    InsecureSkipVerify,
}

impl Default for CaRootConfig {
    fn default() -> Self {
        CaRootConfig::EmbeddedWebPki {
            extra_roots: vec![],
        }
    }
}

impl CaRootConfig {
    /// Builds a a [`ServerCertVerifier`] from this config.
    pub fn build(
        &self,
        crypto_provider: Arc<CryptoProvider>,
    ) -> io::Result<Arc<dyn ServerCertVerifier>> {
        Ok(match self {
            #[cfg(not(target_os = "android"))]
            CaRootConfig::System { extra_roots } => Arc::new(
                rustls_platform_verifier::Verifier::new_with_extra_roots(
                    extra_roots.clone(),
                    crypto_provider,
                )
                .map_err(io::Error::other)?,
            ),
            #[cfg(target_os = "android")]
            CaRootConfig::System {} => Arc::new(
                rustls_platform_verifier::Verifier::new(crypto_provider)
                    .map_err(io::Error::other)?,
            ),
            CaRootConfig::EmbeddedWebPki { extra_roots } => {
                let mut root_store = rustls::RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                };
                root_store.add_parsable_certificates(extra_roots.clone());
                WebPkiServerVerifier::builder(Arc::new(root_store))
                    .build()
                    .map_err(io::Error::other)?
            }
            CaRootConfig::Custom { roots } => {
                let mut root_store = rustls::RootCertStore { roots: vec![] };
                root_store.add_parsable_certificates(roots.clone());
                WebPkiServerVerifier::builder(Arc::new(root_store))
                    .build()
                    .map_err(io::Error::other)?
            }
            #[cfg(any(test, feature = "test-utils"))]
            CaRootConfig::InsecureSkipVerify => Arc::new(self::no_cert_verifier::NoCertVerifier),
        })
    }
}

/// Returns iroh's default crypto provider.
///
/// Currently, this is [`rustls::crypto::ring`].
pub fn default_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[cfg(any(test, feature = "test-utils"))]
mod no_cert_verifier {
    use rustls::{
        client::danger::{ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName},
    };

    /// Used to allow self signed certificates in tests
    #[derive(Debug)]
    pub(super) struct NoCertVerifier;

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
            super::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}
