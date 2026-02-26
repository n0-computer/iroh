//! TLS verification configuration for iroh and iroh-relay.

use std::{io, sync::Arc};

use rustls::{
    client::{ClientConfig, WebPkiServerVerifier, danger::ServerCertVerifier},
    crypto::CryptoProvider,
};
use webpki_types::CertificateDer;

/// Configures the trust roots for verifying the validity of TLS certificates.
///
/// This is used throughout iroh whenever TLS connections are established that are not iroh connections.
///
/// This includes the connection to iroh relays, to pkarr servers, and DNS resolution over HTTPS.
#[derive(Debug, Clone)]
pub struct CaRootsConfig {
    mode: Mode,
    extra_roots: Vec<CertificateDer<'static>>,
}

#[derive(Debug, Clone)]
enum Mode {
    /// Use a compiled-in copy of the root certificates trusted by Mozilla.
    ///
    /// See [`webpki_roots`].
    EmbeddedWebPki,
    /// Use the operating system’s certificate facilities for verifying the validity of TLS certificates.
    ///
    /// See [`rustls_platform_verifier`] for details how roots are retrieved on different platforms.
    System,
    /// Only trust explicitly set root certificates.
    ExtraRootsOnly,
    /// INSECURE: Do not verify server certificates at all.
    ///
    /// May only be used in tests or local development setups.
    #[cfg(any(test, feature = "test-utils"))]
    InsecureSkipVerify,
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
    /// Use the operating system’s certificate facilities for verifying the validity of TLS certificates.
    ///
    /// See [`rustls_platform_verifier`] for details how roots are retrieved on different platforms.
    pub fn system() -> Self {
        Self {
            mode: Mode::System,
            extra_roots: Vec::new(),
        }
    }

    /// Use a compiled-in copy of the root certificates trusted by Mozilla.
    ///
    /// See [`webpki_roots`].
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

    /// Only trust the explicitly set root certificates.
    pub fn custom(roots: impl IntoIterator<Item = CertificateDer<'static>>) -> Self {
        Self {
            mode: Mode::ExtraRootsOnly,
            extra_roots: roots.into_iter().collect(),
        }
    }

    /// Add additional root certificates to the list of trusted certificates.
    ///
    /// Note: When used with [`Self::system`], the extra certificates will be ignored on Android
    /// due to missing support in `rustls`.
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
            #[cfg(any(test, feature = "test-utils"))]
            Mode::InsecureSkipVerify => Arc::new(self::no_cert_verifier::NoCertVerifier),
        })
    }

    /// Build a [`ClientConfig`] from this config.
    pub fn client_config(&self, crypto_provider: Arc<CryptoProvider>) -> io::Result<ClientConfig> {
        let verifier = self.server_cert_verifier(crypto_provider.clone())?;
        let config = ClientConfig::builder_with_provider(crypto_provider)
            .with_safe_default_protocol_versions()
            .expect("protocols supported by ring")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Ok(config)
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
