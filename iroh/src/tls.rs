//! TLS configuration for iroh.
//!
//! Currently there are two mechanisms available
//! - Raw Public Keys, using the TLS extension described in [RFC 7250]
//! - libp2p-tls, based on <https://github.com/libp2p/specs/blob/master/tls/tls.md>.
//!
//! [RFC 7250]: https://datatracker.ietf.org/doc/html/rfc7250

use std::sync::Arc;

use iroh_base::{PublicKey, SecretKey};
use quinn::crypto::rustls::{NoInitialCipherSuite, QuicClientConfig, QuicServerConfig};
use tracing::warn;

use self::resolver::AlwaysResolvesCert;

pub mod certificate;
mod resolver;
mod verifier;

/// TLS Authentication mechanism
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum Authentication {
    /// Self signed certificates, based on libp2p-tls
    #[default]
    X509,
    /// RFC 7250 TLS extension: Raw Public Keys.
    RawPublicKey,
}

impl Authentication {
    /// Create a TLS client configuration.
    ///
    /// If *keylog* is `true` this will enable logging of the pre-master key to the file in the
    /// `SSLKEYLOGFILE` environment variable.  This can be used to inspect the traffic for
    /// debugging purposes.
    pub fn make_client_config(
        self,
        secret_key: &SecretKey,
        remote_peer_id: Option<PublicKey>,
        alpn_protocols: Vec<Vec<u8>>,
        session_store: Option<Arc<dyn rustls::client::ClientSessionStore>>,
        keylog: bool,
    ) -> Result<QuicClientConfig, CreateConfigError> {
        let cert_resolver = Arc::new(
            AlwaysResolvesCert::new(self, secret_key).expect("Client cert key DER is valid; qed"),
        );

        let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
        .expect("version supported by ring")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(
            verifier::CertificateVerifier::with_remote_peer_id(self, remote_peer_id),
        ))
        .with_client_cert_resolver(cert_resolver);
        crypto.alpn_protocols = alpn_protocols;
        if let Some(store) = session_store {
            crypto.resumption = rustls::client::Resumption::store(store);
            crypto.enable_early_data = true;
        }
        if keylog {
            warn!("enabling SSLKEYLOGFILE for TLS pre-master keys");
            crypto.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        let config = crypto.try_into()?;
        Ok(config)
    }

    /// Create a TLS server configuration.
    ///
    /// If *keylog* is `true` this will enable logging of the pre-master key to the file in the
    /// `SSLKEYLOGFILE` environment variable.  This can be used to inspect the traffic for
    /// debugging purposes.
    pub fn make_server_config(
        self,
        secret_key: &SecretKey,
        alpn_protocols: Vec<Vec<u8>>,
        keylog: bool,
    ) -> Result<QuicServerConfig, CreateConfigError> {
        let cert_resolver = Arc::new(
            AlwaysResolvesCert::new(self, secret_key).expect("Server cert key DER is valid; qed"),
        );

        let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
        .expect("fixed config")
        .with_client_cert_verifier(Arc::new(verifier::CertificateVerifier::new(self)))
        .with_cert_resolver(cert_resolver);
        crypto.alpn_protocols = alpn_protocols;
        if keylog {
            warn!("enabling SSLKEYLOGFILE for TLS pre-master keys");
            crypto.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        // must be u32::MAX or 0 (the default). Any other value panics with QUIC
        // This is specified in RFC 9001: https://www.rfc-editor.org/rfc/rfc9001#section-4.6.1
        crypto.max_early_data_size = u32::MAX;

        let config = crypto.try_into()?;
        Ok(config)
    }
}

/// Error for generating TLS configs.
#[derive(Debug, thiserror::Error)]
pub enum CreateConfigError {
    /// Error generating the certificate.
    #[error("Error generating the certificate")]
    CertError(#[from] certificate::GenError),
    /// Error creating QUIC config.
    #[error("Error creating QUIC config")]
    ConfigError(#[from] NoInitialCipherSuite),
    /// Rustls configuration error
    #[error("rustls error")]
    Rustls(#[from] rustls::Error),
}
