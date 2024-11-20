//! TLS configuration based on libp2p TLS specs.
//!
//! See <https://github.com/libp2p/specs/blob/master/tls/tls.md>.
//! Based on rust-libp2p/transports/tls

use std::sync::Arc;

use quinn::crypto::rustls::{NoInitialCipherSuite, QuicClientConfig, QuicServerConfig};
use tracing::warn;

use self::certificate::AlwaysResolvesCert;
use crate::key::{PublicKey, SecretKey};

pub mod certificate;
mod verifier;

/// Error for generating iroh p2p TLS configs.
#[derive(Debug, thiserror::Error)]
pub enum CreateConfigError {
    /// Error generating the certificate.
    #[error("Error generating the certificate")]
    CertError(#[from] certificate::GenError),
    /// Error creating QUIC config.
    #[error("Error creating QUIC config")]
    ConfigError(#[from] NoInitialCipherSuite),
}

/// Create a TLS client configuration.
///
/// If *keylog* is `true` this will enable logging of the pre-master key to the file in the
/// `SSLKEYLOGFILE` environment variable.  This can be used to inspect the traffic for
/// debugging purposes.
pub fn make_client_config(
    secret_key: &SecretKey,
    remote_peer_id: Option<PublicKey>,
    alpn_protocols: Vec<Vec<u8>>,
    keylog: bool,
) -> Result<QuicClientConfig, CreateConfigError> {
    let (certificate, secret_key) = certificate::generate(secret_key)?;

    let cert_resolver = Arc::new(
        AlwaysResolvesCert::new(certificate, &secret_key)
            .expect("Client cert key DER is valid; qed"),
    );

    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
    .expect("version supported by ring")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(
        verifier::Libp2pCertificateVerifier::with_remote_peer_id(remote_peer_id),
    ))
    .with_client_cert_resolver(cert_resolver);
    crypto.alpn_protocols = alpn_protocols;
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
    secret_key: &SecretKey,
    alpn_protocols: Vec<Vec<u8>>,
    keylog: bool,
) -> Result<QuicServerConfig, CreateConfigError> {
    let (certificate, secret_key) = certificate::generate(secret_key)?;

    let cert_resolver = Arc::new(
        AlwaysResolvesCert::new(certificate, &secret_key)
            .expect("Server cert key DER is valid; qed"),
    );

    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
    .expect("fixed config")
    .with_client_cert_verifier(Arc::new(verifier::Libp2pCertificateVerifier::new()))
    .with_cert_resolver(cert_resolver);
    crypto.alpn_protocols = alpn_protocols;
    if keylog {
        warn!("enabling SSLKEYLOGFILE for TLS pre-master keys");
        crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }
    let config = crypto.try_into()?;
    Ok(config)
}
