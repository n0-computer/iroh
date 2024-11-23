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

/// Generate a TLS [`QuicClientConfig`] that contains webpki root certificates
pub fn make_client_config_pki() -> Result<QuicClientConfig, CreateConfigError> {
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let quic_client_config = QuicClientConfig::try_from(config)?;
    Ok(quic_client_config)
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

/// Generate a [`quinn::ClientConfig`] with self-signed certificate for testing
/// local setups.
///
/// Has QUIC address discovery enabled.
pub fn generate_local_client_config() -> anyhow::Result<quinn::ClientConfig> {
    let cert = rcgen::generate_simple_self_signed(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ])
    .expect("valid");
    let cert = cert.cert.der();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone())?;
    let config = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    let config = quinn_proto::crypto::rustls::QuicClientConfig::try_from(config).unwrap();
    let mut transport = quinn_proto::TransportConfig::default();
    // enable address discovery
    transport.receive_observed_address_reports(true);

    let mut client_config = quinn::ClientConfig::new(Arc::new(config));
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}
