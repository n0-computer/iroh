//! TLS configuration based on libp2p TLS specs.
//!
//! See <https://github.com/libp2p/specs/blob/master/tls/tls.md>.
//! Based on rust-libp2p/transports/tls

use std::sync::Arc;

use crate::key::{PeerId, SecretKey};

pub mod certificate;
mod verifier;

/// Create a TLS client configuration.
///
/// If *keylog* is `true` this will enable logging of the pre-master key to the file in the
/// `SSLKEYLOGFILE` environment variable.  This can be used to inspect the traffic for
/// debugging purposes.
pub fn make_client_config(
    keypair: &SecretKey,
    remote_peer_id: Option<PeerId>,
    alpn_protocols: Vec<Vec<u8>>,
    keylog: bool,
) -> Result<rustls::ClientConfig, certificate::GenError> {
    let (certificate, private_key) = certificate::generate(keypair)?;

    let mut crypto = rustls::ClientConfig::builder()
        .with_cipher_suites(verifier::CIPHERSUITES)
        .with_safe_default_kx_groups()
        .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
        .expect("Cipher suites and kx groups are configured; qed")
        .with_custom_certificate_verifier(Arc::new(
            verifier::Libp2pCertificateVerifier::with_remote_peer_id(remote_peer_id),
        ))
        .with_client_auth_cert(vec![certificate], private_key)
        .expect("Client cert key DER is valid; qed");
    crypto.alpn_protocols = alpn_protocols;
    if keylog {
        crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    Ok(crypto)
}

/// Create a TLS server configuration.
///
/// If *keylog* is `true` this will enable logging of the pre-master key to the file in the
/// `SSLKEYLOGFILE` environment variable.  This can be used to inspect the traffic for
/// debugging purposes.
pub fn make_server_config(
    keypair: &SecretKey,
    alpn_protocols: Vec<Vec<u8>>,
    keylog: bool,
) -> Result<rustls::ServerConfig, certificate::GenError> {
    let (certificate, private_key) = certificate::generate(keypair)?;

    let mut crypto = rustls::ServerConfig::builder()
        .with_cipher_suites(verifier::CIPHERSUITES)
        .with_safe_default_kx_groups()
        .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
        .expect("Cipher suites and kx groups are configured; qed")
        .with_client_cert_verifier(Arc::new(verifier::Libp2pCertificateVerifier::new()))
        .with_single_cert(vec![certificate], private_key)
        .expect("Server cert key DER is valid; qed");
    crypto.alpn_protocols = alpn_protocols;
    if keylog {
        crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }
    Ok(crypto)
}
