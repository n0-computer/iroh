//! Exposes functions to quickly configure a server suitable for testing.
use std::net::Ipv4Addr;

use super::{AccessConfig, CertConfig, QuicConfig, RelayConfig, ServerConfig, TlsConfig};

/// Creates a [`rustls::ServerConfig`] and certificates suitable for testing.
///
/// - Uses a self signed certificate valid for the `"localhost"` and `"127.0.0.1"` domains.
pub fn self_signed_tls_certs_and_config() -> (
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::ServerConfig,
) {
    let cert = rcgen::generate_simple_self_signed(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ])
    .expect("valid");
    let rustls_cert = cert.cert.der();
    let private_key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let private_key = rustls::pki_types::PrivateKeyDer::from(private_key);
    let certs = vec![rustls_cert.clone()];
    let server_config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocols supported by ring")
    .with_no_client_auth();

    let server_config = server_config
        .with_single_cert(certs.clone(), private_key)
        .expect("valid");
    (certs, server_config)
}

/// Creates a [`TlsConfig`] suitable for testing.
///
/// - Uses a self signed certificate valid for the `"localhost"` and `"127.0.0.1"` domains.
/// - Configures https to be served on an OS assigned port on ipv4.
pub fn tls_config() -> TlsConfig<()> {
    let (certs, server_config) = self_signed_tls_certs_and_config();
    TlsConfig {
        server_config,
        cert: CertConfig::<(), ()>::Manual { certs },
        https_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
        quic_bind_addr: (Ipv4Addr::UNSPECIFIED, 0).into(),
    }
}

/// Creates a [`RelayConfig`] suitable for testing.
///
/// - Binds http to an OS assigned port on ipv4.
/// - Uses [`tls_config`] to enable TLS.
/// - Uses default limits.
pub fn relay_config() -> RelayConfig<()> {
    RelayConfig {
        http_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
        tls: Some(tls_config()),
        limits: Default::default(),
        key_cache_capacity: Some(1024),
        access: AccessConfig::Everyone,
    }
}

/// Creates a [`QuicConfig`] suitable for testing.
///
/// - Binds to an OS assigned port on ipv4
/// - Uses [`self_signed_tls_certs_and_config`] to create tls certificates
pub fn quic_config() -> QuicConfig {
    let (_, server_config) = self_signed_tls_certs_and_config();
    QuicConfig {
        bind_addr: (Ipv4Addr::UNSPECIFIED, 0).into(),
        server_config,
    }
}

/// Creates a [`ServerConfig`] suitable for testing.
///
/// - Relaying is enabled using [`relay_config`]
/// - QUIC addr discovery is disabled.
/// - Metrics are not enabled.
pub fn server_config() -> ServerConfig<()> {
    ServerConfig {
        relay: Some(relay_config()),
        quic: Some(quic_config()),
        #[cfg(feature = "metrics")]
        metrics_addr: None,
    }
}
