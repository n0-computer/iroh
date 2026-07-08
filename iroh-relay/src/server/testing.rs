//! Exposes functions to quickly configure a server suitable for testing.
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use super::{AllowAll, CertConfig, QuicConfig, RelayConfig, ServerConfig, TlsConfig};

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

/// Creates a WebTransport-compatible self-signed certificate and a matching
/// [`rustls::ServerConfig`], returning the certificate DER alongside the config.
///
/// Browsers accept a self-signed WebTransport server certificate only when it is
/// passed by SHA-256 hash via `serverCertificateHashes`, which the [W3C
/// WebTransport spec] restricts to ECDSA P-256 certificates with a validity
/// period of at most two weeks. [`self_signed_tls_certs_and_config`] produces a
/// long-lived certificate that browsers reject, so this helper generates an
/// ECDSA P-256 certificate valid for 13 days. The returned certificate DER is
/// what the browser client hashes with SHA-256.
///
/// [W3C WebTransport spec]: https://www.w3.org/TR/webtransport/#dom-webtransporthash-value
pub fn webtransport_self_signed_tls_certs_and_config() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::ServerConfig,
) {
    let mut params = rcgen::CertificateParams::new(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ])
    .expect("valid subject alt names");
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(13);
    // `KeyPair::generate` defaults to ECDSA P-256, which is what the browser
    // requires for the `serverCertificateHashes` mechanism.
    let key_pair = rcgen::KeyPair::generate().expect("keypair generation");
    let cert = params
        .self_signed(&key_pair)
        .expect("self-signed certificate");
    let cert_der = cert.der().clone();

    let private_key = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    let private_key = rustls::pki_types::PrivateKeyDer::from(private_key);
    let server_config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocols supported by ring")
    .with_no_client_auth()
    .with_single_cert(vec![cert_der.clone()], private_key)
    .expect("valid");
    (cert_der, server_config)
}

/// Creates a full relay [`ServerConfig`] serving WebTransport with a
/// browser-compatible self-signed certificate.
///
/// The relay is bound to `https_bind_addr` (TCP for HTTPS/WebSocket and, since
/// the H3/WebTransport server reuses the HTTPS bind address, UDP for
/// WebTransport). QUIC address discovery is disabled. Returns the certificate
/// DER so a browser WebTransport client can pass its SHA-256 hash via
/// `serverCertificateHashes`.
///
/// Used by the `wasm_relay` example that backs the browser WebTransport tests.
pub fn webtransport_server_config(
    https_bind_addr: impl Into<SocketAddr>,
) -> (rustls::pki_types::CertificateDer<'static>, ServerConfig) {
    let (cert_der, server_config) = webtransport_self_signed_tls_certs_and_config();
    let tls = TlsConfig {
        cert: CertConfig::Manual { server_config },
        https_bind_addr: https_bind_addr.into(),
    };
    let relay = RelayConfig {
        http_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
        tls: Some(tls),
        limits: Default::default(),
        key_cache_capacity: Some(1024),
        access: Arc::new(AllowAll),
    };
    let config = ServerConfig {
        relay: Some(relay),
        quic: None,
        #[cfg(feature = "metrics")]
        metrics_addr: None,
    };
    (cert_der, config)
}

/// Creates a [`TlsConfig`] suitable for testing.
///
/// - Uses a self signed certificate valid for the `"localhost"` and `"127.0.0.1"` domains.
/// - Configures https to be served on an OS assigned port on ipv4.
pub fn tls_config() -> TlsConfig {
    let (_certs, server_config) = self_signed_tls_certs_and_config();
    TlsConfig {
        cert: CertConfig::Manual { server_config },
        https_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
    }
}

/// Creates a [`RelayConfig`] suitable for testing.
///
/// - Binds http to an OS assigned port on ipv4.
/// - Uses [`tls_config`] to enable TLS.
/// - Uses default limits.
pub fn relay_config() -> RelayConfig {
    RelayConfig {
        http_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
        tls: Some(tls_config()),
        limits: Default::default(),
        key_cache_capacity: Some(1024),
        access: Arc::new(AllowAll),
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
        server_config: Some(server_config),
    }
}

/// Creates a [`ServerConfig`] suitable for testing.
///
/// - Relaying is enabled using [`relay_config`]
/// - QUIC addr discovery is disabled.
/// - Metrics are not enabled.
pub fn server_config() -> ServerConfig {
    ServerConfig {
        relay: Some(relay_config()),
        quic: Some(quic_config()),
        #[cfg(feature = "metrics")]
        metrics_addr: None,
    }
}
