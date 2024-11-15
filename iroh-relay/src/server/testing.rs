//! Exposes functions to quickly configure a server suitable for testing.
use std::net::Ipv4Addr;

use super::{CertConfig, RelayConfig, ServerConfig, StunConfig, TlsConfig};

/// Creates a [`StunConfig`] suitable for testing.
///
/// To ensure port availability for testing, the port is configured to be assigned by the OS.
pub fn stun_config() -> StunConfig {
    StunConfig {
        bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
    }
}

/// Creates a [`TlsConfig`] suitable for testing.
///
/// - Uses a self signed certificate valid for the `"localhost"` and `"127.0.0.1"` domains.
/// - Configures https to be served on an OS assigned port on ipv4.
pub fn tls_config() -> TlsConfig<()> {
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("valid");
    let certs = vec![rustls::pki_types::CertificateDer::from(
        cert.serialize_der().expect("valid cert"),
    )];
    let private_key =
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.get_key_pair().serialize_der());
    let private_key = rustls::pki_types::PrivateKeyDer::from(private_key);
    TlsConfig {
        cert: CertConfig::<(), ()>::Manual { private_key, certs },
        https_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
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
    }
}

/// Creates a [`ServerConfig`] suitable for testing.
///
/// - Relaying is enabled using [`relay_config`]
/// - Stun is enabled using [`stun_config`]
/// - Metrics are not enabled.
pub fn server_config() -> ServerConfig<()> {
    ServerConfig {
        relay: Some(relay_config()),
        stun: Some(stun_config()),
        #[cfg(feature = "metrics")]
        metrics_addr: None,
    }
}
