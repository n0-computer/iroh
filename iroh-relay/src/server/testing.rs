//! Internal utilities to support testing.
use std::net::Ipv4Addr;

use anyhow::Result;
use tokio::sync::oneshot;

use crate::defaults::DEFAULT_STUN_PORT;

use super::{CertConfig, RelayConfig, Server, ServerConfig, StunConfig, TlsConfig};
use crate::{RelayMap, RelayNode, RelayUrl};

/// A drop guard to clean up test infrastructure.
///
/// After dropping the test infrastructure will asynchronously shutdown and release its
/// resources.
// Nightly sees the sender as dead code currently, but we only rely on Drop of the
// sender.
#[derive(Debug)]
#[allow(dead_code)]
pub struct CleanupDropGuard(pub(crate) oneshot::Sender<()>);

/// Runs a relay server with STUN enabled suitable for tests.
///
/// The returned `Url` is the url of the relay server in the returned [`RelayMap`].
/// When dropped, the returned [`Server`] does will stop running.
pub async fn run_relay_server() -> Result<(RelayMap, RelayUrl, Server)> {
    run_relay_server_with(Some(StunConfig {
        bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
    }))
    .await
}

/// Runs a relay server.
///
/// `stun` can be set to `None` to disable stun, or set to `Some` `StunConfig`,
/// to enable stun on a specific socket.
///
/// The return value is similar to [`run_relay_server`].
pub async fn run_relay_server_with(
    stun: Option<StunConfig>,
) -> Result<(RelayMap, RelayUrl, Server)> {
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("valid");
    let rustls_cert = rustls::pki_types::CertificateDer::from(cert.serialize_der().unwrap());
    let private_key =
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.get_key_pair().serialize_der());
    let private_key = rustls::pki_types::PrivateKeyDer::from(private_key);

    let config = ServerConfig {
        relay: Some(RelayConfig {
            http_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
            tls: Some(TlsConfig {
                cert: CertConfig::<(), ()>::Manual {
                    private_key,
                    certs: vec![rustls_cert],
                },
                https_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
            }),
            limits: Default::default(),
        }),
        stun,
        #[cfg(feature = "metrics")]
        metrics_addr: None,
    };
    let server = Server::spawn(config).await.unwrap();
    let url: RelayUrl = format!("https://{}", server.https_addr().expect("configured"))
        .parse()
        .unwrap();
    let m = RelayMap::from_nodes([RelayNode {
        url: url.clone(),
        stun_only: false,
        stun_port: server.stun_addr().map_or(DEFAULT_STUN_PORT, |s| s.port()),
    }])
    .unwrap();
    Ok((m, url, server))
}
