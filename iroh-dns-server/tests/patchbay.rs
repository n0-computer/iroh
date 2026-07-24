//! Patchbay network simulation tests for iroh-dns-server.
//!
//! These tests use the [`patchbay`] crate to create virtual network topologies
//! in Linux user namespaces. They require Linux with user namespace support;
//! on other systems, use the `patchbay` CLI to get a suitable container or VM.
//!
//! To run:
//!
//! ```sh
//! cargo nextest run -p iroh-dns-server --test patchbay --profile patchbay
//! # or via the `cargo make` alias (also runs iroh's patchbay tests):
//! cargo make patchbay
//! ```

// patchbay only runs on linux, and is skipped in cross-compile environments
// via a cfg directive
#![cfg(all(target_os = "linux", not(skip_patchbay)))]

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use iroh_base::SecretKey;
use iroh_dns::{
    dns::{DnsProtocol, DnsResolver},
    pkarr::SignedPacket,
};
use iroh_dns_server::{
    Server,
    config::{Config, MetricsConfig},
};
use n0_error::{Result, StackResultExt, StdResultExt, anyerr, ensure_any};
use n0_tracing_test::traced_test;
use patchbay::{IpSupport, Lab, OutDir};
use testdir::testdir;
use tokio::sync::oneshot;
use tracing::info;

/// Init the user namespace before any threads are spawned.
///
/// This gives us all permissions we need for the patchbay tests.
#[ctor::ctor(unsafe)]
fn userns_ctor() {
    patchbay::init_userns().expect("failed to init userns");
}

/// Ports the server task reports back after binding.
#[derive(Debug, Clone, Copy)]
struct Ports {
    dns: u16,
    http: u16,
    https: u16,
}

/// The default bind addresses accept both IPv4 and IPv6 clients.
///
/// Runs the server with the default listener config (all `bind_addr`s unset,
/// so every listener binds the `::` wildcard; only the data dir and metrics
/// are overridden) on a dual-stack device. A client device then exercises
/// all three listeners once per address family: it publishes a pkarr packet
/// over HTTP, resolves it back over DNS (UDP and TCP), and fetches
/// `/healthz` over HTTPS.
#[tokio::test]
#[traced_test]
async fn default_binds_reachable_v4_and_v6() -> Result {
    let dir = testdir!();
    let mut builder = Lab::builder().outdir(OutDir::Exact(dir.clone()));
    if let Some(name) = std::thread::current().name() {
        builder = builder.label(name);
    }
    let lab = builder.build().await?;
    let guard = lab.test_guard();

    let net = lab
        .add_router("net")
        .ip_support(IpSupport::DualStack)
        .build()
        .await?;
    let dev_server = lab.add_device("dns").uplink(net.id()).build().await?;
    let dev_client = lab.add_device("client").uplink(net.id()).build().await?;

    let server_v4: IpAddr = dev_server.ip().expect("server has IPv4").into();
    let server_v6: IpAddr = dev_server.ip6().expect("server has IPv6").into();

    let data_dir = dir.join("dns-server-data");
    let (ports_tx, ports_rx) = oneshot::channel();
    let mut server_task = dev_server.spawn(move |_dev| async move {
        tokio::fs::create_dir_all(&data_dir)
            .await
            .expect("create data dir");
        let mut config = Config::default();
        config.data_dir = Some(data_dir);
        config.metrics = Some(MetricsConfig::disabled());
        let server = Server::bind(config).await.expect("server bind");
        let ports = Ports {
            dns: server.dns_addr().port(),
            http: server.http_addr().expect("http is bound").port(),
            https: server.https_addr().expect("https is bound").port(),
        };
        ports_tx.send(ports).expect("test task alive");
        server.join().await.expect("server stopped unexpectedly");
    })?;
    let ports = ports_rx
        .await
        .std_context("server task died before binding")?;
    info!(?ports, %server_v4, %server_v6, "server bound with default addresses");

    let client_task = dev_client.spawn(move |_dev| async move {
        for ip in [server_v4, server_v6] {
            check_reachable(ip, ports)
                .await
                .with_context(|_| format!("server not reachable via {ip}"))?;
            info!(%ip, "all listeners reachable");
        }
        n0_error::Ok(())
    })?;
    // Race the client against the server task: the server task runs forever,
    // so it finishing means it panicked. Failing here directly beats letting
    // the client run into timeouts that blame the network.
    tokio::select! {
        res = client_task => res.std_context("client task")??,
        res = &mut server_task => {
            return Err(anyerr!("dns server task exited: {res:?}"));
        }
    }

    guard.ok();
    Ok(())
}

/// Exercises all three listeners on the given server IP.
///
/// Publishes a fresh pkarr packet over HTTP, resolves its TXT record over DNS
/// (UDP), and fetches `/healthz` over HTTPS (accepting the self-signed cert).
/// A fresh key per call keeps the publishes from clashing across families.
async fn check_reachable(ip: IpAddr, ports: Ports) -> Result {
    let host = match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    let secret_key = SecretKey::from_bytes(&rand::random());
    let z32 = secret_key.public().to_z32();
    let txt_value = format!("bind-test={ip}");
    let packet = SignedPacket::from_txt_strings(&secret_key, "_iroh", [&txt_value], 30)
        .context("build signed packet")?;

    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls::insecure_tls_config())
        .timeout(Duration::from_secs(10))
        .build()
        .anyerr()?;

    // HTTP: publish the packet via the pkarr endpoint.
    let url = format!("http://{host}:{}/pkarr/{z32}", ports.http);
    let res = client
        .put(&url)
        .body(packet.to_relay_payload())
        .send()
        .await
        .anyerr()?;
    ensure_any!(
        res.status().is_success(),
        "pkarr publish over HTTP at {url} failed: {}",
        res.status()
    );

    // DNS: resolve the published TXT record, once over UDP and once over TCP
    // (the DNS server binds both on the same address).
    let name = format!("_iroh.{z32}.irohdns.example.");
    for protocol in [DnsProtocol::Udp, DnsProtocol::Tcp] {
        let resolver = DnsResolver::builder()
            .with_nameserver(SocketAddr::new(ip, ports.dns), protocol)
            .build();
        let records: Vec<String> = resolver
            .lookup_txt(&name, Duration::from_secs(5))
            .await
            .with_context(|_| format!("TXT lookup over {protocol:?}"))?
            .map(|record| record.to_string())
            .collect();
        ensure_any!(
            records.contains(&txt_value),
            "TXT lookup over {protocol:?} for {name} returned {records:?}, expected {txt_value:?}"
        );
    }

    // HTTPS: fetch the health endpoint.
    let url = format!("https://{host}:{}/healthz", ports.https);
    let res = client.get(&url).send().await.anyerr()?;
    ensure_any!(
        res.status().is_success(),
        "healthz over HTTPS at {url} failed: {}",
        res.status()
    );

    Ok(())
}

mod tls {
    use std::sync::Arc;

    use rustls::{
        DigitallySignedStruct, RootCertStore,
        client::{
            ClientConfig,
            danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        },
        crypto::{
            CryptoProvider, ring::default_provider, verify_tls12_signature, verify_tls13_signature,
        },
        pki_types::{CertificateDer, ServerName, UnixTime},
    };

    /// Accepts any server certificate; the server uses a self-signed cert.
    #[derive(Debug)]
    struct NoCertificateVerification(CryptoProvider);

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    pub(super) fn insecure_tls_config() -> ClientConfig {
        let provider = default_provider();
        let mut cfg = ClientConfig::builder_with_provider(Arc::new(provider.clone()))
            .with_safe_default_protocol_versions()
            .expect("valid protocol versions")
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        cfg.dangerous()
            .set_certificate_verifier(Arc::new(NoCertificateVerification(provider)));
        cfg
    }
}
