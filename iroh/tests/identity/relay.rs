use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use iroh::identity::{IdentityEndpoint, LocalIdentity, Registry, RemotePolicy};
use iroh::{Endpoint, RelayMap, RelayMode, RelayUrl, endpoint::presets::Empty};
use iroh_relay::server::{RelayConfig, Server, ServerConfig};

pub(super) async fn relay(registry: Arc<Registry>) -> (Server, RelayUrl) {
    let mut config = ServerConfig::default();
    config.relay = Some(RelayConfig::new((Ipv4Addr::LOCALHOST, 0)));
    let server = Server::spawn(config).await.unwrap();
    let url: RelayUrl = format!("http://{}/", server.http_addr().unwrap())
        .parse()
        .unwrap();
    server
        .relay_service()
        .unwrap()
        .enable_identity(iroh_relay::identity::Service::new(
            url.clone(),
            registry,
            32,
        ))
        .unwrap();
    (server, url)
}

#[tokio::test]
async fn relay_upgrade_limits_ignore_forwarded_headers() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
        let (relay, url) = relay(registry).await;
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .build()
            .unwrap();
        let upgrade_url = format!(
            "{}{}",
            url.as_str().trim_end_matches('/'),
            iroh_relay::identity::PATH
        );
        let mut sessions = Vec::new();
        // Hold incomplete registrations open to exhaust the source's 16 slots.
        // Distinct forwarding headers must not create distinct source quotas.
        for n in 0..=16 {
            let response = client
                .get(&upgrade_url)
                .header("X-Forwarded-For", format!("192.0.2.{n}"))
                .header("Upgrade", "websocket")
                .header("Connection", "upgrade")
                .header("Sec-WebSocket-Version", "13")
                .header("Sec-WebSocket-Protocol", iroh_relay::identity::PROTOCOL)
                .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
                .send()
                .await
                .unwrap();
            if n < 16 {
                assert_eq!(response.status(), reqwest::StatusCode::SWITCHING_PROTOCOLS);
                sessions.push(response.upgrade().await.unwrap());
            } else {
                assert_eq!(response.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
            }
        }
        drop(sessions);
        relay.shutdown().await.unwrap();
    })
    .await
    .expect("relay admission test timeout");
}

#[tokio::test]
async fn legacy_and_pq_protocols_coexist_on_one_relay_server() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (relay, url) = relay(Arc::new(Registry::builtins(vec![1, 2]).unwrap())).await;
        let pq_server = endpoint(url.clone(), true, vec![2]).await;
        let pq_client = endpoint(url.clone(), true, vec![2]).await;
        let (pq_out, pq_in) = tokio::join!(
            pq_client.connect(pq_server.addr().unwrap(), b"identity-relay-test/1"),
            pq_server.accept()
        );
        let (pq_out, pq_in) = (pq_out.unwrap(), pq_in.unwrap());
        let mut legacy = Vec::new();
        for _ in 0..2 {
            let endpoint = Endpoint::builder(Empty)
                .clear_ip_transports()
                .crypto_provider(iroh::tls::default_provider())
                .relay_mode(RelayMode::Custom(RelayMap::from_iter([url.clone()])))
                .alpns(vec![b"legacy-relay-test/1".to_vec()])
                .bind()
                .await
                .unwrap();
            endpoint.online().await;
            legacy.push(endpoint);
        }
        let (old_out, old_in) = tokio::join!(
            legacy[0].connect(legacy[1].addr(), b"legacy-relay-test/1"),
            async { legacy[1].accept().await.unwrap().await }
        );
        let (old_out, old_in) = (old_out.unwrap(), old_in.unwrap());
        let mut old_send = old_out.open_uni().await.unwrap();
        old_send
            .write_all(b"unchanged legacy relay protocol")
            .await
            .unwrap();
        old_send.finish().unwrap();
        assert_eq!(
            old_in
                .accept_uni()
                .await
                .unwrap()
                .read_to_end(64)
                .await
                .unwrap(),
            b"unchanged legacy relay protocol"
        );
        let mut pq_send = pq_out.open_uni().await.unwrap();
        pq_send.write_all(b"PQ remains connected").await.unwrap();
        pq_send.finish().unwrap();
        assert_eq!(
            pq_in
                .accept_uni()
                .await
                .unwrap()
                .read_to_end(64)
                .await
                .unwrap(),
            b"PQ remains connected"
        );
        for endpoint in legacy {
            endpoint.close().await;
        }
        pq_client.close().await;
        pq_server.close().await;
        relay.shutdown().await.unwrap();
    })
    .await
    .expect("coexisting relay protocol timeout");
}

async fn endpoint(url: RelayUrl, pq: bool, allowed: Vec<u16>) -> IdentityEndpoint {
    let registry = Arc::new(Registry::builtins(vec![1, 2]).unwrap());
    let identity = if pq {
        LocalIdentity::generate_ml_dsa65(&registry).unwrap()
    } else {
        LocalIdentity::ed25519(iroh::SecretKey::generate(), &registry).unwrap()
    };
    Endpoint::builder(Empty)
        .clear_ip_transports()
        .credentials(identity, registry)
        .remote_policy(RemotePolicy::new(allowed))
        .relay_mode(RelayMode::Custom(RelayMap::from_iter([url])))
        .alpns(vec![b"identity-relay-test/1".to_vec()])
        .bind()
        .await
        .unwrap()
}

#[tokio::test]
async fn pq_and_mixed_identities_authenticate_without_ip_sockets() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (relay, url) = relay(Arc::new(Registry::builtins(vec![1, 2]).unwrap())).await;
        for (server_pq, client_pq) in [(true, true), (true, false), (false, true), (false, false)] {
            let server = endpoint(url.clone(), server_pq, vec![1, 2]).await;
            let client =
                endpoint(url.clone(), client_pq, vec![if server_pq { 2 } else { 1 }]).await;
            assert!(server.local_addr().is_err());
            assert!(client.local_addr().is_err());
            let (outgoing, incoming) = tokio::join!(
                client.connect(server.addr().unwrap(), b"identity-relay-test/1"),
                server.accept()
            );
            let outgoing = outgoing.unwrap();
            let incoming = incoming.unwrap();
            assert_eq!(outgoing.remote_id(), server.id());
            assert_eq!(incoming.remote_id(), client.id());
            let mut send = outgoing.open_uni().await.unwrap();
            send.write_all(b"PQ identity through relay").await.unwrap();
            send.finish().unwrap();
            assert_eq!(
                incoming
                    .accept_uni()
                    .await
                    .unwrap()
                    .read_to_end(128)
                    .await
                    .unwrap(),
                b"PQ identity through relay"
            );
            client.close().await;
            server.close().await;
        }
        relay.shutdown().await.unwrap();
    })
    .await
    .expect("relay test timeout");
}

#[tokio::test]
async fn relay_restart_preserves_the_authenticated_quic_connection() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
        let (relay, url) = relay(registry.clone()).await;
        let address = relay.http_addr().unwrap();
        let server = endpoint(url.clone(), true, vec![2]).await;
        let client = endpoint(url.clone(), true, vec![2]).await;
        let (outgoing, incoming) = tokio::join!(
            client.connect(server.addr().unwrap(), b"identity-relay-test/1"),
            server.accept()
        );
        let outgoing = outgoing.unwrap();
        let incoming = incoming.unwrap();
        relay.shutdown().await.unwrap();
        let mut config = ServerConfig::default();
        config.relay = Some(RelayConfig::new(address));
        let replacement = Server::spawn(config).await.unwrap();
        replacement
            .relay_service()
            .unwrap()
            .enable_identity(iroh_relay::identity::Service::new(url, registry, 32))
            .unwrap();
        let mut send = outgoing.open_uni().await.unwrap();
        send.write_all(b"after restart").await.unwrap();
        send.finish().unwrap();
        assert_eq!(
            incoming
                .accept_uni()
                .await
                .unwrap()
                .read_to_end(64)
                .await
                .unwrap(),
            b"after restart"
        );
        assert_eq!(incoming.remote_id(), client.id());
        assert_eq!(outgoing.remote_id(), server.id());
        client.close().await;
        server.close().await;
        replacement.shutdown().await.unwrap();
    })
    .await
    .expect("relay reconnect timeout");
}

#[tokio::test]
async fn relay_transport_cannot_bypass_endpoint_peer_authorization() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let registry = Arc::new(Registry::builtins(vec![1, 2]).unwrap());
        let (relay, url) = relay(registry.clone()).await;
        let approved = LocalIdentity::generate_ml_dsa65(&registry).unwrap();
        let identity = LocalIdentity::generate_ml_dsa65(&registry).unwrap();
        let server = Endpoint::builder(Empty)
            .clear_ip_transports()
            .credentials(identity, registry)
            .remote_policy(RemotePolicy::new([2]).allow_peers([approved.id()]))
            .relay_mode(RelayMode::Custom(RelayMap::from_iter([url.clone()])))
            .alpns(vec![b"identity-relay-test/1".to_vec()])
            .bind()
            .await
            .unwrap();
        for pq in [true, false] {
            let client = endpoint(url.clone(), pq, vec![2]).await;
            let (outgoing, incoming) = tokio::join!(
                client.connect(server.addr().unwrap(), b"identity-relay-test/1"),
                server.accept()
            );
            assert!(incoming.is_err());
            if let Ok(connection) = outgoing {
                connection.closed().await;
            }
            client.close().await;
        }
        server.close().await;
        relay.shutdown().await.unwrap();
    })
    .await
    .expect("relay policy timeout");
}

#[tokio::test]
async fn relay_registration_enforces_algorithm_and_peer_policy() {
    let registry = Arc::new(Registry::builtins(vec![1, 2]).unwrap());
    let approved = LocalIdentity::generate_ml_dsa65(&registry).unwrap();
    let stranger = LocalIdentity::generate_ml_dsa65(&registry).unwrap();
    let legacy = LocalIdentity::ed25519(iroh::SecretKey::generate(), &registry).unwrap();
    let policy = Arc::new(
        (*registry)
            .clone()
            .with_remote_policy(RemotePolicy::new([2]).allow_peers([approved.id()]))
            .unwrap(),
    );
    let (relay, url) = relay(policy).await;
    let tls = Arc::new(
        iroh_relay::tls::CaTlsConfig::default()
            .client_config(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .unwrap(),
    );
    for denied in [stranger, legacy] {
        assert!(
            iroh_relay::identity::Client::connect(&url, &denied, tls.clone())
                .await
                .is_err()
        );
    }
    // A proven credential may register again after a silent disconnect: the
    // relay replaces the stale session instead of locking the identity out.
    let stale = iroh_relay::identity::Client::connect(&url, &approved, tls.clone())
        .await
        .unwrap();
    let (_stale_tx, stale_rx) = tokio::sync::mpsc::channel(1);
    let (stale_in, _) = tokio::sync::mpsc::channel(1);
    let stale_session = tokio::spawn(stale.run(stale_rx, stale_in));
    let _fresh = iroh_relay::identity::Client::connect(&url, &approved, tls)
        .await
        .unwrap();
    assert!(stale_session.await.unwrap().is_err());
    relay.shutdown().await.unwrap();
}
