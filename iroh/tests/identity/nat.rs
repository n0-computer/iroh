//! Real network namespace NAT test; run with the same capabilities as `patchbay`.
#![cfg(all(feature = "unstable-identity", target_os = "linux", not(skip_patchbay)))]

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use iroh::identity::{EndpointAddr, LocalIdentity, Registry, RemotePolicy};
use iroh::{Endpoint, RelayMap, RelayMode, RelayUrl, endpoint::presets::Empty};
use iroh_relay::server::{QuicConfig, RelayConfig, Server, ServerConfig};
use patchbay::{Lab, Nat};
use tokio::sync::oneshot;

#[tokio::test]
async fn pq_identity_holepunches_between_two_port_restricted_nats() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (lab, guard) = Lab::for_test(testdir::testdir!()).await.unwrap();
        let dc = lab.add_router("dc").build().await.unwrap();
        let relay_device = lab
            .add_device("relay")
            .uplink(dc.id())
            .build()
            .await
            .unwrap();
        let router_a = lab
            .add_router("nat-a")
            .nat(Nat::Moderate)
            .build()
            .await
            .unwrap();
        let router_b = lab
            .add_router("nat-b")
            .nat(Nat::Moderate)
            .build()
            .await
            .unwrap();
        let device_a = lab
            .add_device("peer-a")
            .uplink(router_a.id())
            .build()
            .await
            .unwrap();
        let device_b = lab
            .add_device("peer-b")
            .uplink(router_b.id())
            .build()
            .await
            .unwrap();
        let (relay_tx, relay_rx) = oneshot::channel();
        let (stop_tx, stop_rx) = oneshot::channel();
        let relay_task = relay_device
            .spawn(async move |device| {
                let mut config = ServerConfig::default();
                config.relay = Some(RelayConfig::new((Ipv4Addr::UNSPECIFIED, 0)));
                let (_, tls) = iroh_relay::server::testing::self_signed_tls_certs_and_config();
                let mut qad = QuicConfig::new((Ipv4Addr::UNSPECIFIED, 0));
                qad.server_config = Some(tls);
                config.quic = Some(qad);
                let server = Server::spawn(config).await.unwrap();
                let url: RelayUrl = format!(
                    "http://{}:{}/",
                    device.ip().unwrap(),
                    server.http_addr().unwrap().port()
                )
                .parse()
                .unwrap();
                let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
                server
                    .relay_service()
                    .unwrap()
                    .enable_identity(iroh_relay::identity::Service::new(
                        url.clone(),
                        registry,
                        32,
                    ))
                    .unwrap();
                let map = RelayMap::from_iter([iroh_relay::RelayConfig::new(
                    url.clone(),
                    Some(iroh_relay::RelayQuicConfig::new(
                        server.quic_addr().unwrap().port(),
                    )),
                )]);
                relay_tx.send((url, map)).unwrap();
                let _ = stop_rx.await;
                server.shutdown().await.unwrap();
            })
            .unwrap();
        let (url, map) = relay_rx.await.unwrap();
        let (contact_tx, contact_rx) = oneshot::channel();
        let map_a = map.clone();
        let server = device_a
            .spawn(async move |_device| {
                let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
                let identity = LocalIdentity::generate_ml_dsa65(&registry).unwrap();
                let endpoint = Endpoint::builder(Empty)
                    .credentials(identity, registry)
                    .remote_policy(RemotePolicy::new([2]))
                    .relay_mode(RelayMode::Custom(map_a))
                    .ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify())
                    .alpns(vec![b"pq-nat/1".to_vec()])
                    .bind()
                    .await
                    .unwrap();
                contact_tx
                    .send(EndpointAddr::relay(endpoint.id(), url))
                    .unwrap();
                let conn = endpoint.accept().await.unwrap();
                conn.wait_direct().await.unwrap();
                assert!(conn.is_direct());
                let message = conn
                    .accept_uni()
                    .await
                    .unwrap()
                    .read_to_end(128)
                    .await
                    .unwrap();
                assert_eq!(message, b"PQ authentication survived NAT traversal");
                let mut ack = conn.open_uni().await.unwrap();
                ack.write_all(b"ok").await.unwrap();
                ack.finish().unwrap();
                conn.closed().await;
                endpoint.close().await;
            })
            .unwrap();
        let client = device_b
            .spawn(async move |_device| {
                let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
                let identity = LocalIdentity::generate_ml_dsa65(&registry).unwrap();
                let endpoint = Endpoint::builder(Empty)
                    .credentials(identity, registry)
                    .remote_policy(RemotePolicy::new([2]))
                    .relay_mode(RelayMode::Custom(map))
                    .ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify())
                    .bind()
                    .await
                    .unwrap();
                let contact = contact_rx.await.unwrap();
                let expected = contact.id;
                let conn = endpoint.connect(contact, b"pq-nat/1").await.unwrap();
                assert_eq!(conn.remote_id(), expected);
                conn.wait_direct().await.unwrap();
                assert!(conn.is_direct());
                let mut stream = conn.open_uni().await.unwrap();
                stream
                    .write_all(b"PQ authentication survived NAT traversal")
                    .await
                    .unwrap();
                stream.finish().unwrap();
                assert_eq!(
                    conn.accept_uni()
                        .await
                        .unwrap()
                        .read_to_end(16)
                        .await
                        .unwrap(),
                    b"ok"
                );
                conn.close(0u32.into(), b"done");
                endpoint.close().await;
            })
            .unwrap();
        client.await.unwrap();
        server.await.unwrap();
        stop_tx.send(()).unwrap();
        relay_task.await.unwrap();
        guard.ok();
    })
    .await
    .expect("NAT traversal timeout");
}
