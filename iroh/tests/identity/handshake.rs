use std::{sync::Arc, time::Duration};

use iroh::endpoint::QuicTransportConfig;
use iroh::identity::{EndpointAddr, IdentityEndpoint, LocalIdentity, PeerId, Registry};
use iroh_base::SecretKey;

async fn endpoint(pq: bool, allowed: Vec<u16>) -> IdentityEndpoint {
    let registry = Arc::new(Registry::builtins(allowed).unwrap());
    let identity = if pq {
        LocalIdentity::generate_ml_dsa65(&registry).unwrap()
    } else {
        LocalIdentity::ed25519(SecretKey::generate(), &registry).unwrap()
    };
    bind(identity, registry).await
}

async fn bind(identity: LocalIdentity, registry: Arc<Registry>) -> IdentityEndpoint {
    bind_with_idle(identity, registry, Some(Duration::from_secs(3))).await
}

async fn bind_with_idle(
    identity: LocalIdentity,
    registry: Arc<Registry>,
    idle: Option<Duration>,
) -> IdentityEndpoint {
    IdentityEndpoint::builder(identity, registry)
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .alpns(vec![b"identity-test/1".to_vec()])
        .transport_config(
            QuicTransportConfig::builder()
                .max_idle_timeout(idle.map(|idle| idle.try_into().unwrap()))
                .build(),
        )
        .bind()
        .await
        .unwrap()
}

#[tokio::test]
async fn accepted_connections_expose_the_negotiated_protocol() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
        let protocols = vec![b"identity-test/1".to_vec(), b"identity-test/2".to_vec()];
        let server = IdentityEndpoint::builder(
            LocalIdentity::generate_ml_dsa65(&registry).unwrap(),
            registry,
        )
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .alpns(protocols.clone())
        .bind()
        .await
        .unwrap();
        let client = endpoint(true, vec![2]).await;
        for protocol in protocols {
            let (outgoing, incoming) = tokio::join!(
                client.connect(server.addr().unwrap(), &protocol),
                server.accept()
            );
            assert_eq!(outgoing.unwrap().alpn(), protocol);
            assert_eq!(incoming.unwrap().alpn(), protocol);
        }
        tokio::join!(client.close(), server.close());
    })
    .await
    .expect("protocol dispatch timeout");
}

#[tokio::test]
async fn direct_candidates_race_unusable_relay_hints() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
        let (relay, url) = super::relay::relay(registry.clone()).await;
        // Accept TCP connections but never complete relay registration.
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent_url: iroh::RelayUrl = format!("http://{}/", silent.local_addr().unwrap())
            .parse()
            .unwrap();
        for (hint, configured) in [
            (url, false),
            (silent_url.clone(), true),
            (silent_url, false),
        ] {
            let server = endpoint(true, vec![2]).await;
            let mut builder = IdentityEndpoint::builder(
                LocalIdentity::generate_ml_dsa65(&registry).unwrap(),
                registry.clone(),
            )
            .bind_addr("127.0.0.1:0".parse().unwrap())
            .transport_config(
                QuicTransportConfig::builder()
                    .max_idle_timeout(None)
                    .build(),
            );
            if configured {
                builder = builder.relay_mode(iroh::RelayMode::Custom(iroh::RelayMap::from_iter([
                    hint.clone(),
                ])));
            }
            let client = builder.bind().await.unwrap();
            let mut address = server.addr().unwrap();
            address.addrs.insert(iroh::TransportAddr::Relay(hint));
            let (outgoing, incoming) =
                tokio::join!(client.connect(address, b"identity-test/1"), server.accept());
            assert_eq!(outgoing.unwrap().remote_id(), server.id());
            assert_eq!(incoming.unwrap().remote_id(), client.id());
            tokio::join!(client.close(), server.close());
        }
        relay.shutdown().await.unwrap();
    })
    .await
    .expect("direct connection delayed by relay hint");
}

#[tokio::test]
async fn mutual_authentication_and_data_for_both_suites() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for pq in [false, true] {
            let server = endpoint(pq, vec![1, 2]).await;
            let client = endpoint(pq, vec![1, 2]).await;
            let (outgoing, incoming) = tokio::join!(
                client.connect(server.addr().unwrap(), b"identity-test/1"),
                server.accept()
            );
            let outgoing = outgoing.unwrap();
            let incoming = incoming.unwrap();
            assert_eq!(outgoing.remote_id(), server.id());
            assert_eq!(incoming.remote_id(), client.id());
            let mut send = outgoing.open_uni().await.unwrap();
            send.write_all(b"authenticated").await.unwrap();
            send.finish().unwrap();
            let mut recv = incoming.accept_uni().await.unwrap();
            assert_eq!(recv.read_to_end(64).await.unwrap(), b"authenticated");
            client.close().await;
            server.close().await;
        }
    })
    .await
    .expect("handshake timeout");
}

#[tokio::test]
async fn direct_candidates_skip_unbound_families_and_race_silent_addresses() {
    for unbound_family in [true, false] {
        // Keep this socket bound throughout the test without answering packets.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let first = if unbound_family {
            "[::1]:9".parse().unwrap()
        } else {
            silent.local_addr().unwrap()
        };
        let server = endpoint(true, vec![2]).await;
        // The client never times out an attempt. If connect waited for the
        // silent candidate, this test would hang instead of passing late.
        let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
        let identity = LocalIdentity::generate_ml_dsa65(&registry).unwrap();
        let client = bind_with_idle(identity, registry, None).await;
        let mut address = EndpointAddr::new(server.id(), first);
        address
            .addrs
            .insert(iroh::TransportAddr::Ip(server.local_addr().unwrap()));
        let (outgoing, incoming) =
            tokio::join!(client.connect(address, b"identity-test/1"), server.accept());
        assert_eq!(outgoing.unwrap().remote_id(), server.id());
        assert_eq!(incoming.unwrap().remote_id(), client.id());
        client.close().await;
        server.close().await;
    }
}

#[tokio::test]
async fn all_direct_candidates_must_authenticate_the_expected_identity() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let first = endpoint(true, vec![2]).await;
        let second = endpoint(true, vec![2]).await;
        let client = endpoint(true, vec![2]).await;
        let mut address = EndpointAddr::new(PeerId::V1([0x55; 48]), first.local_addr().unwrap());
        address
            .addrs
            .insert(iroh::TransportAddr::Ip(second.local_addr().unwrap()));
        let (outgoing, first_incoming, second_incoming) = tokio::join!(
            client.connect(address, b"identity-test/1"),
            first.accept(),
            second.accept()
        );
        assert!(outgoing.is_err());
        assert!(first_incoming.is_err());
        assert!(second_incoming.is_err());
        client.close().await;
        first.close().await;
        second.close().await;
    })
    .await
    .expect("candidate authentication timeout");
}

#[tokio::test]
async fn wrong_identity_and_legacy_substitution_fail() {
    tokio::time::timeout(Duration::from_secs(30), async {
        // Both implementations support both schemes. An expected PQ identity
        // must still reject an otherwise valid Ed25519 server.
        for pq_server in [false, true] {
            let server = endpoint(pq_server, vec![1, 2]).await;
            let client = endpoint(true, vec![1, 2]).await;
            let expected = PeerId::V1([0x55; 48]);
            let (outgoing, incoming) = tokio::join!(
                client.connect(
                    EndpointAddr::new(expected, server.local_addr().unwrap()),
                    b"identity-test/1"
                ),
                server.accept()
            );
            assert!(outgoing.is_err());
            assert!(incoming.is_err());
            client.close().await;
            server.close().await;
        }
    })
    .await
    .expect("handshake timeout");
}

#[tokio::test]
async fn pq_only_policy_rejects_legacy_clients() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let server = endpoint(true, vec![2]).await;
        let client = endpoint(false, vec![1, 2]).await;
        let (outgoing, incoming) = tokio::join!(
            client.connect(server.addr().unwrap(), b"identity-test/1"),
            server.accept()
        );
        assert!(incoming.is_err());
        // TLS can let the client finish before it learns that client auth failed.
        if let Ok(outgoing) = outgoing {
            outgoing.closed().await;
        }
        client.close().await;
        server.close().await;
    })
    .await
    .expect("handshake timeout");
}

#[tokio::test]
async fn pq_only_policy_rejects_legacy_servers() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let server = endpoint(false, vec![1, 2]).await;
        let client = endpoint(true, vec![2]).await;
        let (outgoing, incoming) = tokio::join!(
            client.connect(server.addr().unwrap(), b"identity-test/1"),
            server.accept()
        );
        assert!(outgoing.is_err());
        assert!(incoming.is_err());
        client.close().await;
        server.close().await;
    })
    .await
    .expect("handshake timeout");
}

#[derive(Debug)]
struct BadKey(Arc<dyn rustls::sign::SigningKey>);

impl rustls::sign::SigningKey for BadKey {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        self.0
            .choose_scheme(offered)
            .map(|signer| Box::new(BadSignature(signer)) as Box<dyn rustls::sign::Signer>)
    }
    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.0.algorithm()
    }
    fn public_key(&self) -> Option<rustls::pki_types::SubjectPublicKeyInfoDer<'_>> {
        self.0.public_key()
    }
}

#[derive(Debug)]
struct BadSignature(Box<dyn rustls::sign::Signer>);

impl rustls::sign::Signer for BadSignature {
    fn scheme(&self) -> rustls::SignatureScheme {
        self.0.scheme()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut signature = self.0.sign(message)?;
        signature[0] ^= 1;
        Ok(signature)
    }
}

#[tokio::test]
async fn matching_identity_with_corrupted_tls_signature_fails() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
        let pair =
            aws_lc_rs::signature::PqdsaKeyPair::generate(&aws_lc_rs::signature::ML_DSA_65_SIGNING)
                .unwrap();
        let der = pair.to_pkcs8v1().unwrap();
        let private = rustls::pki_types::PrivatePkcs8KeyDer::from(der.as_ref().to_vec());
        let key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&private.into()).unwrap();
        let identity = LocalIdentity::new(Arc::new(BadKey(key)), &registry).unwrap();
        let server = bind(identity, registry).await;
        let client = endpoint(true, vec![2]).await;
        let (outgoing, incoming) = tokio::join!(
            client.connect(server.addr().unwrap(), b"identity-test/1"),
            server.accept()
        );
        assert!(outgoing.is_err());
        assert!(incoming.is_err());
        client.close().await;
        server.close().await;
    })
    .await
    .expect("handshake timeout");
}
