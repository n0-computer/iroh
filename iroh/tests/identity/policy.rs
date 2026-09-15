//! Local credentials and remote signature policy are independent choices.

use std::{sync::Arc, time::Duration};

use iroh::{
    SecretKey,
    endpoint::QuicTransportConfig,
    identity::{
        BuiltinAlgorithm, Error, IdentityAlgorithm, IdentityEndpoint, LocalIdentity, Registry,
    },
};

const ALPN: &[u8] = b"identity-policy/1";

async fn endpoint(local_pq: bool, remote_suite: u16) -> IdentityEndpoint {
    let registry = Arc::new(Registry::builtins(vec![remote_suite]).unwrap());
    let identity = if local_pq {
        LocalIdentity::generate_ml_dsa65(&registry).unwrap()
    } else {
        LocalIdentity::ed25519(SecretKey::generate(), &registry).unwrap()
    };
    IdentityEndpoint::builder(identity, registry)
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .alpns(vec![ALPN.to_vec()])
        .transport_config(
            QuicTransportConfig::builder()
                .max_idle_timeout(Some(Duration::from_secs(3).try_into().unwrap()))
                .build(),
        )
        .bind()
        .await
        .unwrap()
}

#[tokio::test]
async fn different_local_and_remote_suites_authenticate_in_both_directions() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let legacy = endpoint(false, 2).await;
        let pq = endpoint(true, 1).await;
        for (client, server) in [(&legacy, &pq), (&pq, &legacy)] {
            let (outgoing, incoming) = tokio::join!(
                client.connect(server.addr().unwrap(), ALPN),
                server.accept()
            );
            let outgoing = outgoing.unwrap();
            let incoming = incoming.unwrap();
            assert_eq!(outgoing.remote_id(), server.id());
            assert_eq!(incoming.remote_id(), client.id());
            let mut send = outgoing.open_uni().await.unwrap();
            send.write_all(b"independent policies").await.unwrap();
            send.finish().unwrap();
            let mut recv = incoming.accept_uni().await.unwrap();
            assert_eq!(recv.read_to_end(64).await.unwrap(), b"independent policies");
            outgoing.close(0u32.into(), b"done");
        }
        tokio::join!(legacy.close(), pq.close());
    })
    .await
    .expect("mixed policy handshake timeout");
}

#[tokio::test]
async fn local_credential_does_not_allow_that_suite_for_remote_peers() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for (local_pq, allowed_remote_suite) in [(false, 2), (true, 1)] {
            let client = endpoint(local_pq, allowed_remote_suite).await;
            let server = endpoint(local_pq, allowed_remote_suite).await;
            let (outgoing, incoming) = tokio::join!(
                client.connect(server.addr().unwrap(), ALPN),
                server.accept()
            );
            assert!(outgoing.is_err());
            assert!(incoming.is_err());
            tokio::join!(client.close(), server.close());
        }
    })
    .await
    .expect("remote policy rejection timeout");
}

#[tokio::test]
async fn local_credentials_still_require_a_registered_adapter() {
    let registry =
        Arc::new(Registry::new(vec![Arc::new(BuiltinAlgorithm::MlDsa65)], vec![2]).unwrap());
    let key = SecretKey::generate();
    assert!(LocalIdentity::ed25519(key.clone(), &registry).is_err());
    let identity = LocalIdentity::ed25519(key, &Registry::builtins(vec![2]).unwrap()).unwrap();
    let result = IdentityEndpoint::builder(identity, registry)
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .bind()
        .await;
    assert!(matches!(result, Err(Error::PublicIdentity)));
}

#[derive(Debug)]
struct RemappedSuite;

impl IdentityAlgorithm for RemappedSuite {
    fn suite_id(&self) -> u16 {
        500
    }
    fn tls_scheme(&self) -> rustls::SignatureScheme {
        rustls::SignatureScheme::ML_DSA_65
    }
    fn public_key<'a>(&self, spki: &'a [u8]) -> Result<&'a [u8], Error> {
        BuiltinAlgorithm::MlDsa65.public_key(spki)
    }
    fn verify(&self, key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
        BuiltinAlgorithm::MlDsa65.verify(key, message, signature)
    }
}

#[tokio::test]
async fn binding_registry_cannot_reinterpret_the_local_identity() {
    let identity = LocalIdentity::generate_ml_dsa65(&Registry::builtins(vec![2]).unwrap()).unwrap();
    let registry = Arc::new(Registry::new(vec![Arc::new(RemappedSuite)], vec![500]).unwrap());
    let result = IdentityEndpoint::builder(identity, registry)
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .bind()
        .await;
    assert!(matches!(result, Err(Error::IdentityMismatch)));
}
