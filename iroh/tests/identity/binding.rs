//! Identity pins must survive address reuse and prior successful connections.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use iroh::{
    endpoint::QuicTransportConfig,
    identity::{Error, IdentityEndpoint, LocalIdentity, Registry, TrustStore},
};

const ALPN: &[u8] = b"identity-binding/1";

async fn bind(address: SocketAddr, registry: Arc<Registry>) -> IdentityEndpoint {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("identity.key");
    LocalIdentity::generate_ml_dsa65(&registry)
        .unwrap()
        .save(&path)
        .unwrap();
    let identity = LocalIdentity::load(&path, &registry).unwrap();
    IdentityEndpoint::builder(identity, registry)
        .bind_addr(address)
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
async fn rotating_the_key_at_the_same_address_requires_a_new_identity_pin() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
        let server = bind("127.0.0.1:0".parse().unwrap(), registry.clone()).await;
        let client = bind("127.0.0.1:0".parse().unwrap(), registry.clone()).await;
        let old_contact = server.addr().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trust");
        let mut trust = TrustStore::default();
        trust.trust("service", old_contact.id).unwrap();
        trust.save(&path).unwrap();

        // Authenticate the explicitly pinned old identity in a real handshake.
        let (outgoing, incoming) =
            tokio::join!(client.connect(old_contact.clone(), ALPN), server.accept());
        let outgoing = outgoing.unwrap();
        let incoming = incoming.unwrap();
        assert_eq!(outgoing.remote_id(), old_contact.id);
        server.close().await;
        drop(outgoing);
        drop(incoming);
        drop(server);

        // Reuse the exact listening address with a fresh, valid PQ identity.
        // Keep the original client, including any state from the first dial.
        let replacement = bind(old_contact.addr, registry).await;
        let new_contact = replacement.addr().unwrap();
        assert_eq!(old_contact.addr, new_contact.addr);
        assert_ne!(old_contact.id, new_contact.id);
        let (outgoing, incoming) = tokio::join!(
            client.connect(old_contact.clone(), ALPN),
            replacement.accept()
        );
        assert!(
            matches!(
                outgoing,
                Err(Error::Connection(noq::ConnectionError::TransportError(_)))
            ),
            "a stale pin must fail during authentication: {outgoing:?}"
        );
        assert!(incoming.is_err());

        // Only an explicit application-approved migration changes the persisted pin.
        let mut trust = TrustStore::load(&path).unwrap();
        assert_eq!(trust.get("service"), Some(old_contact.id));
        trust
            .migrate("service", old_contact.id, new_contact.id)
            .unwrap();
        trust.save(&path).unwrap();
        let trust = TrustStore::load(&path).unwrap();
        let mut approved_contact = new_contact.clone();
        approved_contact.id = trust.get("service").unwrap();
        let (outgoing, incoming) =
            tokio::join!(client.connect(approved_contact, ALPN), replacement.accept());
        let outgoing = outgoing.unwrap();
        let incoming = incoming.unwrap();
        assert_eq!(outgoing.remote_id(), new_contact.id);
        assert_eq!(incoming.remote_id(), client.id());
        let mut send = outgoing.open_uni().await.unwrap();
        send.write_all(b"new identity explicitly trusted")
            .await
            .unwrap();
        send.finish().unwrap();
        let mut recv = incoming.accept_uni().await.unwrap();
        assert_eq!(
            recv.read_to_end(64).await.unwrap(),
            b"new identity explicitly trusted"
        );
        tokio::join!(client.close(), replacement.close());
    })
    .await
    .expect("identity rotation test timed out");
}
