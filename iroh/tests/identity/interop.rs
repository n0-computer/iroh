use std::{sync::Arc, time::Duration};

use iroh::{
    Endpoint, SecretKey,
    endpoint::presets,
    identity::{Error, IdentityEndpoint, LocalIdentity, PeerId, Registry},
};

const ALPN: &[u8] = b"identity-interop/1";

#[tokio::test]
async fn connections_keep_the_runtime_alive_after_endpoint_handles_are_dropped() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
        let server = IdentityEndpoint::builder(
            LocalIdentity::generate_ml_dsa65(&registry).unwrap(),
            registry.clone(),
        )
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
        let client = IdentityEndpoint::builder(
            LocalIdentity::generate_ml_dsa65(&registry).unwrap(),
            registry,
        )
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .bind()
        .await
        .unwrap();
        let (outgoing, incoming) = tokio::join!(
            client.connect(server.addr().unwrap(), ALPN),
            server.accept()
        );
        let outgoing = outgoing.unwrap();
        let incoming = incoming.unwrap();
        drop(client);
        drop(server);
        let mut send = outgoing.open_uni().await.unwrap();
        send.write_all(b"still alive").await.unwrap();
        send.finish().unwrap();
        let mut recv = incoming.accept_uni().await.unwrap();
        assert_eq!(recv.read_to_end(64).await.unwrap(), b"still alive");
        outgoing.close(0u32.into(), b"done");
        incoming.closed().await;
    })
    .await
    .expect("connection lifetime timeout");
}

#[tokio::test]
async fn direct_ipv6_authentication() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
        let server = IdentityEndpoint::builder(
            LocalIdentity::generate_ml_dsa65(&registry).unwrap(),
            registry.clone(),
        )
        .bind_addr("[::1]:0".parse().unwrap())
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await;
        let server = match server {
            Ok(server) => server,
            Err(Error::Io(error))
                if error.kind() == std::io::ErrorKind::AddrNotAvailable
                    || error.kind() == std::io::ErrorKind::Unsupported =>
            {
                return;
            }
            Err(error) => panic!("IPv6 bind failed: {error}"),
        };
        let client = IdentityEndpoint::builder(
            LocalIdentity::generate_ml_dsa65(&registry).unwrap(),
            registry,
        )
        .bind_addr("[::1]:0".parse().unwrap())
        .bind()
        .await
        .unwrap();
        let (outgoing, incoming) = tokio::join!(
            client.connect(server.addr().unwrap(), ALPN),
            server.accept()
        );
        assert_eq!(outgoing.unwrap().remote_id(), server.id());
        assert_eq!(incoming.unwrap().remote_id(), client.id());
        tokio::join!(client.close(), server.close());
    })
    .await
    .expect("IPv6 handshake timeout");
}

#[tokio::test]
async fn legacy_endpoint_and_identity_endpoint_interoperate_in_both_directions() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let old_key = SecretKey::generate();
        let old = Endpoint::builder(presets::Empty)
            .crypto_provider(iroh::tls::default_provider())
            .secret_key(old_key.clone())
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let registry = Arc::new(Registry::builtins(vec![1, 2]).unwrap());
        let new_key = SecretKey::generate();
        let new = IdentityEndpoint::builder(
            LocalIdentity::ed25519(new_key.clone(), &registry).unwrap(),
            registry,
        )
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap();

        // The old public API is used unchanged, including address and remote_id types.
        let address =
            iroh::EndpointAddr::new(new_key.public()).with_ip_addr(new.local_addr().unwrap());
        let (outgoing, incoming) = tokio::join!(old.connect(address, ALPN), new.accept());
        let outgoing = outgoing.unwrap();
        let incoming = incoming.unwrap();
        assert_eq!(outgoing.remote_id(), new_key.public());
        assert_eq!(incoming.remote_id(), PeerId::Legacy(old.id()));
        let mut send = outgoing.open_uni().await.unwrap();
        send.write_all(b"old to new").await.unwrap();
        send.finish().unwrap();
        let mut recv = incoming.accept_uni().await.unwrap();
        assert_eq!(recv.read_to_end(64).await.unwrap(), b"old to new");
        outgoing.close(0u32.into(), b"done");

        // The direct binding is known locally; no discovery backend is needed.
        let old_addr = old.bound_sockets().into_iter().next().unwrap();
        let address = iroh::identity::EndpointAddr::new(old.id().into(), old_addr);
        let (outgoing, incoming) = tokio::join!(new.connect(address, ALPN), async {
            old.accept().await.unwrap().await
        });
        let outgoing = outgoing.unwrap();
        let incoming = incoming.unwrap();
        assert_eq!(outgoing.remote_id(), PeerId::Legacy(old.id()));
        assert_eq!(incoming.remote_id(), new_key.public());
        let mut send = outgoing.open_uni().await.unwrap();
        send.write_all(b"new to old").await.unwrap();
        send.finish().unwrap();
        let mut recv = incoming.accept_uni().await.unwrap();
        assert_eq!(recv.read_to_end(64).await.unwrap(), b"new to old");
        tokio::join!(new.close(), old.close());
    })
    .await
    .expect("interop timeout");
}

#[tokio::test]
async fn closing_a_clone_wakes_accept_and_closes_the_shared_endpoint() {
    let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
    let identity = LocalIdentity::generate_ml_dsa65(&registry).unwrap();
    let endpoint = IdentityEndpoint::builder(identity, registry)
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .bind()
        .await
        .unwrap();
    let clone = endpoint.clone();
    tokio::time::timeout(Duration::from_secs(5), async {
        let (accepted, ()) = tokio::join!(endpoint.accept(), clone.close());
        assert!(matches!(accepted, Err(Error::Closed)));
        endpoint.close().await;
    })
    .await
    .expect("close timeout");
}

#[tokio::test]
async fn builder_and_connect_validate_configuration() {
    let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
    let identity = LocalIdentity::generate_ml_dsa65(&registry).unwrap();
    assert!(matches!(
        IdentityEndpoint::builder(identity.clone(), registry.clone())
            .bind()
            .await,
        Err(Error::BindAddr)
    ));
    assert!(matches!(
        IdentityEndpoint::builder(identity.clone(), registry.clone())
            .bind_addr("127.0.0.1:0".parse().unwrap())
            .alpns(vec![vec![]])
            .bind()
            .await,
        Err(Error::Alpn)
    ));
    let endpoint = IdentityEndpoint::builder(identity, registry)
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .bind()
        .await
        .unwrap();
    assert!(matches!(
        endpoint.connect(endpoint.addr().unwrap(), ALPN).await,
        Err(Error::SelfConnect)
    ));
    let invalid =
        iroh::identity::EndpointAddr::new(PeerId::V1([0; 48]), "0.0.0.0:0".parse().unwrap());
    assert!(matches!(
        endpoint.connect(invalid.clone(), ALPN).await,
        Err(Error::Destination)
    ));
    assert!(matches!(
        endpoint.connect(invalid, b"").await,
        Err(Error::Alpn)
    ));
    endpoint.close().await;
}
