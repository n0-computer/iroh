//! Regression coverage for client proof of possession and listener recovery.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use iroh::{
    endpoint::QuicTransportConfig,
    identity::{Error, IdentityEndpoint, LocalIdentity, Registry},
};
use rustls::{
    SignatureAlgorithm, SignatureScheme,
    pki_types::{PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer},
    sign::{Signer, SigningKey},
};

const ALPN: &[u8] = b"identity-client-proof/1";

#[derive(Debug)]
struct CorruptingKey {
    inner: Arc<dyn SigningKey>,
    signatures: Arc<AtomicUsize>,
}

impl SigningKey for CorruptingKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.inner.choose_scheme(offered).map(|inner| {
            Box::new(CorruptingSigner {
                inner,
                signatures: self.signatures.clone(),
            }) as Box<dyn Signer>
        })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.inner.algorithm()
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.inner.public_key()
    }
}

#[derive(Debug)]
struct CorruptingSigner {
    inner: Box<dyn Signer>,
    signatures: Arc<AtomicUsize>,
}

impl Signer for CorruptingSigner {
    fn scheme(&self) -> SignatureScheme {
        self.inner.scheme()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let mut signature = self.inner.sign(message)?;
        signature[0] ^= 1;
        self.signatures.fetch_add(1, Ordering::Relaxed);
        Ok(signature)
    }
}

async fn bind(identity: LocalIdentity, registry: Arc<Registry>) -> IdentityEndpoint {
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
async fn forged_client_proof_is_rejected_and_valid_retry_succeeds() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let registry = Arc::new(Registry::builtins(vec![2]).unwrap());
        let server = bind(
            LocalIdentity::generate_ml_dsa65(&registry).unwrap(),
            registry.clone(),
        )
        .await;

        let pair =
            aws_lc_rs::signature::PqdsaKeyPair::generate(&aws_lc_rs::signature::ML_DSA_65_SIGNING)
                .unwrap();
        let document = pair.to_pkcs8v1().unwrap();
        let private = PrivatePkcs8KeyDer::from(document.as_ref().to_vec());
        let key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&private.into()).unwrap();
        let signatures = Arc::new(AtomicUsize::new(0));
        let corrupt_identity = LocalIdentity::new(
            Arc::new(CorruptingKey {
                inner: key.clone(),
                signatures: signatures.clone(),
            }),
            &registry,
        )
        .unwrap();
        let valid_identity = LocalIdentity::new(key, &registry).unwrap();
        // Both advertise exactly the same key. Rejection must depend on the
        // handshake proof, rather than parsing or an unexpected public identity.
        assert_eq!(corrupt_identity.id(), valid_identity.id());
        let corrupt = bind(corrupt_identity, registry.clone()).await;
        let (outgoing, incoming) = tokio::join!(
            corrupt.connect(server.addr().unwrap(), ALPN),
            server.accept()
        );
        assert!(signatures.load(Ordering::Relaxed) > 0);
        assert!(
            matches!(
                incoming,
                Err(Error::Connection(noq::ConnectionError::TransportError(_)))
            ),
            "server must reject the proof during TLS authentication: {incoming:?}"
        );
        // The client can finish its side before receiving the server's rejection.
        if let Ok(connection) = outgoing {
            connection.closed().await;
        }
        corrupt.close().await;

        // A failed authentication must not reserve or poison this identity on
        // the listener. The genuine signer can connect and exchange data.
        let valid = bind(valid_identity, registry).await;
        let (outgoing, incoming) =
            tokio::join!(valid.connect(server.addr().unwrap(), ALPN), server.accept());
        let outgoing = outgoing.unwrap();
        let incoming = incoming.unwrap();
        assert_eq!(incoming.remote_id(), valid.id());
        assert_eq!(outgoing.remote_id(), server.id());
        let mut send = outgoing.open_uni().await.unwrap();
        send.write_all(b"valid proof").await.unwrap();
        send.finish().unwrap();
        let mut recv = incoming.accept_uni().await.unwrap();
        assert_eq!(recv.read_to_end(64).await.unwrap(), b"valid proof");
        tokio::join!(valid.close(), server.close());
    })
    .await
    .expect("client proof test timed out");
}
