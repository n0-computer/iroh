//! TLS configuration based on libp2p TLS specs.
//!
//! See <https://github.com/libp2p/specs/blob/master/tls/tls.md>.
//! Based on rust-libp2p/transports/tls

pub mod certificate;
mod verifier;

use std::{
    fmt::{Debug, Display},
    str::FromStr,
    sync::Arc,
};

pub use ed25519_dalek::{PublicKey, SecretKey, Signature};

// TODO: change?
const P2P_ALPN: [u8; 6] = *b"libp2p";

#[derive(Debug)]
pub struct Keypair(ed25519_dalek::Keypair);

impl Keypair {
    pub fn public(&self) -> PublicKey {
        self.0.public
    }

    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        let key = ed25519_dalek::Keypair::generate(&mut rng);
        Self(key)
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        use ed25519_dalek::Signer;

        self.0.sign(msg)
    }
}

// TODO: probably needs a version field
#[derive(Clone, PartialEq)]
pub struct PeerId(PublicKey);

impl From<PublicKey> for PeerId {
    fn from(key: PublicKey) -> Self {
        PeerId(key)
    }
}

impl Debug for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerId({})", hex::encode(self.0.as_bytes()))
    }
}

impl Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_bytes()))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum PeerIdError {
    #[error("encoding: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("key: {0}")]
    Key(#[from] ed25519_dalek::SignatureError),
}

impl FromStr for PeerId {
    type Err = PeerIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        let key = PublicKey::from_bytes(&bytes)?;
        Ok(PeerId(key))
    }
}

/// Create a TLS client configuration.
pub fn make_client_config(
    keypair: &Keypair,
    remote_peer_id: Option<PeerId>,
) -> Result<rustls::ClientConfig, certificate::GenError> {
    let (certificate, private_key) = certificate::generate(keypair)?;

    let mut crypto = rustls::ClientConfig::builder()
        .with_cipher_suites(verifier::CIPHERSUITES)
        .with_safe_default_kx_groups()
        .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
        .expect("Cipher suites and kx groups are configured; qed")
        .with_custom_certificate_verifier(Arc::new(
            verifier::Libp2pCertificateVerifier::with_remote_peer_id(remote_peer_id),
        ))
        .with_single_cert(vec![certificate], private_key)
        .expect("Client cert key DER is valid; qed");
    crypto.alpn_protocols = vec![P2P_ALPN.to_vec()];

    Ok(crypto)
}

/// Create a TLS server configuration.
pub fn make_server_config(
    keypair: &Keypair,
) -> Result<rustls::ServerConfig, certificate::GenError> {
    let (certificate, private_key) = certificate::generate(keypair)?;

    let mut crypto = rustls::ServerConfig::builder()
        .with_cipher_suites(verifier::CIPHERSUITES)
        .with_safe_default_kx_groups()
        .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
        .expect("Cipher suites and kx groups are configured; qed")
        .with_client_cert_verifier(Arc::new(verifier::Libp2pCertificateVerifier::new()))
        .with_single_cert(vec![certificate], private_key)
        .expect("Server cert key DER is valid; qed");
    crypto.alpn_protocols = vec![P2P_ALPN.to_vec()];

    Ok(crypto)
}
