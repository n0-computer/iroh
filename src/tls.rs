//! TLS configuration based on libp2p TLS specs.
//!
//! See <https://github.com/libp2p/specs/blob/master/tls/tls.md>.
//! Based on rust-libp2p/transports/tls

pub mod certificate;
mod verifier;

use std::{
    fmt::{Debug, Display},
    ops::Deref,
    str::FromStr,
    sync::Arc,
};

pub use ed25519_dalek::{PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use ssh_key::LineEnding;

use crate::util;

pub(crate) const P2P_ALPN: [u8; 9] = *b"n0/iroh/1";

/// A keypair.
#[derive(Debug)]
pub struct Keypair(ed25519_dalek::Keypair);

impl Deref for Keypair {
    type Target = ed25519_dalek::Keypair;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Keypair {
    /// The public key of this keypair.
    pub fn public(&self) -> PublicKey {
        self.0.public
    }

    /// The secret key of this keypair.
    pub fn secret(&self) -> &SecretKey {
        &self.0.secret
    }

    /// Generate a new keypair.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        let key = ed25519_dalek::Keypair::generate(&mut rng);
        Self(key)
    }

    /// Serialise the keypair to OpenSSH format.
    pub fn to_openssh(&self) -> ssh_key::Result<zeroize::Zeroizing<String>> {
        let ckey = ssh_key::private::Ed25519Keypair::from(&self.0);
        ssh_key::private::PrivateKey::from(ckey).to_openssh(LineEnding::default())
    }

    /// Deserialise the keypair from OpenSSH format.
    pub fn try_from_openssh<T: AsRef<[u8]>>(data: T) -> anyhow::Result<Self> {
        let ser_key = ssh_key::private::PrivateKey::from_openssh(data)?;
        match ser_key.key_data() {
            ssh_key::private::KeypairData::Ed25519(kp) => {
                let dalek_keypair: ed25519_dalek::Keypair = kp.try_into()?;
                Ok(Keypair::from(dalek_keypair))
            }
            _ => anyhow::bail!("invalid key format"),
        }
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        use ed25519_dalek::Signer;

        self.0.sign(msg)
    }
}

impl From<ed25519_dalek::Keypair> for Keypair {
    fn from(value: ed25519_dalek::Keypair) -> Self {
        Keypair(value)
    }
}

// TODO: probably needs a version field
/// An identifier for networked peers.
///
/// Each network node has a cryptographic identifier which can be used to make sure you are
/// connecting to the right peer.
///
/// # `Display` and `FromStr`
///
/// The [`PeerId`] implements both `Display` and `FromStr` which can be used to
/// (de)serialise to human-readable and relatively safely transferrable strings.
#[derive(Clone, PartialEq, Eq, Copy, Serialize, Deserialize)]
pub struct PeerId(PublicKey);

impl From<PublicKey> for PeerId {
    fn from(key: PublicKey) -> Self {
        PeerId(key)
    }
}

impl Debug for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerId({})", util::encode(self.0.as_bytes()))
    }
}

/// Serialises the [`PeerId`] to base64.
///
/// [`FromStr`] is capable of deserialising this format.
impl Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", util::encode(self.0.as_bytes()))
    }
}

/// Error when deserialising a [`PeerId`].
#[derive(thiserror::Error, Debug)]
pub enum PeerIdError {
    /// Error when decoding the base64.
    #[error("encoding: {0}")]
    Base64(#[from] base64::DecodeError),
    /// Error when decoding the public key.
    #[error("key: {0}")]
    Key(#[from] ed25519_dalek::SignatureError),
}

/// Deserialises the [`PeerId`] from it's base64 encoding.
///
/// [`Display`] is capable of serialising this format.
impl FromStr for PeerId {
    type Err = PeerIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = util::decode(s)?;
        let key = PublicKey::from_bytes(&bytes)?;
        Ok(PeerId(key))
    }
}

/// Create a TLS client configuration.
///
/// If *keylog* is `true` this will enable logging of the pre-master key to the file in the
/// `SSLKEYLOGFILE` environment variable.  This can be used to inspect the traffic for
/// debugging purposes.
pub fn make_client_config(
    keypair: &Keypair,
    remote_peer_id: Option<PeerId>,
    alpn_protocols: Vec<Vec<u8>>,
    keylog: bool,
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
        .with_client_auth_cert(vec![certificate], private_key)
        .expect("Client cert key DER is valid; qed");
    crypto.alpn_protocols = alpn_protocols;
    if keylog {
        crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    Ok(crypto)
}

/// Create a TLS server configuration.
///
/// If *keylog* is `true` this will enable logging of the pre-master key to the file in the
/// `SSLKEYLOGFILE` environment variable.  This can be used to inspect the traffic for
/// debugging purposes.
pub fn make_server_config(
    keypair: &Keypair,
    alpn_protocols: Vec<Vec<u8>>,
    keylog: bool,
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
    crypto.alpn_protocols = alpn_protocols;
    if keylog {
        crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }
    Ok(crypto)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_openssh_roundtrip() {
        let kp = Keypair::generate();
        let ser = kp.to_openssh().unwrap();
        let de = Keypair::try_from_openssh(&ser).unwrap();
        assert_eq!(kp.to_bytes(), de.to_bytes());
    }
}
