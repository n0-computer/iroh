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

pub use ed25519_dalek::{Signature, SigningKey as SecretKey, VerifyingKey as PublicKey};
use serde::{Deserialize, Serialize};
use ssh_key::LineEnding;

use crate::util;

const P2P_ALPN: [u8; 9] = *b"n0/iroh/1";

/// A keypair.
#[derive(Debug)]
pub struct Keypair {
    public: PublicKey,
    secret: SecretKey,
}

impl Keypair {
    /// The public key of this keypair.
    pub fn public(&self) -> PublicKey {
        self.public
    }

    /// The secret key of this keypair.
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Generate a new keypair.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        let secret = SecretKey::generate(&mut rng);
        let public = secret.verifying_key();

        Self { public, secret }
    }

    /// Serialise the keypair to OpenSSH format.
    pub fn to_openssh(&self) -> ssh_key::Result<zeroize::Zeroizing<String>> {
        let ckey = ssh_key::private::Ed25519Keypair {
            public: self.public.into(),
            private: self.secret.clone().into(),
        };
        ssh_key::private::PrivateKey::from(ckey).to_openssh(LineEnding::default())
    }

    /// Deserialise the keypair from OpenSSH format.
    pub fn try_from_openssh<T: AsRef<[u8]>>(data: T) -> anyhow::Result<Self> {
        let ser_key = ssh_key::private::PrivateKey::from_openssh(data)?;
        match ser_key.key_data() {
            ssh_key::private::KeypairData::Ed25519(kp) => {
                let public: PublicKey = kp.public.try_into()?;

                Ok(Keypair {
                    public,
                    secret: kp.private.clone().into(),
                })
            }
            _ => anyhow::bail!("invalid key format"),
        }
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        use ed25519_dalek::Signer;

        self.secret.sign(msg)
    }

    /// Convert this to the bytes representing the secret part.
    /// The public part can always be recovered.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
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
    #[error("decoding: {0}")]
    Base64(#[from] base64::DecodeError),
    /// Error when decoding the public key.
    #[error("key: {0}")]
    Key(#[from] ed25519_dalek::SignatureError),
    /// Invalid length of the id.
    #[error("decoding size")]
    DecodingSize,
}

/// Deserialises the [`PeerId`] from it's base64 encoding.
///
/// [`Display`] is capable of serialising this format.
impl FromStr for PeerId {
    type Err = PeerIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: [u8; 32] = util::decode(s)?
            .try_into()
            .map_err(|_| PeerIdError::DecodingSize)?;
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
        .with_single_cert(vec![certificate], private_key)
        .expect("Client cert key DER is valid; qed");
    crypto.alpn_protocols = vec![P2P_ALPN.to_vec()];
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
    crypto.alpn_protocols = vec![P2P_ALPN.to_vec()];
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
