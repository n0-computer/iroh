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

/// A keypair.
#[derive(Clone, Debug)]
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

impl From<SecretKey> for Keypair {
    fn from(secret: SecretKey) -> Self {
        let public = secret.verifying_key();
        Keypair { secret, public }
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
#[derive(Clone, PartialEq, Eq, Copy, Serialize, Deserialize, Hash)]
pub struct PeerId(PublicKey);

impl PeerId {
    /// Get this peer id as a byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Try to create a peer id from a byte array.
    ///
    /// # Warning
    ///
    /// The caller is responsible for ensuring that the bytes passed into this
    /// method actually represent a `curve25519_dalek::curve::CompressedEdwardsY`
    /// and that said compressed point is actually a point on the curve.
    pub fn from_bytes(bytes: &[u8; 32]) -> anyhow::Result<Self> {
        let key = PublicKey::from_bytes(bytes)?;
        Ok(PeerId(key))
    }

    /// Get the peer id as a byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl From<PublicKey> for PeerId {
    fn from(key: PublicKey) -> Self {
        PeerId(key)
    }
}

impl From<PeerId> for PublicKey {
    fn from(key: PeerId) -> Self {
        key.0
    }
}

impl Debug for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut text = data_encoding::BASE32_NOPAD.encode(self.0.as_bytes());
        text.make_ascii_lowercase();
        write!(f, "PeerId({text})")
    }
}

/// Serialises the [`PeerId`] to base32.
///
/// [`FromStr`] is capable of deserialising this format.
impl Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut text = data_encoding::BASE32_NOPAD.encode(self.0.as_bytes());
        text.make_ascii_lowercase();
        write!(f, "{text}")
    }
}

/// Error when deserialising a [`PeerId`].
#[derive(thiserror::Error, Debug)]
pub enum PeerIdError {
    /// Error when decoding the base32.
    #[error("decoding: {0}")]
    Base32(#[from] data_encoding::DecodeError),
    /// Error when decoding the public key.
    #[error("key: {0}")]
    Key(#[from] ed25519_dalek::SignatureError),
    /// Invalid length of the id.
    #[error("decoding size")]
    DecodingSize,
}

/// Deserialises the [`PeerId`] from it's base32 encoding.
///
/// [`Display`] is capable of serialising this format.
impl FromStr for PeerId {
    type Err = PeerIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: [u8; 32] = data_encoding::BASE32_NOPAD
            .decode(s.to_ascii_uppercase().as_bytes())?
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
