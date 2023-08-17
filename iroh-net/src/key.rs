//! Cryptographic key handling for `iroh-net`.

mod encryption;

use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

pub use ed25519_dalek::{
    Signature, SigningKey as SecretKey, VerifyingKey as PublicKey, PUBLIC_KEY_LENGTH,
};
use serde::{Deserialize, Serialize};
use ssh_key::LineEnding;

pub use self::encryption::SharedSecret;

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

    /// Sign the given message and return a digital signature
    pub fn sign(&self, msg: &[u8]) -> Signature {
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
