use std::hash::Hash;

pub use ed25519_dalek::{SigningKey as SecretKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};

use super::disco;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(ed25519_dalek::VerifyingKey);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state)
    }
}

impl From<ed25519_dalek::VerifyingKey> for PublicKey {
    fn from(key: ed25519_dalek::VerifyingKey) -> Self {
        Self(key)
    }
}

impl From<[u8; PUBLIC_KEY_LENGTH]> for PublicKey {
    fn from(value: [u8; PUBLIC_KEY_LENGTH]) -> Self {
        Self(ed25519_dalek::VerifyingKey::from_bytes(&value).unwrap())
    }
}

impl From<PublicKey> for disco::PublicKey {
    fn from(value: PublicKey) -> Self {
        let ed_compressed = curve25519_dalek::edwards::CompressedEdwardsY(*value.0.as_bytes());
        let ed = ed_compressed.decompress().expect("must be valid point");
        let montgomery = ed.to_montgomery();
        let montgomery_bytes = *montgomery.as_bytes();

        disco::PublicKey::from(montgomery_bytes)
    }
}

impl From<SecretKey> for disco::SecretKey {
    fn from(value: SecretKey) -> Self {
        disco::SecretKey::from(value.to_bytes())
    }
}
