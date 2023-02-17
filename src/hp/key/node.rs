use std::hash::Hash;

pub use ed25519_dalek::{Keypair, SecretKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(ed25519_dalek::PublicKey);

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

impl From<ed25519_dalek::PublicKey> for PublicKey {
    fn from(key: ed25519_dalek::PublicKey) -> Self {
        Self(key)
    }
}

impl From<[u8; PUBLIC_KEY_LENGTH]> for PublicKey {
    fn from(value: [u8; PUBLIC_KEY_LENGTH]) -> Self {
        Self(ed25519_dalek::PublicKey::from_bytes(&value).unwrap())
    }
}
