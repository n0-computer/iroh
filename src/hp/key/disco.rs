use std::fmt::Debug;

use anyhow::{anyhow, ensure, Result};

pub const PUBLIC_RAW_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 24;
pub const SECRET_RAW_LEN: usize = 32;

/// Public key for a discovery.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey(crypto_box::PublicKey);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", hex::encode(self.0.as_bytes()))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<[u8; PUBLIC_RAW_LEN]> for PublicKey {
    fn from(value: [u8; PUBLIC_RAW_LEN]) -> Self {
        Self(value.into())
    }
}

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; PUBLIC_RAW_LEN] {
        self.0.as_bytes()
    }
}

/// Secret key for discovery.
#[derive(Clone)]
pub struct SecretKey(crypto_box::SecretKey);

impl Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey({})", hex::encode(&self.to_bytes()))
    }
}

impl From<[u8; SECRET_RAW_LEN]> for SecretKey {
    fn from(value: [u8; SECRET_RAW_LEN]) -> Self {
        Self(value.into())
    }
}

impl SecretKey {
    pub fn generate() -> Self {
        let key = crypto_box::SecretKey::generate(&mut crypto_box::aead::OsRng);
        Self(key)
    }

    /// Returns the public key for this secret key.
    pub fn public(&self) -> PublicKey {
        PublicKey((&self.0).into())
    }

    /// Returns the shared key for communication between this key and `other`.
    pub fn shared(&self, other: &PublicKey) -> SharedSecret {
        let boxx = crypto_box::ChaChaBox::new(&other.0, &self.0);
        SharedSecret(boxx)
    }

    pub fn to_bytes(&self) -> [u8; SECRET_RAW_LEN] {
        self.0.to_bytes()
    }
}

/// Shared Secret for a very Node.
#[derive(Clone)]
pub struct SharedSecret(crypto_box::ChaChaBox);

impl Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecret(crypto_box::ChaChaBox)")
    }
}

impl SharedSecret {
    /// Seals the provided cleartext.
    pub fn seal(&self, cleartext: &[u8]) -> Vec<u8> {
        use crypto_box::aead::{Aead, AeadCore, OsRng};

        let nonce = crypto_box::ChaChaBox::generate_nonce(&mut OsRng);
        let ciphertext = self
            .0
            .encrypt(&nonce, cleartext)
            .expect("encryption failed");

        let mut res = nonce.to_vec();
        res.extend(ciphertext);
        res
    }

    /// Opens the ciphertext, which must have been created using `Self::seal`, and returns the cleartext.
    pub fn open(&self, seal: &[u8]) -> Result<Vec<u8>> {
        use crypto_box::aead::Aead;
        ensure!(seal.len() > NONCE_LEN, "too short");

        let (nonce, ciphertext) = seal.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().unwrap();
        let plaintext = self
            .0
            .decrypt(&nonce.into(), ciphertext)
            .map_err(|e| anyhow!("decryption failed: {:?}", e))?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_box() {
        let alice = SecretKey::generate();
        let bob = SecretKey::generate();

        // Alice
        let shared = alice.shared(&bob.public());

        let plaintext = b"hello world";
        let sealed = shared.seal(plaintext);

        // Bob
        let shared = bob.shared(&alice.public());
        let decrypted = shared.open(&sealed).expect("should be valid");

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_serialization() {
        let alice = SecretKey::generate();
        let bob = SecretKey::generate();

        let alice_ser = alice.to_bytes();
        let bob_ser = bob.to_bytes();

        assert_eq!(SecretKey::from(alice_ser).to_bytes(), alice.to_bytes());
        assert_eq!(SecretKey::from(bob_ser).to_bytes(), bob.to_bytes());

        let alice_pub = alice.public();
        let bob_pub = bob.public();

        let alice_pub_ser = *alice_pub.as_bytes();
        let bob_pub_ser = *bob_pub.as_bytes();

        assert_eq!(PublicKey::from(alice_pub_ser), alice_pub);
        assert_eq!(PublicKey::from(bob_pub_ser), bob_pub);
    }
}
