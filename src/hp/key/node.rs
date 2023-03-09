use std::{fmt::Debug, hash::Hash};

pub use ed25519_dalek::{SigningKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};

use super::{disco, disco::NONCE_LEN};
use anyhow::{anyhow, ensure, Result};

#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(ed25519_dalek::VerifyingKey);

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

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        self.0.as_bytes()
    }
}

#[derive(Clone)]
pub struct SecretKey(ed25519_dalek::SigningKey);

impl SecretKey {
    pub fn generate() -> Self {
        Self(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng))
    }

    pub fn verifying_key(&self) -> PublicKey {
        self.0.verifying_key().into()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    fn shared_secret(&self, other: &PublicKey) -> crypto_box::ChaChaBox {
        let public_key = crypto_box::PublicKey::from(*other.as_bytes());
        let secret_key = crypto_box::SecretKey::from(self.to_bytes());
        crypto_box::ChaChaBox::new(&public_key, &secret_key)
    }

    // Creates a shared secret between the [`SecretKey`] and the given [`PublicKey`], and sealsthe
    // provided cleartext.
    pub fn seal_to(&self, other: &PublicKey, cleartext: &[u8]) -> Vec<u8> {
        use crypto_box::aead::{Aead, AeadCore, OsRng};

        let shared_secret = self.shared_secret(other);
        let nonce = crypto_box::ChaChaBox::generate_nonce(&mut OsRng);
        let ciphertext = shared_secret
            .encrypt(&nonce, cleartext)
            .expect("encryption failed");

        let mut res = nonce.to_vec();
        res.extend(ciphertext);
        res
    }

    // Creates a shared secret between the [`SecretKey`] and the given [`PublicKey`], and opens the
    // `seal`, returning the cleartext.
    pub fn open_from(&self, other: &PublicKey, seal: &[u8]) -> Result<Vec<u8>> {
        let shared_secret = self.shared_secret(other);

        use crypto_box::aead::Aead;
        ensure!(seal.len() > NONCE_LEN, "too short");

        let (nonce, ciphertext) = seal.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().unwrap();
        let cleartext = shared_secret
            .decrypt(&nonce.into(), ciphertext)
            .map_err(|e| anyhow!("decryption failed: {:?}", e))?;

        Ok(cleartext)
    }
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey({})", hex::encode(self.0.to_bytes()))
    }
}

impl Hash for SecretKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state)
    }
}

impl From<ed25519_dalek::SigningKey> for SecretKey {
    fn from(key: ed25519_dalek::SigningKey) -> Self {
        Self(key)
    }
}

impl From<[u8; SECRET_KEY_LENGTH]> for SecretKey {
    fn from(value: [u8; SECRET_KEY_LENGTH]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(&value))
    }
}

impl From<SecretKey> for disco::SecretKey {
    fn from(value: SecretKey) -> Self {
        disco::SecretKey::from(value.0.to_bytes())
    }
}

impl From<SecretKey> for crate::tls::Keypair {
    fn from(value: SecretKey) -> Self {
        value.0.into()
    }
}
