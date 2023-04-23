use std::{fmt::Debug, hash::Hash};

use super::{disco, disco::NONCE_LEN};
use anyhow::{anyhow, ensure, Context, Result};
use serde::{Deserialize, Serialize};

pub use crypto_box::KEY_SIZE;

pub(crate) const PUBLIC_KEY_LENGTH: usize = KEY_SIZE;
pub(crate) const SECRET_KEY_LENGTH: usize = KEY_SIZE;

#[derive(Clone, Eq)]
pub struct PublicKey(crypto_box::PublicKey);

impl From<crate::PeerId> for PublicKey {
    fn from(value: crate::PeerId) -> Self {
        let key: ed25519_dalek::VerifyingKey = value.into();
        PublicKey(crypto_box::PublicKey::from(key.to_montgomery()))
    }
}

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

impl std::cmp::PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl From<crypto_box::PublicKey> for PublicKey {
    fn from(key: crypto_box::PublicKey) -> Self {
        Self(key)
    }
}

impl From<[u8; PUBLIC_KEY_LENGTH]> for PublicKey {
    fn from(value: [u8; PUBLIC_KEY_LENGTH]) -> Self {
        Self(crypto_box::PublicKey::from(value))
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = anyhow::Error;
    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let value =
            <[u8; PUBLIC_KEY_LENGTH]>::try_from(value).context("TryFrom slice to PublicKey")?;
        Ok(PublicKey::from(value))
    }
}

impl From<PublicKey> for disco::PublicKey {
    fn from(value: PublicKey) -> Self {
        disco::PublicKey::from(*value.0.as_bytes())
    }
}

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        self.0.as_bytes()
    }

    pub fn is_zero(&self) -> bool {
        self.0.as_bytes() == &[0u8; PUBLIC_KEY_LENGTH]
    }
}

#[derive(Clone)]
pub struct SecretKey(crypto_box::SecretKey);

impl From<crate::SecretKey> for SecretKey {
    fn from(key: crate::SecretKey) -> Self {
        SecretKey(crypto_box::SecretKey::from(key.to_scalar()))
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serdect::array::serialize_hex_upper_or_bin(&self.0.to_bytes(), serializer)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let mut bytes = [0u8; KEY_SIZE];
        serdect::array::deserialize_hex_or_bin(&mut bytes, deserializer)?;
        Ok(SecretKey::from(bytes))
    }
}

impl SecretKey {
    pub fn generate() -> Self {
        Self(crypto_box::SecretKey::generate(&mut rand::rngs::OsRng))
    }

    pub fn public_key(&self) -> PublicKey {
        self.0.public_key().into()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    fn shared_secret(&self, other: &PublicKey) -> crypto_box::ChaChaBox {
        crypto_box::ChaChaBox::new(&other.0, &self.0)
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
        write!(f, "SecretKey({})", hex::encode(&self.0.to_bytes()))
    }
}

impl Hash for SecretKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state)
    }
}

impl From<crypto_box::SecretKey> for SecretKey {
    fn from(key: crypto_box::SecretKey) -> Self {
        Self(key)
    }
}

impl From<[u8; SECRET_KEY_LENGTH]> for SecretKey {
    fn from(value: [u8; SECRET_KEY_LENGTH]) -> Self {
        Self(crypto_box::SecretKey::from(value))
    }
}

impl From<SecretKey> for disco::SecretKey {
    fn from(value: SecretKey) -> Self {
        disco::SecretKey::from(value.0.to_bytes())
    }
}

impl From<SecretKey> for crate::tls::Keypair {
    fn from(value: SecretKey) -> Self {
        ed25519_dalek::SigningKey::from_bytes(&value.to_bytes()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_open_roundtrip() {
        let key_a = SecretKey::generate();
        let key_b = SecretKey::generate();

        let msg = b"super secret message!!!!";
        let sealed_message = key_a.seal_to(&key_b.public_key(), msg);
        let decrypted_message = key_b
            .open_from(&key_a.public_key(), &sealed_message)
            .unwrap();
        assert_eq!(&msg[..], &decrypted_message);
    }
}
