//! The private and public keys of a node.

use std::fmt::Debug;

use anyhow::{anyhow, ensure, Result};

pub(crate) const NONCE_LEN: usize = 24;

fn public_ed_box(key: &ed25519_dalek::VerifyingKey) -> crypto_box::PublicKey {
    crypto_box::PublicKey::from(key.to_montgomery())
}

fn secret_ed_box(key: &ed25519_dalek::SigningKey) -> crypto_box::SecretKey {
    crypto_box::SecretKey::from(key.to_scalar())
}

/// Shared Secret.
pub struct SharedSecret(crypto_box::ChaChaBox);

impl Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecret(crypto_box::ChaChaBox)")
    }
}

impl SharedSecret {
    fn new(this: &crypto_box::SecretKey, other: &crypto_box::PublicKey) -> Self {
        SharedSecret(crypto_box::ChaChaBox::new(other, this))
    }

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

impl crate::key::Keypair {
    /// Creates a shared secret between [Self] and the given [super::key::PublicKey], and seals the
    /// provided cleartext.
    pub fn seal_to(&self, other: &crate::key::PublicKey, cleartext: &[u8]) -> Vec<u8> {
        let secret_key = secret_ed_box(self.secret());
        let public_key = public_ed_box(other);

        let shared = SharedSecret::new(&secret_key, &public_key);
        shared.seal(cleartext)
    }

    /// Creates a shared secret between [Self] and the given [super::key::PublicKey], and opens the
    pub fn open_from(&self, other: &crate::key::PublicKey, seal: &[u8]) -> Result<Vec<u8>> {
        let secret_key = secret_ed_box(self.secret());
        let public_key = public_ed_box(other);

        let shared = SharedSecret::new(&secret_key, &public_key);

        shared.open(seal)
    }

    /// Returns the shared key for communication between this key and `other`.
    pub fn shared(&self, other: &crate::key::PublicKey) -> SharedSecret {
        let secret_key = secret_ed_box(self.secret());
        let public_key = public_ed_box(other);

        SharedSecret::new(&secret_key, &public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_open_roundtrip() {
        let key_a = crate::key::Keypair::generate();
        let key_b = crate::key::Keypair::generate();

        seal_open_roundtrip(&key_a, &key_b);
        seal_open_roundtrip(&key_b, &key_a);
        seal_open_roundtrip(&key_a, &key_a);
    }

    fn seal_open_roundtrip(key_a: &crate::key::Keypair, key_b: &crate::key::Keypair) {
        let msg = b"super secret message!!!!";
        let sealed_message = key_a.seal_to(&key_b.public(), msg);
        let decrypted_message = key_b.open_from(&key_a.public(), &sealed_message).unwrap();
        assert_eq!(&msg[..], &decrypted_message);

        let shared_a = key_a.shared(&key_b.public());
        let sealed_message = shared_a.seal(msg);
        let shared_b = key_b.shared(&key_a.public());
        let decrypted_message = shared_b.open(&sealed_message).unwrap();
        assert_eq!(&msg[..], &decrypted_message);
    }

    #[test]
    fn test_roundtrip_public_key() {
        let key = crypto_box::SecretKey::generate(&mut rand::thread_rng());
        let public_bytes = *key.public_key().as_bytes();
        let public_key_back = crypto_box::PublicKey::from(public_bytes);
        assert_eq!(key.public_key(), public_key_back);
    }

    #[test]
    fn test_same_public_key_api() {
        let key = crate::key::Keypair::generate();
        let public_key1: crypto_box::PublicKey = public_ed_box(&key.public());
        let public_key2: crypto_box::PublicKey = secret_ed_box(key.secret()).public_key();

        assert_eq!(public_key1, public_key2);
    }

    #[test]
    fn test_same_public_key_low_level() {
        let mut rng = rand::thread_rng();
        let key = ed25519_dalek::SigningKey::generate(&mut rng);
        let public_key1 = {
            let m = key.verifying_key().to_montgomery();
            crypto_box::PublicKey::from(m)
        };

        let public_key2 = {
            let s = key.to_scalar();
            let cs = crypto_box::SecretKey::from(s);
            cs.public_key()
        };

        assert_eq!(public_key1, public_key2);
    }
}
