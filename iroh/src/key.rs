//! The private and public keys of an endpoint.

use std::fmt::Debug;

use aead::{AeadCore, AeadInOut, Buffer};
use iroh_base::{PublicKey, SecretKey};
use n0_error::{Error, add_meta, e};

pub(crate) const NONCE_LEN: usize = 24;

const AEAD_DATA: &[u8] = &[];

pub(super) fn public_ed_box(key: &PublicKey) -> crypto_box::PublicKey {
    let key = key.as_verifying_key();
    crypto_box::PublicKey::from(key.to_montgomery())
}

pub(super) fn secret_ed_box(key: &SecretKey) -> crypto_box::SecretKey {
    let key = key.as_signing_key();
    crypto_box::SecretKey::from(key.to_scalar())
}

/// Shared Secret.
pub struct SharedSecret(crypto_box::ChaChaBox);

/// Errors that can occur during [`SharedSecret::open`].
#[add_meta]
#[derive(Error)]
#[error(from_sources, std_sources)]
#[non_exhaustive]
pub enum DecryptionError {
    /// The nonce had the wrong size.
    #[display("Invalid nonce")]
    InvalidNonce,
    /// AEAD decryption failed.
    #[display("Aead error")]
    Aead {
        #[error(std_err)]
        source: aead::Error,
    },
}

impl Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecret(crypto_box::ChaChaBox)")
    }
}

impl SharedSecret {
    pub fn new(this: &crypto_box::SecretKey, other: &crypto_box::PublicKey) -> Self {
        SharedSecret(crypto_box::ChaChaBox::new_from_clamped(other, this))
    }

    /// Seals the provided cleartext.
    pub fn seal(&self, buffer: &mut dyn Buffer) {
        let nonce = crypto_box::ChaChaBox::try_generate_nonce_with_rng(&mut rand::rng())
            .expect("not enough randomness");

        self.0
            .encrypt_in_place(&nonce, AEAD_DATA, buffer)
            .expect("encryption failed");

        buffer.extend_from_slice(&nonce).expect("buffer too small");
    }

    /// Opens the ciphertext, which must have been created using `Self::seal`, and places the clear text into the provided buffer.
    pub fn open(&self, buffer: &mut dyn Buffer) -> Result<(), DecryptionError> {
        n0_error::ensure_e!(buffer.len() >= NONCE_LEN, DecryptionError::InvalidNonce);

        let offset = buffer.len() - NONCE_LEN;
        let nonce: [u8; NONCE_LEN] = buffer.as_ref()[offset..]
            .try_into()
            .map_err(|_| e!(DecryptionError::InvalidNonce))?;

        buffer.truncate(offset);
        self.0.decrypt_in_place(&nonce.into(), AEAD_DATA, buffer)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;

    fn shared(this: &iroh_base::SecretKey, other: &iroh_base::PublicKey) -> SharedSecret {
        let secret_key = secret_ed_box(this);
        let public_key = public_ed_box(other);

        SharedSecret::new(&secret_key, &public_key)
    }

    #[test]
    fn test_seal_open_roundtrip() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let key_a = iroh_base::SecretKey::generate(&mut rng);
        let key_b = iroh_base::SecretKey::generate(&mut rng);

        println!("a -> a");
        seal_open_roundtrip(&key_a, &key_a);
        println!("b -> b");
        seal_open_roundtrip(&key_b, &key_b);

        println!("a -> b");
        seal_open_roundtrip(&key_a, &key_b);
        println!("b -> a");
        seal_open_roundtrip(&key_b, &key_a);
    }

    fn seal_open_roundtrip(key_a: &iroh_base::SecretKey, key_b: &iroh_base::SecretKey) {
        let msg = b"super secret message!!!!".to_vec();
        let shared_a = shared(key_a, &key_b.public());
        let mut sealed_message = msg.clone();
        shared_a.seal(&mut sealed_message);

        let shared_b = shared(key_b, &key_a.public());
        let mut decrypted_message = sealed_message.clone();
        shared_b.open(&mut decrypted_message).unwrap();
        assert_eq!(&msg[..], &decrypted_message);
    }

    #[test]
    fn test_roundtrip_public_key() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let key = crypto_box::SecretKey::generate(&mut rng);
        let public_bytes = *key.public_key().as_bytes();
        let public_key_back = crypto_box::PublicKey::from(public_bytes);
        assert_eq!(key.public_key(), public_key_back);
    }

    #[test]
    fn test_same_public_key_api() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let key = iroh_base::SecretKey::generate(&mut rng);
        let public_key1: crypto_box::PublicKey = public_ed_box(&key.public());
        let public_key2: crypto_box::PublicKey = secret_ed_box(&key).public_key();

        assert_eq!(public_key1, public_key2);
    }

    #[test]
    fn test_same_public_key_low_level() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
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
