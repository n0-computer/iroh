//! The private and public keys of a node.

use std::fmt::Debug;

use aead::{AeadInOut, Buffer};
use nested_enum_utils::common_fields;
use rand::TryRngCore;
use snafu::{ResultExt, Snafu, ensure};

pub(crate) const NONCE_LEN: usize = 24;

pub(super) fn public_ed_box(key: &ed25519_dalek::VerifyingKey) -> crypto_box::PublicKey {
    crypto_box::PublicKey::from(key.to_montgomery())
}

pub(super) fn secret_ed_box(key: &ed25519_dalek::SigningKey) -> crypto_box::SecretKey {
    crypto_box::SecretKey::from(key.to_scalar())
}

/// Shared Secret.
pub struct SharedSecret(crypto_box::ChaChaBox);

/// Errors that can occur during [`SharedSecret::open`].
#[common_fields({
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum DecryptionError {
    /// The nonce had the wrong size.
    #[snafu(display("Invalid nonce"))]
    InvalidNonce {},
    /// AEAD decryption failed.
    #[snafu(display("Aead error"))]
    Aead { source: aead::Error },
}

impl Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecret(crypto_box::ChaChaBox)")
    }
}

impl SharedSecret {
    pub fn new(this: &crypto_box::SecretKey, other: &crypto_box::PublicKey) -> Self {
        SharedSecret(crypto_box::ChaChaBox::new(other, this))
    }

    /// Seals the provided cleartext.
    pub fn seal(&self, buffer: &mut dyn Buffer) {
        let mut nonce = crypto_box::Nonce::default();
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .expect("failed to generate randomness");

        self.0
            .encrypt_in_place(&nonce, &[], buffer)
            .expect("encryption failed");

        buffer.extend_from_slice(&nonce).expect("buffer too small");
    }

    /// Opens the ciphertext, which must have been created using `Self::seal`, and places the clear text into the provided buffer.
    pub fn open(&self, buffer: &mut dyn Buffer) -> Result<(), DecryptionError> {
        ensure!(buffer.len() >= NONCE_LEN, InvalidNonceSnafu);

        let offset = buffer.len() - NONCE_LEN;
        let nonce: [u8; NONCE_LEN] = buffer.as_ref()[offset..]
            .try_into()
            .map_err(|_| InvalidNonceSnafu.build())?;

        buffer.truncate(offset);
        self.0
            .decrypt_in_place(&nonce.into(), &[], buffer)
            .context(AeadSnafu)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared(this: &iroh_base::SecretKey, other: &iroh_base::PublicKey) -> SharedSecret {
        let secret_key = secret_ed_box(this.secret());
        let public_key = public_ed_box(&other.public());

        SharedSecret::new(&secret_key, &public_key)
    }

    #[test]
    fn test_seal_open_roundtrip() {
        let mut rng = rand::rng();
        let key_a = iroh_base::SecretKey::generate(&mut rng);
        let key_b = iroh_base::SecretKey::generate(&mut rng);

        seal_open_roundtrip(&key_a, &key_b);
        seal_open_roundtrip(&key_b, &key_a);
        seal_open_roundtrip(&key_a, &key_a);
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
        let key = crypto_box::SecretKey::generate(&mut rand::rng());
        let public_bytes = *key.public_key().as_bytes();
        let public_key_back = crypto_box::PublicKey::from(public_bytes);
        assert_eq!(key.public_key(), public_key_back);
    }

    #[test]
    fn test_same_public_key_api() {
        let key = iroh_base::SecretKey::generate(rand::rng());
        let public_key1: crypto_box::PublicKey = public_ed_box(&key.public().public());
        let public_key2: crypto_box::PublicKey = secret_ed_box(key.secret()).public_key();

        assert_eq!(public_key1, public_key2);
    }

    #[test]
    fn test_same_public_key_low_level() {
        let mut rng = rand::rng();
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
