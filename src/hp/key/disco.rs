use anyhow::{anyhow, Result};

pub const PUBLIC_RAW_LEN: usize = 32;
pub const SECRET_RAW_LEN: usize = 32;

/// Public key for a discovery.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey(crypto_box::PublicKey);

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
#[derive(Debug, Clone)]
pub struct SecretKey(crypto_box::SecretKey);

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
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

    pub fn as_bytes(&self) -> &[u8; SECRET_RAW_LEN] {
        self.0.as_bytes()
    }
}

/// Seal of a given plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seal {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

/// Shared Secret for a very Node.
#[derive(Clone)]
pub struct SharedSecret(crypto_box::ChaChaBox);

impl SharedSecret {
    /// Seals the provided cleartext.
    pub fn seal(&self, cleartext: &[u8]) -> Seal {
        use crypto_box::aead::{Aead, AeadCore, OsRng};

        let nonce = crypto_box::ChaChaBox::generate_nonce(&mut OsRng);
        let ciphertext = self
            .0
            .encrypt(&nonce, cleartext)
            .expect("encryption failed");
        Seal {
            nonce: nonce.into(),
            ciphertext,
        }
    }

    /// Opens the ciphertext, which must have been created using `Self::seal`, and returns the cleartext.
    pub fn open(&self, seal: &Seal) -> Result<Vec<u8>> {
        use crypto_box::aead::Aead;
        let plaintext = self
            .0
            .decrypt(&seal.nonce.into(), &seal.ciphertext[..])
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

        let alice_ser = *alice.as_bytes();
        let bob_ser = *bob.as_bytes();

        assert_eq!(SecretKey::from(alice_ser).as_ref(), alice.as_ref());
        assert_eq!(SecretKey::from(bob_ser).as_ref(), bob.as_ref());

        let alice_pub = alice.public();
        let bob_pub = bob.public();

        let alice_pub_ser = *alice_pub.as_bytes();
        let bob_pub_ser = *bob_pub.as_bytes();

        assert_eq!(PublicKey::from(alice_pub_ser), alice_pub);
        assert_eq!(PublicKey::from(bob_pub_ser), bob_pub);
    }
}
