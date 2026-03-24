//! QUIC crypto primitives for platforms without ring/aws-lc-rs.
//!
//! Provides HMAC-SHA256 and HKDF-SHA256 + AES-256-GCM implementations
//! using the RustCrypto stack, replacing the ring-based defaults that
//! noq normally uses.

use std::sync::Arc;

use noq_proto::crypto::{self, CryptoError};

/// HMAC-SHA256 key for stateless retry token signing/verification.
pub(crate) struct RustCryptoHmacKey {
    key: hmac::Hmac<sha2::Sha256>,
}

impl RustCryptoHmacKey {
    pub(crate) fn new(key: &[u8]) -> Self {
        use hmac::Mac;
        Self {
            key: hmac::Hmac::<sha2::Sha256>::new_from_slice(key)
                .expect("HMAC accepts any key length"),
        }
    }

    /// Generate a key from random bytes.
    pub(crate) fn random() -> Self {
        let mut key_bytes = [0u8; 64];
        rand::fill(&mut key_bytes);
        Self::new(&key_bytes)
    }
}

impl crypto::HmacKey for RustCryptoHmacKey {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        use hmac::Mac;
        let mut mac = self.key.clone();
        mac.update(data);
        let result = mac.finalize().into_bytes();
        let len = signature_out.len().min(result.len());
        signature_out[..len].copy_from_slice(&result[..len]);
    }

    fn signature_len(&self) -> usize {
        32 // SHA-256 output
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        use hmac::Mac;
        let mut mac = self.key.clone();
        mac.update(data);
        mac.verify_slice(signature).map_err(|_| CryptoError)?;
        Ok(())
    }
}

/// HKDF-SHA256 + AES-256-GCM based handshake token key.
pub(crate) struct RustCryptoHandshakeTokenKey {
    prk: hkdf::Hkdf<sha2::Sha256>,
}

impl RustCryptoHandshakeTokenKey {
    pub(crate) fn random() -> Self {
        let mut master = [0u8; 64];
        rand::fill(&mut master);
        Self {
            prk: hkdf::Hkdf::<sha2::Sha256>::new(None, &master),
        }
    }

    fn derive_aead(&self, token_nonce: u128) -> aes_gcm::Aes256Gcm {
        let nonce_bytes = token_nonce.to_le_bytes();
        let mut key_buffer = [0u8; 32];
        self.prk
            .expand(&nonce_bytes, &mut key_buffer)
            .expect("valid output length");
        use aes_gcm::KeyInit;
        aes_gcm::Aes256Gcm::new_from_slice(&key_buffer).expect("valid key length")
    }
}

impl crypto::HandshakeTokenKey for RustCryptoHandshakeTokenKey {
    fn seal(&self, token_nonce: u128, data: &mut Vec<u8>) -> Result<(), CryptoError> {
        use aes_gcm::aead::AeadInPlace;

        let cipher = self.derive_aead(token_nonce);
        let nonce = aes_gcm::Nonce::default(); // zero nonce — key is unique per token_nonce
        cipher
            .encrypt_in_place(&nonce, &[], data)
            .map_err(|_| CryptoError)?;
        Ok(())
    }

    fn open<'a>(&self, token_nonce: u128, data: &'a mut [u8]) -> Result<&'a [u8], CryptoError> {
        use aes_gcm::aead::AeadInPlace;

        let cipher = self.derive_aead(token_nonce);
        let nonce = aes_gcm::Nonce::default();
        let tag_len = 16;
        let payload_len = data.len().checked_sub(tag_len).ok_or(CryptoError)?;

        let (msg, tag_bytes) = data.split_at_mut(payload_len);
        let tag = aes_gcm::Tag::from_slice(tag_bytes);

        cipher
            .decrypt_in_place_detached(&nonce, &[], msg, tag)
            .map_err(|_| CryptoError)?;

        Ok(&data[..payload_len])
    }
}

/// Create a default [`noq::EndpointConfig`] with real HMAC-SHA256 (no ring required).
pub(crate) fn default_endpoint_config() -> noq::EndpointConfig {
    noq::EndpointConfig::new(Arc::new(RustCryptoHmacKey::random()))
}

/// Create a [`noq::ServerConfig`] from a QUIC server crypto config
/// with real HKDF-SHA256 handshake token key (no ring required).
pub(crate) fn server_config_with_crypto(
    crypto: Arc<dyn noq_proto::crypto::ServerConfig>,
) -> noq::ServerConfig {
    noq::ServerConfig::new(crypto, Arc::new(RustCryptoHandshakeTokenKey::random()))
}
