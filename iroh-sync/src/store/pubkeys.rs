use std::{collections::HashMap, sync::Arc};

use ed25519_dalek::{SignatureError, VerifyingKey};
use parking_lot::RwLock;

use crate::{AuthorId, AuthorPublicKey, NamespaceId, NamespacePublicKey};

/// Store trait for expanded public keys for authors and namespaces.
///
/// Used to cache [`ed25519_dalek::VerifyingKeys`]. This trait is also implemented for the unit type [`()`], where no
/// caching is used.
pub trait PublicKeyStore {
    /// Convert a byte array into a  [`VerifyingKey`], reusing from cache if available.
    fn public_key(&self, id: &[u8; 32]) -> std::result::Result<VerifyingKey, SignatureError>;

    /// Convert a [`NamespaceId`] into a [`NamespacePublicKey`], reusing from cache if available.
    fn namespace_key(
        &self,
        bytes: &NamespaceId,
    ) -> std::result::Result<NamespacePublicKey, SignatureError> {
        self.public_key(bytes.as_bytes())
            .map(NamespacePublicKey::from)
    }

    /// Convert a [`AuthorId`] into a [`AuthorPublicKey`], reusing from cache if available.
    fn author_key(&self, bytes: &AuthorId) -> std::result::Result<AuthorPublicKey, SignatureError> {
        self.public_key(bytes.as_bytes()).map(AuthorPublicKey::from)
    }
}

impl PublicKeyStore for () {
    /// Convert a byte array into a  [`VerifyingKey`], reusing from cache if available.
    fn public_key(&self, id: &[u8; 32]) -> std::result::Result<VerifyingKey, SignatureError> {
        VerifyingKey::from_bytes(id)
    }
}

/// In-memory key storage
#[derive(Debug, Clone, Default)]
pub struct MemPublicKeyStore {
    keys: Arc<RwLock<HashMap<[u8; 32], VerifyingKey>>>,
}

impl PublicKeyStore for MemPublicKeyStore {
    fn public_key(&self, bytes: &[u8; 32]) -> Result<VerifyingKey, SignatureError> {
        if let Some(id) = self.keys.read().get(bytes) {
            return Ok(*id);
        }
        let id = VerifyingKey::from_bytes(bytes)?;
        self.keys.write().insert(*bytes, id);
        Ok(id)
    }
}
