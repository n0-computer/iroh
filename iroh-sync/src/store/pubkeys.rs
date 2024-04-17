use std::sync::RwLock;
use std::{collections::HashMap, sync::Arc};

use ed25519_dalek::{SignatureError, VerifyingKey};

use crate::{AuthorId, AuthorPublicKey, NamespaceId, NamespacePublicKey};

/// Store trait for expanded public keys for authors and namespaces.
///
/// Used to cache [`ed25519_dalek::VerifyingKey`].
///
/// This trait is implemented for the unit type [`()`], where no caching is used.
pub trait PublicKeyStore {
    /// Convert a byte array into a  [`VerifyingKey`].
    ///
    /// New keys are inserted into the [`PublicKeyStore ] and reused on subsequent calls.
    fn public_key(&self, id: &[u8; 32]) -> Result<VerifyingKey, SignatureError>;

    /// Convert a [`NamespaceId`] into a [`NamespacePublicKey`].
    ///
    /// New keys are inserted into the [`PublicKeyStore ] and reused on subsequent calls.
    fn namespace_key(&self, bytes: &NamespaceId) -> Result<NamespacePublicKey, SignatureError> {
        self.public_key(bytes.as_bytes()).map(Into::into)
    }

    /// Convert a [`AuthorId`] into a [`AuthorPublicKey`].
    ///
    /// New keys are inserted into the [`PublicKeyStore ] and reused on subsequent calls.
    fn author_key(&self, bytes: &AuthorId) -> Result<AuthorPublicKey, SignatureError> {
        self.public_key(bytes.as_bytes()).map(Into::into)
    }
}

impl<T: PublicKeyStore> PublicKeyStore for &T {
    fn public_key(&self, id: &[u8; 32]) -> Result<VerifyingKey, SignatureError> {
        (*self).public_key(id)
    }
}

impl<T: PublicKeyStore> PublicKeyStore for &mut T {
    fn public_key(&self, id: &[u8; 32]) -> Result<VerifyingKey, SignatureError> {
        PublicKeyStore::public_key(*self, id)
    }
}

impl PublicKeyStore for () {
    fn public_key(&self, id: &[u8; 32]) -> Result<VerifyingKey, SignatureError> {
        VerifyingKey::from_bytes(id)
    }
}

/// In-memory key storage
// TODO: Make max number of keys stored configurable.
#[derive(Debug, Clone, Default)]
pub struct MemPublicKeyStore {
    keys: Arc<RwLock<HashMap<[u8; 32], VerifyingKey>>>,
}

impl PublicKeyStore for MemPublicKeyStore {
    fn public_key(&self, bytes: &[u8; 32]) -> Result<VerifyingKey, SignatureError> {
        if let Some(id) = self.keys.read().unwrap().get(bytes) {
            return Ok(*id);
        }
        let id = VerifyingKey::from_bytes(bytes)?;
        self.keys.write().unwrap().insert(*bytes, id);
        Ok(id)
    }
}
