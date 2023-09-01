use std::{collections::HashMap, sync::Arc};

use ed25519_dalek::{SignatureError, VerifyingKey};
use parking_lot::RwLock;

use super::PublicKeyStore;

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
