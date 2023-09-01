use std::{collections::HashMap, sync::Arc};

use ed25519_dalek::SignatureError;
use parking_lot::RwLock;

use crate::{AuthorId, AuthorIdBytes, NamespaceId, NamespaceIdBytes};

use super::PubkeyStore;

/// In-memory key storage
#[derive(Debug, Clone, Default)]
pub struct MemPubkeyStore {
    authors: Arc<RwLock<HashMap<AuthorIdBytes, AuthorId>>>,
    namespaces: Arc<RwLock<HashMap<NamespaceIdBytes, NamespaceId>>>,
}

impl PubkeyStore for MemPubkeyStore {
    fn namespace_id(&self, bytes: &NamespaceIdBytes) -> Result<NamespaceId, SignatureError> {
        if let Some(id) = self.namespaces.read().get(bytes) {
            return Ok(*id);
        }
        let id = NamespaceId::from_bytes(bytes)?;
        self.namespaces.write().insert(*bytes, id);
        Ok(id)
    }

    fn author_id(&self, bytes: &AuthorIdBytes) -> Result<AuthorId, SignatureError> {
        if let Some(id) = self.authors.read().get(bytes) {
            return Ok(*id);
        }
        let id = AuthorId::from_bytes(bytes)?;
        self.authors.write().insert(*bytes, id);
        Ok(id)
    }
}
