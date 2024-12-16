use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};

use iroh_base::PublicKey;

type SignatureError = <PublicKey as TryFrom<&'static [u8]>>::Error;
type PublicKeyBytes = [u8; PublicKey::LENGTH];

/// A cache for public keys.
#[derive(Debug, Clone, Default)]
pub enum KeyCache {
    /// The key cache is disabled.
    #[default]
    Disabled,
    /// The key cache is enabled with a fixed capacity. It is shared between
    /// multiple threads.
    Shared(Arc<Mutex<lru::LruCache<PublicKey, ()>>>),
}

impl KeyCache {
    /// Key cache to be used in tests.
    #[cfg(test)]
    pub fn test() -> Self {
        Self::Disabled
    }

    /// Create a new key cache with the given capacity.
    ///
    /// If the capacity is zero, the cache is disabled and has zero overhead.
    pub fn new(capacity: usize) -> Self {
        let Some(capacity) = NonZeroUsize::new(capacity) else {
            return Self::Disabled;
        };
        let cache = lru::LruCache::new(capacity);
        Self::Shared(Arc::new(Mutex::new(cache)))
    }

    /// Get a key from a slice of bytes.
    pub fn key_from_slice(&self, slice: &[u8]) -> Result<PublicKey, SignatureError> {
        let Self::Shared(cache) = self else {
            return PublicKey::try_from(slice);
        };
        let Ok(bytes) = PublicKeyBytes::try_from(slice) else {
            PublicKey::try_from(slice)?;
            unreachable!();
        };
        let mut cache = cache.lock().unwrap();
        if let Some((key, _)) = cache.get_key_value(&bytes) {
            return Ok(key.clone());
        }
        let key = PublicKey::from_bytes(&bytes)?;
        cache.put(key.clone(), ());
        Ok(key)
    }
}
