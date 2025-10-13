use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};

use iroh_base::PublicKey;

type SignatureError = <PublicKey as TryFrom<&'static [u8]>>::Error;
type PublicKeyBytes = [u8; PublicKey::LENGTH];

/// A cache for public keys.
///
/// This is used solely to make parsing public keys from byte slices more
/// efficient for the very common case where a large number of identical keys
/// are being parsed, like in the relay server.
///
/// The cache stores only successful parse results.
#[derive(Debug, Clone)]
pub enum KeyCache {
    /// The key cache is disabled.
    Disabled,
    /// The key cache is enabled with a fixed capacity. It is shared between
    /// multiple threads.
    Shared(Arc<Mutex<lru::LruCache<PublicKey, ()>>>),
}

impl KeyCache {
    /// Key cache to be used in tests.
    #[cfg(all(test, feature = "server"))]
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
            // if the size is wrong, use PublicKey::try_from to fail with a
            // SignatureError.
            return Err(PublicKey::try_from(slice).expect_err("invalid length"));
        };
        let mut cache = cache.lock().expect("not poisoned");
        if let Some((key, _)) = cache.get_key_value(&bytes) {
            return Ok(*key);
        }
        let key = PublicKey::from_bytes(&bytes)?;
        cache.put(key, ());
        Ok(key)
    }
}
