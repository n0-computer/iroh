//! This module implements a map that can be modified from only one task but read from many others.
//!
//! We ensure this map avoids race conditions from multiple writers by doing these two things:
//! - We only allow writing from one owner of the `&mut self` [`ConcurrentReadMap`].
//!   It cannot be cloned.
//! - The read-only replicas [`ReadOnlyMap`] can only read, not write, but allow reading from
//!   concurrent tasks.

use std::{hash::Hash, sync::Arc};

use rustc_hash::FxBuildHasher;

/// A map that can be modified from only one task but read from many others.
///
/// Only the single `&mut self`-based "leader" which owns this map can modify it, but cheaply
/// clonable "followers" can be created with [`ConcurrentReadMap::read_only`].
/// These clones will update with recent writes from the leader.
#[derive(Debug)]
pub(crate) struct ConcurrentReadMap<K: Hash + Eq, V>(Arc<papaya::HashMap<K, V, FxBuildHasher>>);

impl<K: Hash + Eq, V> Default for ConcurrentReadMap<K, V> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<K: Hash + Eq, V> ConcurrentReadMap<K, V> {
    pub(crate) fn get_or_insert_with<F>(&mut self, key: K, f: F) -> V
    where
        F: FnOnce() -> V,
        V: Clone,
    {
        self.0.get_or_insert_with(key, f, &self.0.guard()).clone()
    }

    pub(crate) fn insert(&mut self, key: K, value: V) {
        self.0.insert(key, value, &self.0.guard());
    }

    pub(crate) fn remove(&mut self, key: &K) {
        self.0.remove(key, &self.0.guard());
    }

    pub(crate) fn get(&self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        self.0.get(key, &self.0.guard()).cloned()
    }

    pub(crate) fn read_only(&self) -> ReadOnlyMap<K, V> {
        ReadOnlyMap(self.0.clone())
    }
}

/// A read replica for a [`ConcurrentReadMap`].
///
/// These can be cloned cheaply and will read recent writes from the original map.
#[derive(Clone, Debug)]
pub(crate) struct ReadOnlyMap<K: Hash + Eq, V>(Arc<papaya::HashMap<K, V, FxBuildHasher>>);

impl<K: Hash + Eq, V> ReadOnlyMap<K, V> {
    pub(crate) fn get(&self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        self.0.get(key, &self.0.guard()).cloned()
    }

    pub(crate) fn guard(&self) -> papaya::LocalGuard<'_> {
        self.0.guard()
    }

    pub(crate) fn values<'g, G: papaya::Guard>(&self, guard: &'g G) -> papaya::Values<'g, K, V, G> {
        self.0.values(guard)
    }
}
