use std::{cell::RefCell, collections::HashMap, rc::Rc, sync::Arc};

use anyhow::Result;

use crate::proto::{
    grouping::{Range, RangeEnd, ThreeDRange},
    keys::{NamespaceSecretKey, NamespaceSignature, UserId, UserSecretKey, UserSignature},
    meadowcap::{self},
    sync::Fingerprint,
    willow::{AuthorisedEntry, Entry, NamespaceId},
};

#[derive(Debug, Clone, Copy)]
pub struct SyncConfig {
    /// Up to how many values to send immediately, before sending only a fingerprint.
    pub max_set_size: usize,
    /// `k` in the protocol, how many splits to generate. at least 2
    pub split_factor: usize,
}

impl Default for SyncConfig {
    fn default() -> Self {
        SyncConfig {
            max_set_size: 1,
            split_factor: 2,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("store failed: {0}")]
    Store(#[from] anyhow::Error),
    #[error("missing secret key")]
    MissingKey,
}

#[derive(Debug, Copy, Clone)]
pub enum KeyScope {
    Namespace,
    User,
}

pub trait KeyStore: Send + 'static {
    fn insert(&mut self, secret: meadowcap::SecretKey) -> Result<(), KeyStoreError>;
    fn sign_user(&self, id: &UserId, message: &[u8]) -> Result<UserSignature, KeyStoreError>;
    fn sign_namespace(
        &self,
        id: &NamespaceId,
        message: &[u8],
    ) -> Result<NamespaceSignature, KeyStoreError>;
}

pub trait Store: ReadonlyStore + 'static {
    type Snapshot: ReadonlyStore + Clone + Send;

    fn snapshot(&mut self) -> Result<Self::Snapshot>;
    fn ingest_entry(&mut self, entry: &AuthorisedEntry) -> Result<bool>;
}

pub trait ReadonlyStore: Send + 'static {
    fn fingerprint(&self, namespace: NamespaceId, range: &ThreeDRange) -> Result<Fingerprint>;

    fn split_range(
        &self,
        namespace: NamespaceId,
        range: &ThreeDRange,
        config: &SyncConfig,
    ) -> Result<impl Iterator<Item = Result<RangeSplit>>>;

    fn count(&self, namespace: NamespaceId, range: &ThreeDRange) -> Result<u64>;

    fn get_entries_with_authorisation<'a>(
        &'a self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> impl Iterator<Item = Result<AuthorisedEntry>> + 'a;

    fn get_entries<'a>(
        &'a self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> impl Iterator<Item = Result<Entry>> + 'a {
        self.get_entries_with_authorisation(namespace, range)
            .map(|e| e.map(|e| e.into_entry()))
    }
}

#[derive(Debug)]
pub struct Shared<S>(Rc<RefCell<S>>);

impl<S> Clone for Shared<S> {
    fn clone(&self) -> Self {
        Self(Rc::clone(&self.0))
    }
}

impl<S> Shared<S> {
    pub fn new(inner: S) -> Self {
        Self(Rc::new(RefCell::new(inner)))
    }
}

impl<S: Store> Shared<S> {
    pub fn snapshot(&self) -> Result<S::Snapshot> {
        Ok(self.0.borrow_mut().snapshot()?)
    }

    pub fn ingest_entry(&self, entry: &AuthorisedEntry) -> Result<bool> {
        self.0.borrow_mut().ingest_entry(entry)
    }
    pub fn fingerprint(&self, namespace: NamespaceId, range: &ThreeDRange) -> Result<Fingerprint> {
        self.0.borrow().fingerprint(namespace, range)
    }

    // pub fn split_range(
    //     &self,
    //     namespace: NamespaceId,
    //     range: &ThreeDRange,
    //     config: &SyncConfig,
    // ) -> Result<impl Iterator<Item = Result<RangeSplit>>> {
    //     let this = self.clone();
    //     this.0.borrow().split_range(namespace, range, config)
    // }
    //
    // pub fn count(&self, namespace: NamespaceId, range: &ThreeDRange) -> Result<u64> {
    //     self.0.borrow().count(namespace, range)
    // }
    //
    // pub fn get_entries_with_authorisation<'a>(
    //     &'a self,
    //     namespace: NamespaceId,
    //     range: &ThreeDRange,
    // ) -> impl Iterator<Item = Result<AuthorisedEntry>> + 'a {
    //     self.0.borrow().count(namespace, range)
    // }
    //
    // fn get_entries<'a>(
    //     &'a self,
    //     namespace: NamespaceId,
    //     range: &ThreeDRange,
    // ) -> impl Iterator<Item = Result<Entry>> + 'a {
    //     self.get_entries_with_authorisation(namespace, range)
    //         .map(|e| e.map(|e| e.into_entry()))
    // }
}

impl<S: KeyStore> Shared<S> {
    pub fn insert(&mut self, secret: meadowcap::SecretKey) -> Result<(), KeyStoreError> {
        self.0.borrow_mut().insert(secret)
    }

    pub fn sign_user(&self, id: &UserId, message: &[u8]) -> Result<UserSignature, KeyStoreError> {
        self.0.borrow().sign_user(id, message)
    }

    pub fn sign_namespace(
        &self,
        id: &NamespaceId,
        message: &[u8],
    ) -> Result<NamespaceSignature, KeyStoreError> {
        self.0.borrow().sign_namespace(id, message)
    }
}

#[derive(Debug, Default)]
pub struct MemoryKeyStore {
    user: HashMap<UserId, UserSecretKey>,
    namespace: HashMap<NamespaceId, NamespaceSecretKey>,
}

impl KeyStore for MemoryKeyStore {
    fn insert(&mut self, secret: meadowcap::SecretKey) -> Result<(), KeyStoreError> {
        Ok(match secret {
            meadowcap::SecretKey::User(secret) => {
                self.user.insert(secret.id(), secret);
            }
            meadowcap::SecretKey::Namespace(secret) => {
                self.namespace.insert(secret.id(), secret);
            }
        })
    }

    fn sign_user(&self, id: &UserId, message: &[u8]) -> Result<UserSignature, KeyStoreError> {
        Ok(self
            .user
            .get(id)
            .ok_or(KeyStoreError::MissingKey)?
            .sign(message))
    }

    fn sign_namespace(
        &self,
        id: &NamespaceId,
        message: &[u8],
    ) -> Result<NamespaceSignature, KeyStoreError> {
        Ok(self
            .namespace
            .get(id)
            .ok_or(KeyStoreError::MissingKey)?
            .sign(message))
    }
}

#[derive(Debug, Default)]
pub struct MemoryStore {
    entries: HashMap<NamespaceId, Vec<AuthorisedEntry>>,
}

impl ReadonlyStore for MemoryStore {
    fn fingerprint(&self, namespace: NamespaceId, range: &ThreeDRange) -> Result<Fingerprint> {
        let mut fingerprint = Fingerprint::default();
        for entry in self.get_entries(namespace, range) {
            let entry = entry?;
            fingerprint.add_entry(&entry);
        }
        Ok(fingerprint)
    }

    fn split_range(
        &self,
        namespace: NamespaceId,
        range: &ThreeDRange,
        config: &SyncConfig,
    ) -> Result<impl Iterator<Item = Result<RangeSplit>>> {
        let count = self.get_entries(namespace, range).count();
        if count <= config.max_set_size {
            return Ok(
                vec![Ok((range.clone(), SplitAction::SendEntries(count as u64)))].into_iter(),
            );
        }
        let mut entries: Vec<Entry> = self
            .get_entries(namespace, range)
            .filter_map(|e| e.ok())
            .collect();

        entries.sort_by(|e1, e2| e1.as_set_sort_tuple().cmp(&e2.as_set_sort_tuple()));

        let split_index = count / 2;
        let mid = entries.get(split_index).expect("not empty");
        let mut ranges = vec![];
        // split in two halves by subspace
        if mid.subspace_id != range.subspaces.start {
            ranges.push(ThreeDRange::new(
                Range::new(range.subspaces.start, RangeEnd::Closed(mid.subspace_id)),
                range.paths.clone(),
                range.times.clone(),
            ));
            ranges.push(ThreeDRange::new(
                Range::new(mid.subspace_id, range.subspaces.end),
                range.paths.clone(),
                range.times.clone(),
            ));
        }
        // split by path
        else if mid.path != range.paths.start {
            ranges.push(ThreeDRange::new(
                range.subspaces.clone(),
                Range::new(
                    range.paths.start.clone(),
                    RangeEnd::Closed(mid.path.clone()),
                ),
                range.times.clone(),
            ));
            ranges.push(ThreeDRange::new(
                range.subspaces.clone(),
                Range::new(mid.path.clone(), range.paths.end.clone()),
                range.times.clone(),
            ));
        // split by time
        } else {
            ranges.push(ThreeDRange::new(
                range.subspaces.clone(),
                range.paths.clone(),
                Range::new(range.times.start, RangeEnd::Closed(mid.timestamp)),
            ));
            ranges.push(ThreeDRange::new(
                range.subspaces.clone(),
                range.paths.clone(),
                Range::new(mid.timestamp, range.times.end),
            ));
        }
        let mut out = vec![];
        for range in ranges {
            let fingerprint = self.fingerprint(namespace, &range)?;
            out.push(Ok((range, SplitAction::SendFingerprint(fingerprint))));
        }
        Ok(out.into_iter())
    }

    fn count(&self, namespace: NamespaceId, range: &ThreeDRange) -> Result<u64> {
        Ok(self.get_entries(namespace, range).count() as u64)
    }

    fn get_entries_with_authorisation<'a>(
        &'a self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> impl Iterator<Item = Result<AuthorisedEntry>> + 'a {
        self.entries
            .get(&namespace)
            .into_iter()
            .flatten()
            .filter(|entry| range.includes_entry(entry.entry()))
            .map(|e| Result::<_, anyhow::Error>::Ok(e.clone()))
            .collect::<Vec<_>>()
            .into_iter()
    }
}

impl ReadonlyStore for Arc<MemoryStore> {
    fn fingerprint(&self, namespace: NamespaceId, range: &ThreeDRange) -> Result<Fingerprint> {
        MemoryStore::fingerprint(&self, namespace, range)
    }

    fn split_range(
        &self,
        namespace: NamespaceId,
        range: &ThreeDRange,
        config: &SyncConfig,
    ) -> Result<impl Iterator<Item = Result<RangeSplit>>> {
        MemoryStore::split_range(&self, namespace, range, config)
    }

    fn count(&self, namespace: NamespaceId, range: &ThreeDRange) -> Result<u64> {
        MemoryStore::count(&self, namespace, range)
    }

    fn get_entries_with_authorisation<'a>(
        &'a self,
        namespace: NamespaceId,
        range: &ThreeDRange,
    ) -> impl Iterator<Item = Result<AuthorisedEntry>> + 'a {
        MemoryStore::get_entries_with_authorisation(&self, namespace, range)
    }
}

impl Store for MemoryStore {
    type Snapshot = Arc<Self>;
    // type KeyStore = MemoryKeyStore;
    fn snapshot(&mut self) -> Result<Self::Snapshot> {
        Ok(Arc::new(Self {
            entries: self.entries.clone(),
        }))
    }
    // fn key_store(&mut self) -> &mut Self::KeyStore {
    //     &mut self.keys
    // }
    fn ingest_entry(&mut self, entry: &AuthorisedEntry) -> Result<bool> {
        let entries = self.entries.entry(entry.namespace_id()).or_default();
        let new = entry.entry();
        let mut to_remove = vec![];
        for (i, existing) in entries.iter().enumerate() {
            let existing = existing.entry();
            if existing.subspace_id == new.subspace_id
                && existing.path.is_prefix_of(&new.path)
                && existing.is_newer_than(new)
            {
                // we cannot insert the entry, a newer entry exists
                return Ok(false);
            }
            if new.subspace_id == existing.subspace_id
                && new.path.is_prefix_of(&existing.path)
                && new.is_newer_than(existing)
            {
                to_remove.push(i);
            }
        }
        for i in to_remove {
            entries.remove(i);
        }
        entries.push(entry.clone());
        Ok(true)
    }
}

pub type RangeSplit = (ThreeDRange, SplitAction);

#[derive(Debug)]
pub enum SplitAction {
    SendFingerprint(Fingerprint),
    SendEntries(u64),
}
