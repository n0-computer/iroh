use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use anyhow::Result;

use crate::{
    proto::{
        grouping::{Range, RangeEnd, ThreeDRange},
        keys::{NamespaceSecretKey, UserId, UserSecretKey},
        meadowcap,
        sync::Fingerprint,
        willow::{AuthorisedEntry, Entry, NamespaceId},
    },
    store::traits::{self, RangeSplit, SplitAction, SplitOpts},
};

#[derive(Debug, Clone, Default)]
pub struct Store {
    secrets: Rc<RefCell<SecretStore>>,
    entries: Rc<RefCell<EntryStore>>,
    payloads: iroh_blobs::store::mem::Store,
}

impl Store {
    pub fn new(payloads: iroh_blobs::store::mem::Store) -> Self {
        Self {
            payloads,
            secrets: Default::default(),
            entries: Default::default(),
        }
    }
}

impl traits::Storage for Store {
    type Entries = Rc<RefCell<EntryStore>>;
    type Secrets = Rc<RefCell<SecretStore>>;
    type Payloads = iroh_blobs::store::mem::Store;

    fn entries(&self) -> &Self::Entries {
        &self.entries
    }

    fn secrets(&self) -> &Self::Secrets {
        &self.secrets
    }

    fn payloads(&self) -> &Self::Payloads {
        &self.payloads
    }
}

#[derive(Debug, Default)]
pub struct SecretStore {
    user: HashMap<UserId, UserSecretKey>,
    namespace: HashMap<NamespaceId, NamespaceSecretKey>,
}

impl traits::SecretStorage for Rc<RefCell<SecretStore>> {
    fn insert(&self, secret: meadowcap::SecretKey) -> Result<(), traits::SecretStoreError> {
        let mut slf = self.borrow_mut();
        match secret {
            meadowcap::SecretKey::User(secret) => {
                slf.user.insert(secret.id(), secret);
            }
            meadowcap::SecretKey::Namespace(secret) => {
                slf.namespace.insert(secret.id(), secret);
            }
        };
        Ok(())
    }

    fn get_user(&self, id: &UserId) -> Option<UserSecretKey> {
        self.borrow().user.get(id).cloned()
    }

    fn get_namespace(&self, id: &NamespaceId) -> Option<NamespaceSecretKey> {
        self.borrow().namespace.get(id).cloned()
    }
}

#[derive(Debug, Default)]
pub struct EntryStore {
    entries: HashMap<NamespaceId, Vec<AuthorisedEntry>>,
}

// impl<T: std::ops::Deref<Target = MemoryEntryStore> + 'static> ReadonlyStore for T {
impl traits::EntryReader for Rc<RefCell<EntryStore>> {
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
        config: &SplitOpts,
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
                range.times,
            ));
            ranges.push(ThreeDRange::new(
                Range::new(mid.subspace_id, range.subspaces.end),
                range.paths.clone(),
                range.times,
            ));
        }
        // split by path
        else if mid.path != range.paths.start {
            ranges.push(ThreeDRange::new(
                range.subspaces,
                Range::new(
                    range.paths.start.clone(),
                    RangeEnd::Closed(mid.path.clone()),
                ),
                range.times,
            ));
            ranges.push(ThreeDRange::new(
                range.subspaces,
                Range::new(mid.path.clone(), range.paths.end.clone()),
                range.times,
            ));
        // split by time
        } else {
            ranges.push(ThreeDRange::new(
                range.subspaces,
                range.paths.clone(),
                Range::new(range.times.start, RangeEnd::Closed(mid.timestamp)),
            ));
            ranges.push(ThreeDRange::new(
                range.subspaces,
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
        let slf = self.borrow();
        slf.entries
            .get(&namespace)
            .into_iter()
            .flatten()
            .filter(|entry| range.includes_entry(entry.entry()))
            .map(|e| Result::<_, anyhow::Error>::Ok(e.clone()))
            .collect::<Vec<_>>()
            .into_iter()
    }
}

impl traits::EntryStorage for Rc<RefCell<EntryStore>> {
    type Snapshot = Self;
    type Reader = Self;

    fn reader(&self) -> Self::Reader {
        self.clone()
    }

    fn snapshot(&self) -> Result<Self::Snapshot> {
        let entries = self.borrow().entries.clone();
        Ok(Rc::new(RefCell::new(EntryStore { entries })))
    }

    fn ingest_entry(&self, entry: &AuthorisedEntry) -> Result<bool> {
        let mut slf = self.borrow_mut();
        let entries = slf.entries.entry(entry.namespace_id()).or_default();
        let new = entry.entry();
        let mut to_remove = vec![];
        for (i, existing) in entries.iter().enumerate() {
            let existing = existing.entry();
            if existing == new {
                return Ok(false);
            }
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
