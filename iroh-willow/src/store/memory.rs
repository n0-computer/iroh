//! In-memory storage implementation for testing purposes.
//!
//! This is a minimal, but spec-compliant (unless there's bugs) implementation of a willow store.
//!
//! It does not have good performance, it does a lot of iterating. But it is concise and can
//! hopefully easily kept correct.

use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    pin::Pin,
    rc::{Rc, Weak},
    task::{ready, Context, Poll, Waker},
};

use anyhow::Result;
use futures_util::Stream;
use tracing::debug;

use super::{
    traits::{StoreEvent, SubscribeParams},
    EntryOrigin,
};
use crate::{
    interest::{CapSelector, CapabilityPack},
    proto::{
        data_model::{AuthorisedEntry, Path, PathExt, SubspaceId, WriteCapability},
        grouping::{Area, Range3d},
        keys::{NamespaceId, NamespaceSecretKey, UserId, UserSecretKey},
        meadowcap::{self, is_wider_than, ReadAuthorisation},
    },
    store::traits,
};

#[derive(Debug, Clone, Default)]
pub struct Store<PS> {
    secrets: Rc<RefCell<SecretStore>>,
    entries: Rc<RefCell<EntryStore>>,
    payloads: PS,
    caps: Rc<RefCell<CapsStore>>,
}

impl<PS: iroh_blobs::store::Store> Store<PS> {
    pub fn new(payloads: PS) -> Self {
        Self {
            payloads,
            secrets: Default::default(),
            entries: Default::default(),
            caps: Default::default(),
        }
    }
}

impl<PS: iroh_blobs::store::Store> traits::Storage for Store<PS> {
    type Entries = Rc<RefCell<EntryStore>>;
    type Secrets = Rc<RefCell<SecretStore>>;
    type Payloads = PS;
    type Caps = Rc<RefCell<CapsStore>>;

    fn entries(&self) -> &Self::Entries {
        &self.entries
    }

    fn secrets(&self) -> &Self::Secrets {
        &self.secrets
    }

    fn payloads(&self) -> &Self::Payloads {
        &self.payloads
    }

    fn caps(&self) -> &Self::Caps {
        &self.caps
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

    fn get_user(&self, id: &UserId) -> Result<Option<UserSecretKey>> {
        Ok(self.borrow().user.get(id).cloned())
    }

    fn get_namespace(&self, id: &NamespaceId) -> Result<Option<NamespaceSecretKey>> {
        Ok(self.borrow().namespace.get(id).cloned())
    }
}

#[derive(Debug, Default)]
pub struct EntryStore {
    stores: HashMap<NamespaceId, NamespaceStore>,
}

#[derive(Debug, Default)]
pub struct NamespaceStore {
    entries: Vec<AuthorisedEntry>,
    events: EventQueue<StoreEvent>,
}

// impl<T: std::ops::Deref<Target = MemoryEntryStore> + 'static> ReadonlyStore for T {
impl traits::EntryReader for Rc<RefCell<EntryStore>> {
    fn get_authorised_entries<'a>(
        &'a self,
        namespace: NamespaceId,
        range: &Range3d,
    ) -> Result<impl Iterator<Item = Result<AuthorisedEntry>> + 'a> {
        let slf = self.borrow();
        Ok(slf
            .stores
            .get(&namespace)
            .map(|s| &s.entries)
            .into_iter()
            .flatten()
            .filter(|entry| range.includes_entry(entry.entry()))
            .map(|e| anyhow::Result::Ok(e.clone()))
            .collect::<Vec<_>>()
            .into_iter())
    }

    fn get_entry(
        &self,
        namespace: NamespaceId,
        subspace: SubspaceId,
        path: &Path,
    ) -> Result<Option<AuthorisedEntry>> {
        let inner = self.borrow();
        let Some(entries) = inner.stores.get(&namespace) else {
            return Ok(None);
        };
        Ok(entries
            .entries
            .iter()
            .find(|e| {
                let e = e.entry();
                *e.namespace_id() == namespace && *e.subspace_id() == subspace && e.path() == path
            })
            .cloned())
    }
}

impl EntryStore {
    fn ingest_entry(&mut self, entry: &AuthorisedEntry, origin: EntryOrigin) -> Result<bool> {
        let store = self
            .stores
            .entry(*entry.entry().namespace_id())
            .or_default();
        let entries = &mut store.entries;
        let new = entry.entry();
        let mut to_prune = vec![];
        for (i, existing) in entries.iter().enumerate() {
            let existing = existing.entry();
            if existing == new {
                return Ok(false);
            }
            if existing.subspace_id() == new.subspace_id()
                && existing.path().is_prefix_of(new.path())
                && existing.is_newer_than(new)
            {
                // we cannot insert the entry, a newer entry exists
                debug!(subspace=%entry.entry().subspace_id().fmt_short(), path=%entry.entry().path().fmt_utf8(), "skip ingest, already pruned");
                return Ok(false);
            }
            if new.subspace_id() == existing.subspace_id()
                && new.path().is_prefix_of(existing.path())
                && new.is_newer_than(existing)
            {
                to_prune.push(i);
            }
        }
        let pruned_count = to_prune.len();
        for i in to_prune {
            let pruned = entries.remove(i);
            store.events.insert(move |id| {
                StoreEvent::Pruned(
                    id,
                    traits::PruneEvent {
                        pruned,
                        by: entry.clone(),
                    },
                )
            });
        }
        entries.push(entry.clone());
        debug!(subspace=%entry.entry().subspace_id().fmt_short(), path=%entry.entry().path().fmt_utf8(), pruned=pruned_count, total=entries.len(), "ingest entry");
        store
            .events
            .insert(|id| StoreEvent::Ingested(id, entry.clone(), origin));
        Ok(true)
    }
}

impl traits::EntryStorage for Rc<RefCell<EntryStore>> {
    type Snapshot = Self;
    type Reader = Self;

    fn reader(&self) -> Self::Reader {
        self.clone()
    }

    fn snapshot(&self) -> Result<Self::Snapshot> {
        // This is quite ugly. But this is a quick memory impl only.
        // But we should really maybe strive to not expose snapshots.
        let stores = self
            .borrow()
            .stores
            .iter()
            .map(|(key, value)| {
                (
                    *key,
                    NamespaceStore {
                        entries: value.entries.clone(),
                        events: Default::default(),
                    },
                )
            })
            .collect();
        Ok(Rc::new(RefCell::new(EntryStore { stores })))
    }

    fn ingest_entry(&self, entry: &AuthorisedEntry, origin: EntryOrigin) -> Result<bool> {
        let mut slf = self.borrow_mut();
        slf.ingest_entry(entry, origin)
    }

    fn subscribe_area(
        &self,
        namespace: NamespaceId,
        area: Area,
        params: SubscribeParams,
    ) -> impl Stream<Item = traits::StoreEvent> + Unpin + 'static {
        let progress_id = self
            .borrow_mut()
            .stores
            .entry(namespace)
            .or_default()
            .events
            .next_progress_id();
        EventStream {
            area,
            params,
            namespace,
            progress_id,
            store: Rc::downgrade(self),
        }
    }

    fn resume_subscription(
        &self,
        progress_id: u64,
        namespace: NamespaceId,
        area: Area,
        params: SubscribeParams,
    ) -> impl Stream<Item = traits::StoreEvent> + Unpin + 'static {
        EventStream {
            area,
            params,
            progress_id,
            namespace,
            store: Rc::downgrade(self),
        }
    }
}

/// Stream of events from a store subscription.
///
/// We have weak pointer to the entry store and thus the EventQueue.
/// Once the store is dropped, the EventQueue wakes all streams a last time in its drop impl,
/// which then makes the stream return none because Weak::upgrade returns None.
#[derive(Debug)]
struct EventStream {
    progress_id: u64,
    store: Weak<RefCell<EntryStore>>,
    namespace: NamespaceId,
    area: Area,
    params: SubscribeParams,
}

impl Stream for EventStream {
    type Item = StoreEvent;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Some(inner) = self.store.upgrade() else {
            return Poll::Ready(None);
        };
        let mut inner_mut = inner.borrow_mut();
        let store = inner_mut.stores.entry(self.namespace).or_default();
        let res = ready!(store.events.poll_next(
            self.progress_id,
            |e| e.matches(self.namespace, &self.area, &self.params),
            cx,
        ));
        drop(inner_mut);
        drop(inner);
        Poll::Ready(match res {
            None => None,
            Some((next_id, event)) => {
                self.progress_id = next_id;
                Some(event)
            }
        })
    }
}

/// A simple in-memory event queue.
///
/// Events can be pushed, and get a unique monotonically-increasing *progress id*.
/// Events can be polled, with a progress id to start at, and an optional filter function.
///
/// Current in-memory impl keeps all events, forever.
// TODO: Add max_len constructor, add a way to truncate old entries.
// TODO: This would be quite a bit more efficient if we filtered the waker with a closure
// that is set from the last poll, to not wake everyone for each new event.
#[derive(Debug)]
pub(crate) struct EventQueue<T> {
    events: VecDeque<T>,
    offset: u64,
    wakers: VecDeque<Waker>,
}

impl<T> Drop for EventQueue<T> {
    fn drop(&mut self) {
        for waker in self.wakers.drain(..) {
            waker.wake()
        }
    }
}

impl<T> Default for EventQueue<T> {
    fn default() -> Self {
        Self {
            events: Default::default(),
            offset: 0,
            wakers: Default::default(),
        }
    }
}

impl<T: Clone> EventQueue<T> {
    pub(crate) fn insert(&mut self, f: impl FnOnce(u64) -> T) {
        let progress_id = self.next_progress_id();
        let event = f(progress_id);
        self.events.push_back(event);
        for waker in self.wakers.drain(..) {
            waker.wake()
        }
    }

    pub(crate) fn next_progress_id(&self) -> u64 {
        self.offset + self.events.len() as u64
    }

    pub(crate) fn get(&self, progress_id: u64) -> Option<&T> {
        let index = progress_id.checked_sub(self.offset)?;
        self.events.get(index as usize)
    }

    pub(crate) fn poll_next(
        &mut self,
        progress_id: u64,
        filter: impl Fn(&T) -> bool,
        cx: &mut Context<'_>,
    ) -> Poll<Option<(u64, T)>> {
        if progress_id < self.offset {
            return Poll::Ready(None);
        }
        let mut i = progress_id;
        loop {
            if let Some(event) = self.get(i) {
                i += 1;
                if filter(event) {
                    break Poll::Ready(Some((i, event.clone())));
                }
            } else {
                self.wakers.push_back(cx.waker().clone());
                break Poll::Pending;
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct CapsStore {
    write_caps: HashMap<NamespaceId, Vec<WriteCapability>>,
    read_caps: HashMap<NamespaceId, Vec<ReadAuthorisation>>,
}

impl CapsStore {
    fn get_write_cap(&self, selector: &CapSelector) -> Result<Option<WriteCapability>> {
        let candidates = self
            .write_caps
            .get(&selector.namespace_id)
            .into_iter()
            .flatten()
            .filter(|cap| selector.is_covered_by(cap));

        // Select the best candidate, by sorting for
        // * first: widest area
        // * then: smallest number of delegations
        let best = candidates.reduce(|prev, next| {
            if is_wider_than(next, prev) {
                next
            } else {
                prev
            }
        });
        Ok(best.cloned())
    }

    fn get_read_cap(&self, selector: &CapSelector) -> Result<Option<ReadAuthorisation>> {
        let candidates = self
            .read_caps
            .get(&selector.namespace_id)
            .into_iter()
            .flatten()
            .filter(|auth| selector.is_covered_by(auth.read_cap()));

        // Select the best candidate, by sorting for
        // * widest area
        let best = candidates.reduce(|prev, next| {
            if is_wider_than(next.read_cap(), prev.read_cap()) {
                next
            } else {
                prev
            }
        });

        Ok(best.cloned())
    }

    fn list_write_caps(
        &self,
        namespace: Option<NamespaceId>,
    ) -> Result<impl Iterator<Item = WriteCapability> + 'static> {
        let caps = if let Some(namespace) = namespace {
            self.write_caps.get(&namespace).cloned().unwrap_or_default()
        } else {
            self.write_caps.values().flatten().cloned().collect()
        };
        Ok(caps.into_iter())
    }

    fn list_read_caps(
        &self,
        namespace: Option<NamespaceId>,
    ) -> Result<impl Iterator<Item = ReadAuthorisation> + 'static> {
        let caps = if let Some(namespace) = namespace {
            self.read_caps.get(&namespace).cloned().unwrap_or_default()
        } else {
            self.read_caps.values().flatten().cloned().collect()
        };
        Ok(caps.into_iter())
    }

    fn insert(&mut self, cap: CapabilityPack) {
        match cap {
            CapabilityPack::Read(cap) => {
                self.read_caps
                    .entry(*cap.read_cap().granted_namespace())
                    .or_default()
                    .push(cap);
            }
            CapabilityPack::Write(cap) => {
                self.write_caps
                    .entry(*cap.granted_namespace())
                    .or_default()
                    .push(cap);
            }
        }
    }
}

impl traits::CapsStorage for Rc<RefCell<CapsStore>> {
    fn insert(&self, cap: CapabilityPack) -> Result<()> {
        self.borrow_mut().insert(cap);
        Ok(())
    }

    fn list_read_caps(
        &self,
        namespace: Option<NamespaceId>,
    ) -> Result<impl Iterator<Item = ReadAuthorisation>> {
        self.borrow().list_read_caps(namespace)
    }

    fn list_write_caps(
        &self,
        namespace: Option<NamespaceId>,
    ) -> Result<impl Iterator<Item = WriteCapability>> {
        self.borrow().list_write_caps(namespace)
    }

    fn get_write_cap(&self, selector: &CapSelector) -> Result<Option<WriteCapability>> {
        self.borrow().get_write_cap(selector)
    }

    fn get_read_cap(&self, selector: &CapSelector) -> Result<Option<ReadAuthorisation>> {
        self.borrow().get_read_cap(selector)
    }
}
