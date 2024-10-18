//! In-memory storage implementation for testing purposes.
//!
//! This is a minimal, but spec-compliant (unless there's bugs) implementation of a willow store.
//!
//! It does not have good performance, it does a lot of iterating. But it is concise and can
//! hopefully easily kept correct.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::task::{Context, Poll, Waker};

use anyhow::Result;
use ed25519_dalek::ed25519;
use futures_lite::ready;
use futures_util::Stream;
use tracing::debug;
use willow_data_model::SubspaceId as _;
use willow_store::{BlobSeq, QueryRange, QueryRange3d};

use crate::proto::data_model::{AuthorisationToken, PathExt};
use crate::proto::grouping::Area;
use crate::store::glue::StoredAuthorisedEntry;
use crate::{
    interest::{CapSelector, CapabilityPack},
    proto::{
        data_model::{AuthorisedEntry, Entry, EntryExt, Path, SubspaceId, WriteCapability},
        grouping::{Range, Range3d, RangeEnd},
        keys::{NamespaceId, NamespaceSecretKey, UserId, UserSecretKey},
        meadowcap::{self, is_wider_than, ReadAuthorisation},
        wgps::Fingerprint,
    },
    store::traits::{self, RangeSplit, SplitAction, SplitOpts},
};

use super::glue::{blobseq_successor, path_to_blobseq, to_query, IrohWillowParams};
use super::traits::{StoreEvent, SubscribeParams};
use super::EntryOrigin;

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

    fn get_user(&self, id: &UserId) -> Option<UserSecretKey> {
        self.borrow().user.get(id).cloned()
    }

    fn get_namespace(&self, id: &NamespaceId) -> Option<NamespaceSecretKey> {
        self.borrow().namespace.get(id).cloned()
    }
}

#[derive(Debug, Clone)]
pub struct EntryStore {
    stores: HashMap<NamespaceId, NamespaceStore>,
    authorisation_tokens: BTreeMap<ed25519::SignatureBytes, AuthorisationToken>,
    store: willow_store::MemStore,
}

impl Default for EntryStore {
    fn default() -> Self {
        Self {
            stores: Default::default(),
            authorisation_tokens: Default::default(),
            store: willow_store::MemStore::new(),
        }
    }
}

#[derive(Debug)]
pub struct NamespaceStore {
    entries: willow_store::Node<IrohWillowParams>,
    events: EventQueue<StoreEvent>,
}

impl Clone for NamespaceStore {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            events: Default::default(),
        }
    }
}

impl Default for NamespaceStore {
    fn default() -> Self {
        Self {
            entries: willow_store::Node::EMPTY,
            events: Default::default(),
        }
    }
}

// impl<T: std::ops::Deref<Target = MemoryEntryStore> + 'static> ReadonlyStore for T {
impl traits::EntryReader for Rc<RefCell<EntryStore>> {
    fn fingerprint(&self, namespace: NamespaceId, range: &Range3d) -> Result<Fingerprint> {
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
        range: &Range3d,
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

        entries.sort_by(|e1, e2| e1.as_sortable_tuple().cmp(&e2.as_sortable_tuple()));

        let split_index = count / 2;
        let mid = entries.get(split_index).expect("not empty");
        let mut ranges = vec![];
        // split in two halves by subspace
        if *mid.subspace_id() != range.subspaces().start {
            ranges.push(Range3d::new(
                Range::new_closed(range.subspaces().start, *mid.subspace_id()).unwrap(),
                range.paths().clone(),
                *range.times(),
            ));
            ranges.push(Range3d::new(
                Range::new(*mid.subspace_id(), range.subspaces().end),
                range.paths().clone(),
                *range.times(),
            ));
        }
        // split by path
        else if *mid.path() != range.paths().start {
            ranges.push(Range3d::new(
                *range.subspaces(),
                Range::new(
                    range.paths().start.clone(),
                    RangeEnd::Closed(mid.path().clone()),
                ),
                *range.times(),
            ));
            ranges.push(Range3d::new(
                *range.subspaces(),
                Range::new(mid.path().clone(), range.paths().end.clone()),
                *range.times(),
            ));
        // split by time
        } else {
            ranges.push(Range3d::new(
                *range.subspaces(),
                range.paths().clone(),
                Range::new(range.times().start, RangeEnd::Closed(mid.timestamp())),
            ));
            ranges.push(Range3d::new(
                *range.subspaces(),
                range.paths().clone(),
                Range::new(mid.timestamp(), range.times().end),
            ));
        }
        let mut out = vec![];
        for range in ranges {
            let fingerprint = self.fingerprint(namespace, &range)?;
            out.push(Ok((range, SplitAction::SendFingerprint(fingerprint))));
        }
        Ok(out.into_iter())
    }

    fn count(&self, namespace: NamespaceId, range: &Range3d) -> Result<u64> {
        Ok(self.get_entries(namespace, range).count() as u64)
    }

    fn get_authorised_entries<'a>(
        &'a self,
        namespace: NamespaceId,
        range: &Range3d,
    ) -> impl Iterator<Item = Result<AuthorisedEntry>> + 'a {
        let slf = self.borrow();
        let Some(ns_store) = slf.stores.get(&namespace) else {
            return either::Left(std::iter::empty());
        };
        // TODO(matheus23): Maybe figure out a way to share this more efficiently?
        let atmap = slf.authorisation_tokens.clone();
        either::Right(
            ns_store
                .entries
                .query(&to_query(range), &slf.store)
                .map(move |result| {
                    let (point, stored_entry) = result?;
                    let id = stored_entry.authorisation_token_id;
                    let auth_token = atmap.get(&id).ok_or_else(|| {
                        anyhow::anyhow!(
                            "couldn't find authorisation token id (database inconsistent)"
                        )
                    })?;
                    stored_entry.into_authorised_entry(namespace, &point, auth_token.clone())
                })
                .collect::<Vec<_>>()
                .into_iter(),
        )
    }

    fn get_entry(
        &self,
        namespace: NamespaceId,
        subspace: SubspaceId,
        path: &Path,
    ) -> Result<Option<AuthorisedEntry>> {
        let inner = self.borrow();
        let Some(ns_store) = inner.stores.get(&namespace) else {
            return Ok(None);
        };
        let blobseq = path_to_blobseq(path);
        let end = blobseq_successor(&blobseq);
        let Some(result) = ns_store
            .entries
            .query_ordered(
                &QueryRange3d {
                    x: QueryRange::new(subspace, subspace.successor()),
                    y: QueryRange::all(),
                    z: QueryRange::new(blobseq, Some(end)),
                },
                willow_store::SortOrder::YZX,
                &inner.store,
            )
            .last()
        else {
            return Ok(None);
        };

        let (point, stored_entry) = result?;
        let id = stored_entry.authorisation_token_id;
        let auth_token = inner.authorisation_tokens.get(&id).ok_or_else(|| {
            anyhow::anyhow!("couldn't find authorisation token id (database inconsistent)")
        })?;
        let entry = stored_entry.into_authorised_entry(namespace, &point, auth_token.clone())?;
        Ok(Some(entry))
    }
}

fn blobseq_below(blobseq: &BlobSeq) -> Option<BlobSeq> {
    let mut path = blobseq
        .components()
        .map(|slice| slice.to_vec())
        .collect::<Vec<_>>();

    if path
        .last_mut()
        .map(|last_path| match last_path.last_mut() {
            Some(255) | None => {
                last_path.push(0);
            }
            Some(i) => {
                *i += 1;
            }
        })
        .is_some()
    {
        Some(BlobSeq::from(path))
    } else {
        None
    }
}

impl EntryStore {
    fn ingest_entry(&mut self, entry: &AuthorisedEntry, origin: EntryOrigin) -> Result<bool> {
        let namespace = *entry.entry().namespace_id();
        let ns_store = self.stores.entry(namespace).or_default();

        // Insert auth token & entry:

        self.authorisation_tokens
            .entry(entry.token().signature.to_bytes())
            .or_insert_with(|| entry.token().clone());

        let (insert_point, insert_entry) = StoredAuthorisedEntry::from_authorised_entry(entry);

        let _replaced = ns_store
            .entries
            .insert(&insert_point, &insert_entry, &mut self.store)?;

        // TODO(matheus23): need to get a progress_id here somehow.
        // There's ideas to use the willow-store NodeId for that.

        // Enforce prefix deletion:

        let blobseq_start = path_to_blobseq(entry.entry().path());
        let blobseq_end = blobseq_below(&blobseq_start);

        let overwritten_range = QueryRange3d {
            x: QueryRange::new(
                *entry.entry().subspace_id(),
                entry.entry().subspace_id().successor(),
            ),
            y: QueryRange::new(0, Some(entry.entry().timestamp())),
            z: QueryRange::new(blobseq_start, blobseq_end),
        };

        let prune_candidates = ns_store
            .entries
            .query(&overwritten_range, &self.store)
            .collect::<Result<Vec<_>, _>>()?;

        for (prune_pos, prune_candidate) in prune_candidates {
            let auth_token = self
                .authorisation_tokens
                .get(&prune_candidate.authorisation_token_id)
                .ok_or_else(|| {
                    anyhow::anyhow!("couldn't find authorisation token id (database inconsistent)")
                })?;
            let pruned =
                prune_candidate.into_authorised_entry(namespace, &prune_pos, auth_token.clone())?; // fairly inefficient
            if entry.entry().is_newer_than(pruned.entry()) {
                // TODO(matheus23): Don't *actually* delete here? (depending on a potential traceless bit)
                // There was some idea along the lines of "mark as deleted" by storing the identifier for the deletion.
                ns_store.entries.delete(&prune_pos, &mut self.store)?;
                ns_store.events.insert(move |id| {
                    StoreEvent::Pruned(
                        id,
                        traits::PruneEvent {
                            pruned,
                            by: entry.clone(),
                        },
                    )
                });
            }
        }

        debug!(
            subspace = %entry.entry().subspace_id().fmt_short(),
            path = %entry.entry().path().fmt_utf8(),
            "ingest entry"
        );

        ns_store
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
        Ok(Rc::new(RefCell::new(self.borrow().clone())))
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
struct EventQueue<T> {
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
    fn insert(&mut self, f: impl FnOnce(u64) -> T) {
        let progress_id = self.next_progress_id();
        let event = f(progress_id);
        self.events.push_back(event);
        for waker in self.wakers.drain(..) {
            waker.wake()
        }
    }

    fn next_progress_id(&self) -> u64 {
        self.offset + self.events.len() as u64
    }

    fn get(&self, progress_id: u64) -> Option<&T> {
        let index = progress_id.checked_sub(self.offset)?;
        self.events.get(index as usize)
    }

    fn poll_next(
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
