//! Traits for storage backends for the Willow store.

use std::fmt::Debug;

use anyhow::Result;
use futures_lite::Stream;
use serde::{Deserialize, Serialize};
use willow_data_model::grouping::{Range, RangeEnd};

use crate::{
    interest::{CapSelector, CapabilityPack},
    proto::{
        data_model::{
            self, AuthorisedEntry, Entry, EntryExt as _, NamespaceId, Path, SubspaceId,
            WriteCapability,
        },
        grouping::{Area, Range3d},
        keys::{NamespaceSecretKey, NamespaceSignature, UserId, UserSecretKey, UserSignature},
        meadowcap::{self, ReadAuthorisation},
        wgps::Fingerprint,
    },
};

/// Storage backend.
///
/// This type combines the different stores needed.
pub trait Storage: Debug + Clone + 'static {
    type Entries: EntryStorage;
    type Secrets: SecretStorage;
    type Payloads: iroh_blobs::store::Store;
    type Caps: CapsStorage;
    fn entries(&self) -> &Self::Entries;
    fn secrets(&self) -> &Self::Secrets;
    fn payloads(&self) -> &Self::Payloads;
    fn caps(&self) -> &Self::Caps;
}

/// Storage for user and namespace secrets.
pub trait SecretStorage: Debug + Clone + 'static {
    fn insert(&self, secret: meadowcap::SecretKey) -> Result<(), SecretStoreError>;
    fn get_user(&self, id: &UserId) -> Result<Option<UserSecretKey>>;
    fn get_namespace(&self, id: &NamespaceId) -> Result<Option<NamespaceSecretKey>>;

    fn has_user(&self, id: &UserId) -> Result<bool> {
        Ok(self.get_user(id)?.is_some())
    }

    fn has_namespace(&self, id: &UserId) -> Result<bool> {
        Ok(self.get_user(id)?.is_some())
    }

    fn insert_user(&self, secret: UserSecretKey) -> Result<UserId, SecretStoreError> {
        let id = secret.id();
        self.insert(meadowcap::SecretKey::User(secret))?;
        Ok(id)
    }
    fn insert_namespace(
        &self,
        secret: NamespaceSecretKey,
    ) -> Result<NamespaceId, SecretStoreError> {
        let id = secret.id();
        self.insert(meadowcap::SecretKey::Namespace(secret))?;
        Ok(id)
    }

    fn sign_user(&self, id: &UserId, message: &[u8]) -> Result<UserSignature, SecretStoreError> {
        Ok(self
            .get_user(id)?
            .ok_or(SecretStoreError::MissingKey)?
            .sign(message))
    }
    fn sign_namespace(
        &self,
        id: &NamespaceId,
        message: &[u8],
    ) -> Result<NamespaceSignature, SecretStoreError> {
        Ok(self
            .get_namespace(id)?
            .ok_or(SecretStoreError::MissingKey)?
            .sign(message))
    }
}

/// Storage for entries.
pub trait EntryStorage: EntryReader + Clone + Debug + 'static {
    type Reader: EntryReader;
    type Snapshot: EntryReader + Clone;

    fn reader(&self) -> Self::Reader;
    fn snapshot(&self) -> Result<Self::Snapshot>;

    /// Ingest a new entry.
    ///
    /// Returns `true` if the entry was ingested, and `false` if the entry was not ingested because a newer entry exists.
    fn ingest_entry(&self, entry: &AuthorisedEntry, origin: EntryOrigin) -> Result<bool>;

    /// Subscribe to events concerning entries [included](https://willowprotocol.org/specs/grouping-entries/index.html#area_include)
    /// by an [`AreaOfInterest`], returning a producer of `StoreEvent`s which occurred since the moment of calling this function.
    ///
    /// If `ignore_incomplete_payloads` is `true`, the producer will not produce entries with incomplete corresponding payloads.
    /// If `ignore_empty_payloads` is `true`, the producer will not produce entries with a `payload_length` of `0`.
    fn subscribe_area(
        &self,
        namespace: NamespaceId,
        area: Area,
        params: SubscribeParams,
    ) -> impl Stream<Item = StoreEvent> + Unpin + 'static;

    /// Attempt to resume a subscription using a *progress ID* obtained from a previous subscription, or return an error
    /// if this store implementation is unable to resume the subscription.
    fn resume_subscription(
        &self,
        progress_id: u64,
        namespace: NamespaceId,
        area: Area,
        params: SubscribeParams,
    ) -> impl Stream<Item = StoreEvent> + Unpin + 'static;
}

/// Read-only interface to [`EntryStorage`].
pub trait EntryReader: Debug + 'static {
    fn fingerprint(&self, namespace: NamespaceId, range: &Range3d) -> Result<Fingerprint> {
        let mut fingerprint = Fingerprint::default();
        for entry in self.get_entries(namespace, range)? {
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
        let count = self.count(namespace, range)? as usize;
        if count <= config.max_set_size {
            return Ok(
                vec![Ok((range.clone(), SplitAction::SendEntries(count as u64)))].into_iter(),
            );
        }
        let mut entries: Vec<Entry> = self
            .get_entries(namespace, range)?
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
        Ok(self.get_entries(namespace, range)?.count() as u64)
    }

    fn get_entry(
        &self,
        namespace: NamespaceId,
        subspace: SubspaceId,
        path: &Path,
    ) -> Result<Option<AuthorisedEntry>>;

    fn get_authorised_entries<'a>(
        &'a self,
        namespace: NamespaceId,
        range: &Range3d,
    ) -> Result<impl Iterator<Item = Result<AuthorisedEntry>> + 'a>;

    fn get_entries(
        &self,
        namespace: NamespaceId,
        range: &Range3d,
    ) -> Result<impl Iterator<Item = Result<Entry>>> {
        Ok(self
            .get_authorised_entries(namespace, range)?
            .map(|e| e.map(|e| e.into_parts().0)))
    }
}

/// Error returned from [`SecretStorage`].
#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
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

pub type RangeSplit = (Range3d, SplitAction);

#[derive(Debug)]
pub enum SplitAction {
    SendFingerprint(Fingerprint),
    SendEntries(u64),
}

#[derive(Debug, Clone, Copy)]
pub struct SplitOpts {
    /// Up to how many values to send immediately, before sending only a fingerprint.
    pub max_set_size: usize,
    /// `k` in the protocol, how many splits to generate. at least 2
    pub split_factor: usize,
}

impl Default for SplitOpts {
    fn default() -> Self {
        SplitOpts {
            max_set_size: 1,
            split_factor: 2,
        }
    }
}

/// Capability storage.
pub trait CapsStorage: Debug + Clone {
    fn insert(&self, cap: CapabilityPack) -> Result<()>;

    fn list_read_caps(
        &self,
        namespace: Option<NamespaceId>,
    ) -> Result<impl Iterator<Item = ReadAuthorisation> + '_>;

    fn list_write_caps(
        &self,
        namespace: Option<NamespaceId>,
    ) -> Result<impl Iterator<Item = WriteCapability> + '_>;

    fn get_write_cap(&self, selector: &CapSelector) -> Result<Option<WriteCapability>>;

    fn get_read_cap(&self, selector: &CapSelector) -> Result<Option<ReadAuthorisation>>;
}

/// An event which took place within a [`EntryStorage`].
/// Each event includes a *progress ID* which can be used to *resume* a subscription at any point in the future.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StoreEvent {
    /// A new entry was ingested.
    Ingested(
        u64,
        #[serde(with = "data_model::serde_encoding::authorised_entry")] AuthorisedEntry,
        EntryOrigin,
    ),
    // PayloadForgotten(u64, PD),
    /// An entry was pruned via prefix pruning.
    Pruned(u64, PruneEvent),
    // /// An existing entry received a portion of its corresponding payload.
    // Appended(u64, LengthyAuthorisedEntry),
    // /// An entry was forgotten.
    // EntryForgotten(u64, (S, Path<MCL, MCC, MPL>)),
    // /// A payload was forgotten.
}

impl StoreEvent {
    pub fn progress_id(&self) -> u64 {
        match self {
            StoreEvent::Ingested(id, _, _) => *id,
            StoreEvent::Pruned(id, _) => *id,
        }
    }
}

impl StoreEvent {
    /// Returns `true` if the event is included in the `area` and not skipped by `ignore_params`.
    pub fn matches(
        &self,
        namespace_id: NamespaceId,
        area: &Area,
        params: &SubscribeParams,
    ) -> bool {
        match self {
            StoreEvent::Ingested(_, entry, origin) => {
                *entry.entry().namespace_id() == namespace_id
                    && area.includes_entry(entry.entry())
                    && params.includes_entry(entry.entry())
                    && params.includes_origin(origin)
            }
            StoreEvent::Pruned(_, PruneEvent { pruned, by: _ }) => {
                !params.ingest_only
                    && *pruned.entry().namespace_id() == namespace_id
                    && area.includes_entry(pruned.entry())
            }
        }
    }
}

/// Describes an [`AuthorisedEntry`] which was pruned and the [`AuthorisedEntry`] which triggered the pruning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruneEvent {
    #[serde(with = "data_model::serde_encoding::authorised_entry")]
    pub pruned: AuthorisedEntry,
    /// The entry which triggered the pruning.
    #[serde(with = "data_model::serde_encoding::authorised_entry")]
    pub by: AuthorisedEntry,
}

/// The origin of an entry ingestion event.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum EntryOrigin {
    /// The entry was probably created on this machine.
    Local,
    /// The entry was sourced from another device, e.g. a networked sync session.
    Remote(u64),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EntryChannel {
    Reconciliation,
    Data,
}

/// Describes which entries to ignore during a query.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SubscribeParams {
    /// Omit entries whose payload is the empty string.
    pub ignore_empty_payloads: bool,
    /// Omit entries whose origin is this remote.
    pub ignore_remote: Option<u64>,
    /// Only emit ingestion events.
    pub ingest_only: bool,
    // TODO: ignore_incomplete_payloads is harder to support for us because we need to query the blob store each time currently.
    // /// Omit entries with locally incomplete corresponding payloads.
    // pub ignore_incomplete_payloads: bool,
}

impl SubscribeParams {
    // pub fn ignore_incomplete_payloads(&mut self) {
    //     self.ignore_incomplete_payloads = true;
    // }

    pub fn ignore_empty_payloads(mut self) -> Self {
        self.ignore_empty_payloads = true;
        self
    }

    pub fn ignore_remote(mut self, remote: u64) -> Self {
        self.ignore_remote = Some(remote);
        self
    }

    pub fn ingest_only(mut self) -> Self {
        self.ingest_only = true;
        self
    }

    pub fn includes_entry(&self, entry: &Entry) -> bool {
        !(self.ignore_empty_payloads && entry.payload_length() == 0)
    }

    pub fn includes_origin(&self, origin: &EntryOrigin) -> bool {
        match &self.ignore_remote {
            None => true,
            Some(ignored_session) => match origin {
                EntryOrigin::Local => true,
                EntryOrigin::Remote(session) => session != ignored_session,
            },
        }
    }
}
