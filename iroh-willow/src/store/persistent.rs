use std::{
    cell::{Ref, RefCell, RefMut},
    collections::HashMap,
    ops::DerefMut,
    path::PathBuf,
    pin::Pin,
    rc::{Rc, Weak},
    task::{ready, Context, Poll},
    time::Duration,
};

use anyhow::Result;
use ed25519_dalek::ed25519;
use futures_util::Stream;
use redb::{Database, ReadableTable};
use willow_data_model::SubspaceId as _;
use willow_store::{QueryRange, QueryRange3d};

use super::{
    memory,
    traits::{self, SplitAction, StoreEvent, SubscribeParams},
    willow_store_glue::{to_query, IrohWillowParams},
};
use crate::{
    interest::{CapSelector, CapabilityPack},
    proto::{
        data_model::{
            AuthorisationToken, AuthorisedEntry, NamespaceId, Path, PathExt as _, SubspaceId,
            WriteCapability,
        },
        grouping::{Area, Range3d},
        keys::{NamespaceSecretKey, UserId, UserSecretKey, UserSignature},
        meadowcap,
        wgps::Fingerprint,
    },
    store::willow_store_glue::{
        path_to_blobseq, to_range3d, StoredAuthorisedEntry, StoredTimestamp,
    },
};

mod tables;

const MAX_COMMIT_DELAY: Duration = Duration::from_millis(500);

#[derive(derive_more::Debug, Clone)]
pub struct Store<PS: iroh_blobs::store::Store> {
    payloads: PS,
    willow: Rc<WillowStore>,
}

impl<PS: iroh_blobs::store::Store> Store<PS> {
    pub fn new(db_path: PathBuf, payload_store: PS) -> Result<Self> {
        Ok(Self {
            payloads: payload_store,
            willow: Rc::new(WillowStore::persistent(db_path)?),
        })
    }

    pub fn new_memory(payload_store: PS) -> Result<Self> {
        Ok(Self {
            payloads: payload_store,
            willow: Rc::new(WillowStore::memory()?),
        })
    }
}

#[derive(Debug)]
pub struct WillowStore {
    db: Db,
    namespace_events: RefCell<HashMap<NamespaceId, memory::EventQueue<StoreEvent>>>,
}

#[derive(derive_more::Debug)]
struct Db {
    #[debug("redb::Database")]
    redb: redb::Database,
    tx: RefCell<CurrentTransaction>,
}

#[derive(derive_more::Debug, Default)]
enum CurrentTransaction {
    #[default]
    None,
    Write(#[debug("tables::OpenWrite")] tables::OpenWrite),
    Read(#[debug("tables::OpenRead")] tables::OpenRead),
}

impl WillowStore {
    pub fn memory() -> Result<Self> {
        let db = Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?;
        Self::new_impl(db)
    }

    /// Create or open a store from a `path` to a database file.
    ///
    /// The file will be created if it does not exist, otherwise it will be opened.
    pub fn persistent(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let db = Database::create(&path.as_ref())?;
        Self::new_impl(db)
    }

    fn new_impl(db: Database) -> Result<Self> {
        // Setup all tables
        let write_tx = db.begin_write()?;
        let _ = tables::Tables::new(&write_tx)?;
        write_tx.commit()?;

        Ok(Self {
            db: Db {
                redb: db,
                tx: Default::default(),
            },
            namespace_events: Default::default(),
        })
    }

    pub fn snapshot(&self) -> Result<WillowSnapshot> {
        Ok(WillowSnapshot(Rc::new(self.db.snapshot_owned()?)))
    }
}

impl Db {
    /// Flush the current transaction, if any.
    ///
    /// This is the cheapest way to ensure that the data is persisted.
    fn flush(&self) -> Result<()> {
        if let CurrentTransaction::Write(w) = std::mem::take(self.tx.borrow_mut().deref_mut()) {
            w.commit()?;
        }
        Ok(())
    }

    /// Get a read-only snapshot of the database.
    ///
    /// This has the side effect of committing any open write transaction,
    /// so it can be used as a way to ensure that the data is persisted.
    fn snapshot(&self) -> Result<Ref<'_, tables::OpenRead>> {
        let mut guard = self.tx.borrow_mut();
        let tables = match std::mem::take(guard.deref_mut()) {
            CurrentTransaction::None => {
                let tx = self.redb.begin_read()?;
                tables::OpenRead::new(&tx)?
            }
            CurrentTransaction::Write(w) => {
                w.commit()?;
                let tx = self.redb.begin_read()?;
                tables::OpenRead::new(&tx)?
            }
            CurrentTransaction::Read(tables) => tables,
        };
        *guard = CurrentTransaction::Read(tables);
        drop(guard);
        Ok(Ref::map(self.tx.borrow(), |tx| match tx {
            CurrentTransaction::Read(ref tables) => tables,
            _ => unreachable!(),
        }))
    }

    /// Get an owned read-only snapshot of the database.
    ///
    /// This will open a new read transaction. The read transaction won't be reused for other
    /// reads.
    ///
    /// This has the side effect of committing any open write transaction,
    /// so it can be used as a way to ensure that the data is persisted.
    fn snapshot_owned(&self) -> Result<tables::OpenRead> {
        // make sure the current transaction is committed
        self.flush()?;
        let tx = self.redb.begin_read()?;
        let tables = tables::OpenRead::new(&tx)?;
        Ok(tables)
    }

    /// Get access to the tables to read from them.
    ///
    /// The underlying transaction is a write transaction, but with a non-mut
    /// reference to the tables you can not write.
    ///
    /// There is no guarantee that this will be an independent transaction.
    /// You just get readonly access to the current state of the database.
    ///
    /// As such, there is also no guarantee that the data you see is
    /// already persisted.
    fn tables(&self) -> Result<RefMut<'_, tables::OpenWrite>> {
        let mut guard = self.tx.borrow_mut();
        let tables = match std::mem::take(guard.deref_mut()) {
            CurrentTransaction::None | CurrentTransaction::Read(_) => {
                let tx = self.redb.begin_write()?;
                tables::OpenWrite::new(tx)?
            }
            CurrentTransaction::Write(w) => {
                if w.since.elapsed() > MAX_COMMIT_DELAY {
                    tracing::debug!("committing transaction because it's too old");
                    w.commit()?;
                    let tx = self.redb.begin_write()?;
                    tables::OpenWrite::new(tx)?
                } else {
                    w
                }
            }
        };
        *guard = CurrentTransaction::Write(tables);
        Ok(RefMut::map(guard, |tx| match tx {
            CurrentTransaction::Write(ref mut tables) => tables,
            _ => unreachable!(),
        }))
    }
}

impl<PS: iroh_blobs::store::Store> traits::Storage for Store<PS> {
    type Entries = Rc<WillowStore>;
    type Secrets = Rc<WillowStore>;
    type Payloads = PS;
    type Caps = Rc<WillowStore>;

    fn entries(&self) -> &Self::Entries {
        &self.willow
    }

    fn secrets(&self) -> &Self::Secrets {
        &self.willow
    }

    fn payloads(&self) -> &Self::Payloads {
        &self.payloads
    }

    fn caps(&self) -> &Self::Caps {
        &self.willow
    }
}

#[derive(derive_more::Debug, Clone)]
pub struct WillowSnapshot(#[debug(skip)] Rc<tables::OpenRead>);

impl WillowSnapshot {
    fn split_range_owned(
        self,
        namespace: NamespaceId,
        range: &Range3d,
        config: &traits::SplitOpts,
    ) -> Result<impl Iterator<Item = Result<traits::RangeSplit>>> {
        let max_set_size = config.max_set_size as u64;
        let split_factor = config.split_factor as u64;

        let count = traits::EntryReader::count(&self, namespace, range)?;
        if count <= max_set_size {
            return Ok(either::Left(
                Some(Ok((range.clone(), SplitAction::SendEntries(count)))).into_iter(),
            ));
        }

        let node_id = self
            .0
            .as_ref()
            .namespace_nodes
            .get(namespace.as_bytes())?
            .expect("node must be set if count > 0 (checked above)");
        let ns_node = willow_store::Node::<IrohWillowParams>::from(node_id.value());

        Ok(either::Right(
            ns_node
                .split_range_owned(to_query(&range), split_factor, self.clone())
                .map({
                    let ns_node = ns_node.clone();
                    move |result| {
                        let (range, count) = result?;
                        if count <= max_set_size {
                            Ok((to_range3d(range)?, traits::SplitAction::SendEntries(count)))
                        } else {
                            let fingerprint = ns_node.range_summary(&range, &self)?;
                            Ok((
                                to_range3d(range)?,
                                traits::SplitAction::SendFingerprint(fingerprint),
                            ))
                        }
                    }
                }),
        ))
    }

    fn get_authorised_entries_owned(
        self,
        namespace: NamespaceId,
        range: &Range3d,
    ) -> Result<impl Iterator<Item = Result<AuthorisedEntry>>> {
        let clone = Rc::clone(&self.0);
        let read = self.0.as_ref();
        let Some(node_id) = read.namespace_nodes.get(namespace.as_bytes())? else {
            return Ok(either::Left(std::iter::empty()));
        };
        let ns_node = willow_store::Node::<IrohWillowParams>::from(node_id.value());
        Ok(either::Right(
            ns_node
                .query(&to_query(range), &read.node_store)
                .map(move |result| {
                    let (point, stored_entry) = result?;
                    let id = stored_entry.authorisation_token_id;
                    let auth_token = get_entry_auth_token(id, &clone.auth_tokens)
                        .inspect_err(|e| tracing::error!(%e, "Database inconsistent, failed to fetch auth token"))?;
                    stored_entry.into_authorised_entry(namespace, &point, auth_token)
                })
                .collect::<Vec<_>>()
                .into_iter(),
        ))
    }
}

impl willow_store::BlobStoreRead for WillowSnapshot {
    fn peek<T>(&self, id: willow_store::NodeId, f: impl Fn(&[u8]) -> T) -> Result<T> {
        self.0.node_store.peek(id, f)
    }
}

impl traits::EntryReader for WillowSnapshot {
    fn fingerprint(&self, namespace: NamespaceId, range: &Range3d) -> Result<Fingerprint> {
        let read = self.0.as_ref();
        let Some(node_id) = read.namespace_nodes.get(namespace.as_bytes())? else {
            return Ok(Fingerprint::default());
        };
        let ns_node = willow_store::Node::<IrohWillowParams>::from(node_id.value());
        ns_node.range_summary(&to_query(range), &read.node_store)
    }

    fn count(&self, namespace: NamespaceId, range: &Range3d) -> Result<u64> {
        let read = self.0.as_ref();
        let Some(node_id) = read.namespace_nodes.get(namespace.as_bytes())? else {
            return Ok(0);
        };
        let ns_node = willow_store::Node::<IrohWillowParams>::from(node_id.value());
        ns_node.range_count(&to_query(range), &read.node_store)
    }

    fn split_range(
        &self,
        namespace: NamespaceId,
        range: &Range3d,
        config: &traits::SplitOpts,
    ) -> Result<impl Iterator<Item = Result<traits::RangeSplit>>> {
        self.clone().split_range_owned(namespace, range, config)
    }

    fn get_entry(
        &self,
        namespace: NamespaceId,
        subspace: SubspaceId,
        path: &Path,
    ) -> Result<Option<AuthorisedEntry>> {
        let read = self.0.as_ref();
        let Some(node_id) = read.namespace_nodes.get(namespace.as_bytes())? else {
            return Ok(None);
        };
        let ns_node = willow_store::Node::<IrohWillowParams>::from(node_id.value());
        let blobseq = path_to_blobseq(path);
        let end = blobseq.immediate_successor();
        let Some(result) = ns_node
            .query_ordered(
                &QueryRange3d {
                    x: QueryRange::new(subspace, subspace.successor()),
                    y: QueryRange::all(),
                    z: QueryRange::new(blobseq, Some(end)),
                },
                willow_store::SortOrder::YZX,
                &read.node_store,
            )
            .last()
        else {
            return Ok(None);
        };

        let (point, stored_entry) = result?;
        let id = stored_entry.authorisation_token_id;
        let auth_token = get_entry_auth_token(id, &read.auth_tokens)?;
        let entry = stored_entry.into_authorised_entry(namespace, &point, auth_token.clone())?;
        Ok(Some(entry))
    }

    fn get_authorised_entries<'a>(
        &'a self,
        namespace: NamespaceId,
        range: &Range3d,
    ) -> Result<impl Iterator<Item = Result<AuthorisedEntry>> + 'a> {
        self.clone().get_authorised_entries_owned(namespace, range)
    }
}

impl traits::EntryStorage for Rc<WillowStore> {
    type Reader = Self;
    type Snapshot = WillowSnapshot;

    fn reader(&self) -> Self::Reader {
        Rc::clone(self)
    }

    fn snapshot(&self) -> Result<Self::Snapshot> {
        Ok(WillowSnapshot(Rc::new(self.db.snapshot_owned()?)))
    }

    fn ingest_entry(
        &self,
        entry: &crate::proto::data_model::AuthorisedEntry,
        origin: super::EntryOrigin,
    ) -> Result<bool> {
        let namespace = *entry.entry().namespace_id();

        let (insert_point, insert_entry) = StoredAuthorisedEntry::from_authorised_entry(entry);

        let mut events = self.namespace_events.borrow_mut();
        let ns_events = events.entry(namespace).or_default();

        self.db.tables()?.modify(|write| {
            // TODO(matheus23): need to get a progress_id here somehow.
            // There's ideas to use the willow-store NodeId for that.

            let mut ns_node: willow_store::Node<IrohWillowParams> = write
                .namespace_nodes
                .get(namespace.as_bytes())?
                .map_or(willow_store::NodeId::EMPTY, |guard| guard.value())
                .into();

            // Enforce prefix deletion:

            let blobseq_start = path_to_blobseq(entry.entry().path());
            let blobseq_end = blobseq_start.subseq_successor();

            let overwritten_range = QueryRange3d {
                x: QueryRange::new(
                    *entry.entry().subspace_id(),
                    entry.entry().subspace_id().successor(),
                ),
                y: QueryRange::new(
                    StoredTimestamp::new(0),
                    Some(StoredTimestamp::new(entry.entry().timestamp())),
                ),
                z: QueryRange::new(blobseq_start, blobseq_end),
            };

            let prune_candidates = ns_node
                .query(&overwritten_range, &write.node_store)
                .collect::<Result<Vec<_>, _>>()?;

            for (prune_pos, prune_candidate) in prune_candidates {
                let pruned_token_id = prune_candidate.authorisation_token_id;
                let auth_token = get_entry_auth_token(pruned_token_id, &write.auth_tokens)?;
                let pruned =
                    prune_candidate.into_authorised_entry(namespace, &prune_pos, auth_token)?; // fairly inefficient
                if entry.entry().is_newer_than(pruned.entry()) {
                    // TODO(matheus23): Don't *actually* delete here? (depending on a potential traceless bit)
                    // There was some idea along the lines of "mark as deleted" by storing the identifier for the deletion.
                    ns_node.delete(&prune_pos, &mut write.node_store)?;
                    ns_events.insert(move |id| {
                        StoreEvent::Pruned(
                            id,
                            traits::PruneEvent {
                                pruned,
                                by: entry.clone(),
                            },
                        )
                    });
                    // Decrease auth token refcount to allow eventually cleaning up the token
                    remove_entry_auth_token(write, pruned_token_id)?;
                }
            }

            tracing::debug!(
                subspace = %entry.entry().subspace_id().fmt_short(),
                path = %entry.entry().path().fmt_utf8(),
                "ingest entry"
            );

            // Insert auth token & entry:

            add_entry_auth_token(entry.token(), write)?;

            let _replaced = ns_node.insert(&insert_point, &insert_entry, &mut write.node_store)?;

            ns_events.insert(|id| StoreEvent::Ingested(id, entry.clone(), origin));

            write
                .namespace_nodes
                .insert(namespace.to_bytes(), ns_node.id())?;

            Ok(())
        })?;

        Ok(true)
    }

    fn subscribe_area(
        &self,
        namespace: NamespaceId,
        area: Area,
        params: traits::SubscribeParams,
    ) -> impl Stream<Item = StoreEvent> + Unpin + 'static {
        let namespaces = &mut self.namespace_events.borrow_mut();
        let ns_events = namespaces.entry(namespace).or_default();
        let progress_id = ns_events.next_progress_id();
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
        params: traits::SubscribeParams,
    ) -> impl Stream<Item = StoreEvent> + Unpin + 'static {
        EventStream {
            area,
            params,
            progress_id,
            namespace,
            store: Rc::downgrade(self),
        }
    }
}

impl traits::EntryReader for Rc<WillowStore> {
    fn fingerprint(&self, namespace: NamespaceId, range: &Range3d) -> Result<Fingerprint> {
        self.snapshot()?.fingerprint(namespace, range)
    }

    fn count(&self, namespace: NamespaceId, range: &Range3d) -> Result<u64> {
        self.snapshot()?.count(namespace, range)
    }

    fn split_range(
        &self,
        namespace: NamespaceId,
        range: &Range3d,
        config: &traits::SplitOpts,
    ) -> Result<impl Iterator<Item = Result<traits::RangeSplit>>> {
        self.snapshot()?.split_range_owned(namespace, range, config)
    }

    fn get_entry(
        &self,
        namespace: NamespaceId,
        subspace: SubspaceId,
        path: &Path,
    ) -> Result<Option<AuthorisedEntry>> {
        self.snapshot()?.get_entry(namespace, subspace, path)
    }

    fn get_authorised_entries<'a>(
        &'a self,
        namespace: NamespaceId,
        range: &Range3d,
    ) -> Result<impl Iterator<Item = Result<AuthorisedEntry>> + 'a> {
        self.snapshot()?
            .get_authorised_entries_owned(namespace, range)
    }
}

impl traits::SecretStorage for Rc<WillowStore> {
    fn insert(&self, secret: meadowcap::SecretKey) -> Result<(), traits::SecretStoreError> {
        self.db
            .tables()?
            .modify(|write| {
                match secret {
                    meadowcap::SecretKey::User(user) => write
                        .user_secrets
                        .insert(user.public_key().as_bytes(), user.to_bytes())?,
                    meadowcap::SecretKey::Namespace(namespace) => write
                        .namespace_secrets
                        .insert(namespace.public_key().as_bytes(), namespace.to_bytes())?,
                };
                Ok(())
            })
            .map_err(traits::SecretStoreError::from)
    }

    fn get_user(&self, id: &UserId) -> Result<Option<UserSecretKey>> {
        let tables = self.db.tables()?;
        let user = tables.read().user_secrets.get(id.as_bytes())?;
        Ok(user.map(|usr| UserSecretKey::from_bytes(&usr.value())))
    }

    fn get_namespace(&self, id: &NamespaceId) -> Result<Option<NamespaceSecretKey>> {
        let tables = self.db.tables()?;
        let namespace = tables.read().namespace_secrets.get(id.as_bytes())?;
        Ok(namespace.map(|ns| NamespaceSecretKey::from_bytes(&ns.value())))
    }
}

impl traits::CapsStorage for Rc<WillowStore> {
    fn insert(&self, cap: CapabilityPack) -> Result<()> {
        self.db.tables()?.modify(|write| {
            let namespace_id = cap.namespace().to_bytes();
            match cap {
                CapabilityPack::Read(r) => {
                    write.read_caps.insert(namespace_id, tables::ReadCap(r))?
                }
                CapabilityPack::Write(w) => {
                    write.write_caps.insert(namespace_id, tables::WriteCap(w))?
                }
            };
            Ok(())
        })
    }

    fn list_read_caps(
        &self,
        namespace: Option<NamespaceId>,
    ) -> Result<impl Iterator<Item = meadowcap::ReadAuthorisation> + '_> {
        Ok(self
            .db
            .snapshot()?
            .read_caps
            .range(namespace.unwrap_or_default().to_bytes()..)?
            .flat_map(|result| match result {
                Err(_) => either::Left(std::iter::empty()),
                Ok((_key_guard, multimap_val)) => either::Right(
                    multimap_val
                        .into_iter()
                        .filter_map(|result| result.ok().map(|val| val.value().0)),
                ),
            }))
    }

    fn list_write_caps(
        &self,
        namespace: Option<NamespaceId>,
    ) -> Result<impl Iterator<Item = WriteCapability> + '_> {
        Ok(self
            .db
            .snapshot()?
            .write_caps
            .range(namespace.unwrap_or_default().to_bytes()..)?
            .flat_map(|result| match result {
                Err(_) => either::Left(std::iter::empty()),
                Ok((_key_guard, multimap_val)) => either::Right(
                    multimap_val
                        .into_iter()
                        .filter_map(|result| result.ok().map(|val| val.value().0)),
                ),
            }))
    }

    fn get_write_cap(&self, selector: &CapSelector) -> Result<Option<WriteCapability>> {
        Ok(self
            .list_write_caps(Some(selector.namespace_id))?
            .find(|cap| selector.is_covered_by(cap)))
    }

    fn get_read_cap(&self, selector: &CapSelector) -> Result<Option<meadowcap::ReadAuthorisation>> {
        Ok(self
            .list_read_caps(Some(selector.namespace_id))?
            .find(|cap| selector.is_covered_by(cap.read_cap())))
    }
}

fn add_entry_auth_token(
    token: &AuthorisationToken,
    write: &mut tables::Tables<'_>,
) -> Result<[u8; 64]> {
    let cap_sig_bytes = token.signature.to_bytes();
    write
        .auth_tokens
        .insert(cap_sig_bytes, tables::WriteCap(token.capability.clone()))?;
    let refcount = write
        .auth_token_refcount
        .get(&cap_sig_bytes)?
        .map_or(1, |rc| rc.value() + 1);
    write.auth_token_refcount.insert(cap_sig_bytes, refcount)?;
    Ok(cap_sig_bytes)
}

fn get_entry_auth_token(
    key: ed25519::SignatureBytes,
    auth_tokens: &impl redb::ReadableTable<ed25519::SignatureBytes, tables::WriteCap>,
) -> Result<AuthorisationToken> {
    let capability = auth_tokens
        .get(key)?
        .ok_or_else(|| {
            anyhow::anyhow!("couldn't find authorisation token id (database inconsistent)")
        })?
        .value()
        .0;
    Ok(AuthorisationToken {
        capability,
        signature: UserSignature::from_bytes(key),
    })
}

fn remove_entry_auth_token(
    write: &mut tables::Tables<'_>,
    key: ed25519::SignatureBytes,
) -> Result<Option<AuthorisationToken>> {
    let Some(refcount) = write.auth_token_refcount.get(&key)?.map(|v| v.value()) else {
        return Ok(None);
    };
    debug_assert_ne!(refcount, 0);
    let new_refcount = refcount - 1;
    if new_refcount == 0 {
        let capability = write
            .auth_tokens
            .remove(&key)?
            .ok_or_else(|| anyhow::anyhow!("inconsistent database state"))?
            .value()
            .0;
        write.auth_token_refcount.remove(&key)?;
        Ok(Some(AuthorisationToken {
            capability,
            signature: UserSignature::from_bytes(key),
        }))
    } else {
        Ok(None)
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
    store: Weak<WillowStore>,
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
        let mut inner_mut = inner.namespace_events.borrow_mut();
        let events = inner_mut.entry(self.namespace).or_default();
        let res = ready!(events.poll_next(
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
