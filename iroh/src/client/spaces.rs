//! API for managing iroh spaces
//!
//! iroh spaces is an implementation of the [Willow] protocol.
//! The main entry point is the [`Client`].
//!
//! You obtain a [`Client`] via [`Iroh::spaces()`](crate::client::Iroh::spaces).
//!
//! [Willow]: https://willowprotocol.org/

// TODO: Reexport everything that is needed from iroh_willow.

use std::{
    collections::HashMap,
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::Result;
use bytes::Bytes;
use futures_lite::{Stream, StreamExt};
use futures_util::{Sink, SinkExt};
use iroh_base::key::NodeId;
use iroh_blobs::Hash;
use iroh_net::NodeAddr;
use iroh_willow::{
    form::{AuthForm, SubspaceForm, TimestampForm},
    interest::{
        AreaOfInterestSelector, CapSelector, CapabilityPack, DelegateTo, Interests, RestrictArea,
    },
    proto::{
        data_model::{AuthorisedEntry, Path, SubspaceId},
        grouping::{Area, Range3d},
        keys::{NamespaceId, NamespaceKind, UserId},
        meadowcap::{AccessMode, SecretKey},
    },
    session::{
        intents::{serde_encoding::Event, Completion, IntentUpdate},
        SessionInit,
    },
};
use ref_cast::RefCast;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncRead;
use tokio_stream::StreamMap;

use crate::client::RpcClient;
use crate::rpc_protocol::spaces::*;

/// Iroh Willow client.
#[derive(Debug, Clone, RefCast)]
#[repr(transparent)]
pub struct Client {
    pub(super) rpc: RpcClient,
}

impl Client {
    fn net(&self) -> &super::net::Client {
        super::net::Client::ref_cast(&self.rpc)
    }
    /// Create a new namespace in the Willow store.
    pub async fn create(&self, kind: NamespaceKind, owner: UserId) -> Result<Space> {
        let req = CreateNamespaceRequest { kind, owner };
        let res = self.rpc.rpc(req).await??;
        Ok(Space::new(self.rpc.clone(), res.0))
    }

    /// Create a new user in the Willow store.
    pub async fn create_user(&self) -> Result<UserId> {
        let req = CreateUserRequest;
        let res: CreateUserResponse = self.rpc.rpc(req).await??;
        Ok(res.0)
    }

    /// Delegate capabilities to another user.
    ///
    /// Returns a `Vec` of [`CapabilityPack`]s, which can be serialized.
    pub async fn delegate_caps(
        &self,
        from: CapSelector,
        access_mode: AccessMode,
        to: DelegateTo,
    ) -> Result<Vec<CapabilityPack>> {
        let req = DelegateCapsRequest {
            from,
            access_mode,
            to,
        };
        let res = self.rpc.rpc(req).await??;
        Ok(res.0)
    }

    /// Import capabilities.
    pub async fn import_caps(&self, caps: Vec<CapabilityPack>) -> Result<()> {
        let req = ImportCapsRequest { caps };
        self.rpc.rpc(req).await??;
        Ok(())
    }

    /// Import a ticket and start to synchronize.
    pub async fn import_and_sync(
        &self,
        ticket: SpaceTicket,
    ) -> Result<(Space, MergedIntentHandle)> {
        if ticket.caps.is_empty() {
            anyhow::bail!("Invalid ticket: Does not include any capabilities");
        }
        let mut namespaces = ticket.caps.iter().map(|pack| pack.namespace());
        let namespace = namespaces.next().expect("just checked");
        if !namespaces.all(|n| n == namespace) {
            anyhow::bail!("Invalid ticket: Capabilities do not all refer to the same namespace");
        }

        self.import_caps(ticket.caps).await?;
        let interests = Interests::builder().add_full_cap(CapSelector::any(namespace));
        let init = SessionInit::reconcile_once(interests);
        let mut intents = MergedIntentHandle::default();
        for addr in ticket.nodes {
            let node_id = addr.node_id;
            self.net().add_node_addr(addr).await?;
            let intent = self.sync_with_peer(node_id, init.clone()).await?;
            intents.insert(node_id, intent);
        }
        let space = Space::new(self.rpc.clone(), namespace);
        Ok((space, intents))
    }

    /// Synchronize with a peer.
    pub async fn sync_with_peer(&self, peer: NodeId, init: SessionInit) -> Result<IntentHandle> {
        let req = SyncWithPeerRequest { peer, init };
        let (update_tx, event_rx) = self.rpc.bidi(req).await?;

        let update_tx = SinkExt::with(
            update_tx,
            |update| async move { Ok(SyncWithPeerUpdate(update)) },
        );
        let update_tx: UpdateSender = Box::pin(update_tx);

        let event_rx = Box::pin(event_rx.map(|res| match res {
            Ok(Ok(SyncWithPeerResponse::Event(event))) => event,
            Ok(Ok(SyncWithPeerResponse::Started)) => Event::ReconciledAll, // or another appropriate event
            Err(e) => Event::Abort {
                error: e.to_string(),
            },
            Ok(Err(e)) => Event::Abort {
                error: e.to_string(),
            },
        }));

        Ok(IntentHandle::new(update_tx, event_rx))
    }

    /// Import a secret into the Willow store.
    pub async fn import_secret(&self, secret: impl Into<SecretKey>) -> Result<()> {
        let req = InsertSecretRequest {
            secret: secret.into(),
        };
        self.rpc.rpc(req).await??;
        Ok(())
    }
}

/// A space to store entries in.
#[derive(Debug, Clone)]
pub struct Space {
    rpc: RpcClient,
    namespace_id: NamespaceId,
}

impl Space {
    fn new(rpc: RpcClient, namespace_id: NamespaceId) -> Self {
        Self { rpc, namespace_id }
    }

    fn blobs(&self) -> &super::blobs::Client {
        super::blobs::Client::ref_cast(&self.rpc)
    }

    fn spaces(&self) -> &Client {
        Client::ref_cast(&self.rpc)
    }

    fn net(&self) -> &super::net::Client {
        super::net::Client::ref_cast(&self.rpc)
    }

    /// Returns the identifier for this space.
    pub fn namespace_id(&self) -> NamespaceId {
        self.namespace_id
    }

    async fn insert(&self, entry: EntryForm, payload: PayloadForm) -> Result<InsertEntrySuccess> {
        let form = FullEntryForm {
            namespace_id: self.namespace_id,
            subspace_id: entry.subspace_id,
            path: entry.path,
            timestamp: entry.timestamp,
            payload,
        };
        let auth = entry.auth;
        let req = InsertEntryRequest { entry: form, auth };
        let res = self.rpc.rpc(req).await??;
        Ok(res)
    }

    /// Inserts a new entry, with the payload set to the hash of a blob.
    ///
    /// Note that the payload must exist in the local blob store, otherwise the operation will fail.
    pub async fn insert_hash(&self, entry: EntryForm, payload: Hash) -> Result<InsertEntrySuccess> {
        let payload = PayloadForm::Checked(payload);
        self.insert(entry, payload).await
    }

    /// Inserts a new entry, with the payload imported from a byte string.
    pub async fn insert_bytes(
        &self,
        entry: EntryForm,
        payload: impl Into<Bytes>,
    ) -> Result<InsertEntrySuccess> {
        let batch = self.blobs().batch().await?;
        let tag = batch.add_bytes(payload).await?;
        self.insert_hash(entry, *tag.hash()).await
    }

    /// Inserts a new entry, with the payload imported from a byte reader.
    pub async fn insert_reader(
        &self,
        entry: EntryForm,
        payload: impl AsyncRead + Send + Unpin + 'static,
    ) -> Result<InsertEntrySuccess> {
        let batch = self.blobs().batch().await?;
        let tag = batch.add_reader(payload).await?;
        self.insert_hash(entry, *tag.hash()).await
    }

    /// Inserts a new entry, with the payload imported from a byte stream.
    pub async fn insert_stream(
        &self,
        entry: EntryForm,
        payload: impl Stream<Item = std::io::Result<Bytes>> + Send + Unpin + 'static,
    ) -> Result<InsertEntrySuccess> {
        let batch = self.blobs().batch().await?;
        let tag = batch.add_stream(payload).await?;
        self.insert_hash(entry, *tag.hash()).await
    }

    /// Inserts a new entry, with the payload imported from a file.
    pub async fn insert_from_file(
        &self,
        entry: EntryForm,
        file_path: PathBuf,
    ) -> Result<InsertEntrySuccess> {
        let batch = self.blobs().batch().await?;
        let (tag, _len) = batch.add_file(file_path).await?;
        self.insert_hash(entry, *tag.hash()).await
    }

    /// Ingest an authorised entry.
    // TODO: Not sure if we should expose this on the client at all.
    pub async fn ingest(&self, authorised_entry: AuthorisedEntry) -> Result<()> {
        let req = IngestEntryRequest { authorised_entry };
        self.rpc.rpc(req).await??;
        Ok(())
    }

    /// Get a single entry.
    pub async fn get_one(
        &self,
        subspace: SubspaceId,
        path: Path,
    ) -> Result<Option<AuthorisedEntry>> {
        let req = GetEntryRequest {
            namespace: self.namespace_id,
            subspace,
            path,
        };
        let entry = self.rpc.rpc(req).await??;
        Ok(entry.0.map(Into::into))
    }

    /// Get entries by range.
    pub async fn get_many(
        &self,
        range: Range3d,
    ) -> Result<impl Stream<Item = Result<AuthorisedEntry>>> {
        let req = GetEntriesRequest {
            namespace: self.namespace_id,
            range,
        };
        let stream = self.rpc.try_server_streaming(req).await?;
        Ok(stream.map(|res| res.map(|r| r.0).map_err(Into::into)))
    }

    /// Syncs with a peer and quit the session after a single reconciliation of the selected areas.
    ///
    /// Returns an [`IntentHandle`] that emits events for the reconciliation. If you want to wait for everything to complete,
    /// await [`IntentHandle::complete`].
    ///
    /// This will connect to the node, start a sync session, and submit all our capabilities for this namespace,
    /// constrained to the selected areas.
    ///
    /// If you want to specify the capabilities to submit more concretely, use [`Client::sync_with_peer`].
    pub async fn sync_once(
        &self,
        node: NodeId,
        areas: AreaOfInterestSelector,
    ) -> Result<IntentHandle> {
        let cap = CapSelector::any(self.namespace_id);
        let interests = Interests::builder().add(cap, areas);
        let init = SessionInit::reconcile_once(interests);
        self.spaces().sync_with_peer(node, init).await
    }

    /// Sync with a peer and keep sending and receiving live updates for the selected areas.
    ///
    /// Returns an [`IntentHandle`] that emits events for the reconciliation. If you want to wait for everything to complete,
    /// await [`IntentHandle::complete`].
    ///
    /// This will connect to the node, start a sync session, and submit all our capabilities for this namespace,
    /// constrained to the selected areas.
    ///
    /// If you want to specify the capabilities to submit more concretely, use [`Client::sync_with_peer`].
    pub async fn sync_continuously(
        &self,
        node: NodeId,
        areas: AreaOfInterestSelector,
    ) -> Result<IntentHandle> {
        let cap = CapSelector::any(self.namespace_id);
        let interests = Interests::builder().add(cap, areas);
        let init = SessionInit::continuous(interests);
        self.spaces().sync_with_peer(node, init).await
    }

    /// Share access to this space, or parts of this space, with another user.
    ///
    /// This will use any matching capability as the source of the capability delegation.
    /// If you want to specify more options, use [`Client::delegate_caps`].
    pub async fn share(
        &self,
        receiver: UserId,
        access_mode: AccessMode,
        restrict_area: RestrictArea,
    ) -> Result<SpaceTicket> {
        let caps = self
            .spaces()
            .delegate_caps(
                CapSelector::any(self.namespace_id),
                access_mode,
                DelegateTo::new(receiver, restrict_area),
            )
            .await?;
        let node_addr = self.net().node_addr().await?;
        Ok(SpaceTicket {
            caps,
            nodes: vec![node_addr],
        })
    }

    /// TODO
    pub fn subscribe(&self, _area: Area) {
        todo!()
    }

    /// TODO
    pub fn subscribe_offset(&self, _area: Area, _offset: u64) {
        todo!()
    }
}

/// A ticket to import and sync a space.
#[derive(Debug, Serialize, Deserialize)]
pub struct SpaceTicket {
    /// Capabilities for a space.
    pub caps: Vec<CapabilityPack>,
    /// List of nodes to sync with.
    pub nodes: Vec<NodeAddr>,
}

/// Form to insert a new entry
#[derive(Debug)]
pub struct EntryForm {
    /// The authorisation, either an exact capability, or a user id to select a capability for automatically.
    pub auth: AuthForm,
    /// The subspace, either exact or automatically set to the authorising user.
    pub subspace_id: SubspaceForm,
    /// The path
    pub path: Path,
    /// The timestamp, either exact or automatically set current time.
    pub timestamp: TimestampForm,
}

impl EntryForm {
    /// Creates a new entry form with the specified user and path.
    ///
    /// The subspace will be set to the specified user id.
    /// The timestamp will be set to the current system time.
    /// To authorise the entry, any applicable capability issued to the specified user id
    /// that covers this path will be used, or return an error if no such capability is available.
    pub fn new(user: UserId, path: Path) -> Self {
        Self {
            auth: AuthForm::Any(user),
            path,
            subspace_id: Default::default(),
            timestamp: Default::default(),
        }
    }

    // TODO: Add builder methods for auth, subspace_id, timestamp
}

/// Handle to a synchronization intent.
///
/// The `IntentHandle` is a `Stream` of `Event`s. It *must* be progressed in a loop,
/// otherwise the session will be blocked from progressing.
///
/// The `IntentHandle` can also submit new interests into the session.
///
// This version of IntentHandle differs from the one in iroh-willow intents module
// by using the Event type instead of EventKind, which serializes the error to a string
// to cross the RPC boundary. Maybe look into making the main iroh_willow Error type
// serializable instead.
#[derive(derive_more::Debug)]
pub struct IntentHandle {
    #[debug("UpdateSender")]
    update_tx: UpdateSender,
    #[debug("EventReceiver")]
    event_rx: EventReceiver,
}

/// Sends updates into a reconciliation intent.
///
/// Can be obtained from [`IntentHandle::split`].
pub type UpdateSender = Pin<Box<dyn Sink<IntentUpdate, Error = anyhow::Error> + Send + 'static>>;

/// Receives events for a reconciliation intent.
///
/// Can be obtained from [`IntentHandle::split`].
pub type EventReceiver = Pin<Box<dyn Stream<Item = Event> + Send + 'static>>;

impl IntentHandle {
    /// Creates a new `IntentHandle` with the given update sender and event receiver.
    fn new(update_tx: UpdateSender, event_rx: EventReceiver) -> Self {
        Self {
            update_tx,
            event_rx,
        }
    }

    /// Splits the `IntentHandle` into a update sender sink and event receiver stream.
    ///
    /// The intent will be dropped once both the sender and receiver are dropped.
    pub fn split(self) -> (UpdateSender, EventReceiver) {
        (self.update_tx, self.event_rx)
    }

    /// Waits for the intent to be completed.
    ///
    /// This future completes either if the session terminated, or if all interests of the intent
    /// are reconciled and the intent is not in live data mode.
    ///
    /// Note that successful completion of this future does not guarantee that all interests were
    /// fulfilled.
    pub async fn complete(&mut self) -> Result<Completion> {
        complete(&mut self.event_rx).await
    }

    /// Submit new synchronisation interests into the session.
    ///
    /// The `IntentHandle` will then receive events for these interests in addition to already
    /// submitted interests.
    pub async fn add_interests(&mut self, interests: impl Into<Interests>) -> Result<()> {
        self.update_tx
            .send(IntentUpdate::AddInterests(interests.into()))
            .await?;
        Ok(())
    }

    // TODO: I think all should work via dropping, but let's make sure that is the case.
    // /// Close the intent.
    // pub async fn close(&mut self) {
    //     self.update_tx.send(IntentUpdate::Close).await.ok();
    // }
}

impl Stream for IntentHandle {
    type Item = Event;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.event_rx).poll_next(cx)
    }
}

async fn complete(event_rx: &mut EventReceiver) -> Result<Completion> {
    let mut complete = false;
    let mut partial = false;
    while let Some(event) = event_rx.next().await {
        match event {
            Event::ReconciledAll => complete = true,
            Event::Reconciled { .. } => partial = true,
            Event::Abort { error } => return Err(anyhow::anyhow!(error)),
            _ => {}
        }
    }
    let completion = if complete {
        Completion::Complete
    } else if partial {
        Completion::Partial
    } else {
        Completion::Nothing
    };

    Ok(completion)
}

/// Merges synchronisation intent handles into one struct.
#[derive(Default, derive_more::Debug)]
#[debug("MergedIntentHandle({:?})", self.event_rx.keys().collect::<Vec<_>>())]
pub struct MergedIntentHandle {
    event_rx: StreamMap<NodeId, EventReceiver>,
    update_tx: HashMap<NodeId, UpdateSender>,
}

impl MergedIntentHandle {
    /// Add an intent to this merged handle.
    pub fn insert(&mut self, peer: NodeId, handle: IntentHandle) {
        let (update_tx, event_rx) = handle.split();
        self.event_rx.insert(peer, event_rx);
        self.update_tx.insert(peer, update_tx);
    }

    /// Submit new synchronisation interests into all sessions.
    pub async fn add_interests(&mut self, interests: impl Into<Interests>) -> Result<()> {
        let interests: Interests = interests.into();
        let futs = self
            .update_tx
            .values_mut()
            .map(|tx| tx.send(IntentUpdate::AddInterests(interests.clone())));
        futures_buffered::try_join_all(futs).await?;
        Ok(())
    }

    /// Wait for all intents to complete.
    pub async fn complete_all(mut self) -> HashMap<NodeId, Result<Completion>> {
        let streams = self.event_rx.iter_mut();
        let futs =
            streams.map(|(node_id, stream)| async move { (*node_id, complete(stream).await) });
        let res = futures_buffered::join_all(futs).await;
        res.into_iter().collect()
    }
}

impl Stream for MergedIntentHandle {
    type Item = (NodeId, Event);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.event_rx).poll_next(cx)
    }
}

/// Options for setting the payload on the a new entry.
#[derive(Debug, Serialize, Deserialize)]
pub enum PayloadForm {
    /// Make sure the hash is available in the blob store, and use the length from the blob store.
    Checked(Hash),
    /// Insert with the specified hash and length, without checking if the blob is in the local blob store.
    Unchecked(Hash, u64),
}

impl From<PayloadForm> for iroh_willow::form::PayloadForm {
    fn from(value: PayloadForm) -> Self {
        match value {
            PayloadForm::Checked(hash) => Self::Hash(hash),
            PayloadForm::Unchecked(hash, len) => Self::HashUnchecked(hash, len),
        }
    }
}
