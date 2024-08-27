//! API for managing iroh spaces
//!
//! iroh spaces is an implementation of the [Willow] protocol.
//! The main entry point is the [`Client`].
//!
//! You obtain a [`Client`] via [`Iroh::spaces()`](crate::client::Iroh::spaces).
//!
//! [Willow]: https://willowprotocol.org/

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::Result;
use futures_lite::{Stream, StreamExt};
use futures_util::{Sink, SinkExt};
use iroh_base::key::NodeId;
use iroh_willow::{
    form::{AuthForm, SerdeEntryOrForm as EntryOrForm},
    interest::{CapSelector, CapabilityPack, DelegateTo, Interests},
    proto::{
        data_model::{AuthorisedEntry, Entry},
        grouping::Range3d,
        keys::{NamespaceId, NamespaceKind, UserId},
        meadowcap::{AccessMode, SecretKey},
    },
    session::{
        intents::{serde_encoding::Event, Completion, IntentUpdate},
        SessionInit,
    },
};
use ref_cast::RefCast;

use crate::client::RpcClient;
use crate::rpc_protocol::spaces::*;

/// Iroh Willow client.
#[derive(Debug, Clone, RefCast)]
#[repr(transparent)]
pub struct Client {
    pub(super) rpc: RpcClient,
}

impl Client {
    /// Insert a new entry.
    ///
    /// `entry` can be a [`EntryForm`] or a `Entry`.
    /// `auth` can either be a [`AuthForm`] or simply a [`UserId`].
    /// When passing a [`UserId`], a matching capability will be selected for the user.
    /// If you want to select the capability to use more specifically, use the methods on [`AuthForm`].
    // TODO: Not sure I like the impl Into, better change to two methods.
    pub async fn insert_entry(
        &self,
        entry: impl Into<EntryOrForm>,
        auth: impl Into<AuthForm>,
    ) -> Result<()> {
        let req = InsertEntryRequest {
            entry: entry.into(),
            auth: auth.into(),
        };
        let _res: InsertEntryResponse = self.rpc.rpc(req).await??;
        Ok(())
    }

    /// Ingest an authorised entry.
    // TODO: Not sure if we should expose this on the client at all.
    pub async fn ingest_entry(&self, authorised_entry: AuthorisedEntry) -> Result<()> {
        let req = IngestEntryRequest { authorised_entry };
        self.rpc.rpc(req).await??;
        Ok(())
    }

    /// Get entries from the Willow store.
    pub async fn get_entries(
        &self,
        namespace: NamespaceId,
        range: Range3d,
    ) -> Result<impl Stream<Item = Result<Entry>>> {
        let req = GetEntriesRequest { namespace, range };
        let stream = self.rpc.try_server_streaming(req).await?;
        Ok(stream.map(|res| res.map(|r| r.0.into()).map_err(Into::into)))
    }

    /// Create a new namespace in the Willow store.
    pub async fn create_namespace(
        &self,
        kind: NamespaceKind,
        owner: UserId,
    ) -> Result<NamespaceId> {
        let req = CreateNamespaceRequest { kind, owner };
        let res: CreateNamespaceResponse = self.rpc.rpc(req).await??;
        Ok(res.0)
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
        let mut complete = false;
        let mut partial = false;
        while let Some(event) = self.event_rx.next().await {
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
