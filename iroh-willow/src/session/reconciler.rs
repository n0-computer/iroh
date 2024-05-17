use futures_lite::StreamExt;
use tracing::{debug, trace};

use crate::{
    proto::{
        grouping::ThreeDRange,
        keys::NamespaceId,
        wgps::{
            AreaOfInterestHandle, Fingerprint, LengthyEntry, Message,
            ReconciliationAnnounceEntries, ReconciliationMessage, ReconciliationSendEntry,
            ReconciliationSendFingerprint,
        },
        willow::AuthorisedEntry,
    },
    session::{channels::MessageReceiver, AreaOfInterestIntersection, Error, Session},
    store::{ReadonlyStore, Shared, SplitAction, Store, SyncConfig},
    util::channel::WriteError,
};

#[derive(derive_more::Debug)]
pub struct Reconciler<S: Store> {
    session: Session,
    store: Shared<S>,
    recv: MessageReceiver<ReconciliationMessage>,
    snapshot: S::Snapshot,
}

impl<S: Store> Reconciler<S> {
    pub fn new(
        session: Session,
        store: Shared<S>,
        recv: MessageReceiver<ReconciliationMessage>,
    ) -> Result<Self, Error> {
        let snapshot = store.snapshot()?;
        Ok(Self {
            recv,
            store,
            snapshot,
            session,
        })
    }

    pub async fn run(mut self) -> Result<(), Error> {
        let our_role = self.session.our_role();
        loop {
            tokio::select! {
                message = self.recv.try_next() => {
                    match message? {
                        None => break,
                        Some(message) => self.on_message(message).await?,
                    }
                }
                Some(intersection) = self.session.next_aoi_intersection() => {
                    if our_role.is_alfie() {
                        self.initiate(intersection).await?;
                    }
                }
            }
            if self.session.reconciliation_is_complete() {
                debug!("reconciliation complete, close session");
                break;
            }
        }
        Ok(())
    }

    async fn on_message(&mut self, message: ReconciliationMessage) -> Result<(), Error> {
        match message {
            ReconciliationMessage::SendFingerprint(message) => {
                self.on_send_fingerprint(message).await?
            }
            ReconciliationMessage::AnnounceEntries(message) => {
                self.on_announce_entries(message).await?
            }
            ReconciliationMessage::SendEntry(message) => self.on_send_entry(message).await?,
        };
        Ok(())
    }

    async fn initiate(&mut self, intersection: AreaOfInterestIntersection) -> Result<(), Error> {
        let AreaOfInterestIntersection {
            our_handle,
            their_handle,
            intersection,
            namespace,
        } = intersection;
        let range = intersection.into_range();
        let fingerprint = self.snapshot.fingerprint(namespace, &range)?;
        self.send_fingerprint(range, fingerprint, our_handle, their_handle, None)
            .await?;
        Ok(())
    }

    async fn on_send_fingerprint(
        &mut self,
        message: ReconciliationSendFingerprint,
    ) -> Result<(), Error> {
        let (namespace, range_count) = self.session.on_send_fingerprint(&message).await?;
        let our_fingerprint = self.snapshot.fingerprint(namespace, &message.range)?;

        // case 1: fingerprint match.
        if our_fingerprint == message.fingerprint {
            let reply = ReconciliationAnnounceEntries {
                range: message.range.clone(),
                count: 0,
                want_response: false,
                will_sort: false,
                sender_handle: message.receiver_handle,
                receiver_handle: message.sender_handle,
                covers: Some(range_count),
            };
            self.send(reply).await?;
        }
        // case 2: fingerprint is empty
        else if message.fingerprint.is_empty() {
            self.announce_and_send_entries(
                namespace,
                &message.range,
                message.receiver_handle,
                message.sender_handle,
                true,
                Some(range_count),
                None,
            )
            .await?;
        }
        // case 3: fingerprint doesn't match and is non-empty
        else {
            // reply by splitting the range into parts unless it is very short
            self.split_range_and_send_parts(
                namespace,
                &message.range,
                message.receiver_handle,
                message.sender_handle,
                range_count,
            )
            .await?;
        }
        Ok(())
    }
    async fn on_announce_entries(
        &mut self,
        message: ReconciliationAnnounceEntries,
    ) -> Result<(), Error> {
        trace!("on_announce_entries start");
        let (namespace, range_count) = self.session.on_announce_entries(&message).await?;
        if message.want_response {
            self.announce_and_send_entries(
                namespace,
                &message.range,
                message.receiver_handle,
                message.sender_handle,
                false,
                range_count,
                None,
            )
            .await?;
        }
        trace!("on_announce_entries done");
        Ok(())
    }

    async fn on_send_entry(&mut self, message: ReconciliationSendEntry) -> Result<(), Error> {
        let static_token = self
            .session
            .get_their_resource_eventually(|r| &mut r.static_tokens, message.static_token_handle)
            .await;

        self.session.on_send_entry()?;

        let authorised_entry = AuthorisedEntry::try_from_parts(
            message.entry.entry,
            static_token,
            message.dynamic_token,
        )?;

        self.store.ingest_entry(&authorised_entry)?;

        Ok(())
    }

    async fn send_fingerprint(
        &mut self,
        range: ThreeDRange,
        fingerprint: Fingerprint,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
        covers: Option<u64>,
    ) -> anyhow::Result<()> {
        self.session.mark_range_pending(our_handle);
        let msg = ReconciliationSendFingerprint {
            range,
            fingerprint,
            sender_handle: our_handle,
            receiver_handle: their_handle,
            covers,
        };
        self.send(msg).await?;
        Ok(())
    }

    async fn announce_and_send_entries(
        &mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
        want_response: bool,
        covers: Option<u64>,
        our_entry_count: Option<u64>,
    ) -> Result<(), Error> {
        let our_entry_count = match our_entry_count {
            Some(count) => count,
            None => self.snapshot.count(namespace, &range)?,
        };
        let msg = ReconciliationAnnounceEntries {
            range: range.clone(),
            count: our_entry_count,
            want_response,
            will_sort: false, // todo: sorted?
            sender_handle: our_handle,
            receiver_handle: their_handle,
            covers,
        };
        if want_response {
            self.session.mark_range_pending(our_handle);
        }
        self.send(msg).await?;
        for authorised_entry in self
            .snapshot
            .get_entries_with_authorisation(namespace, &range)
        {
            let authorised_entry = authorised_entry?;
            let (entry, token) = authorised_entry.into_parts();
            let (static_token, dynamic_token) = token.into_parts();
            // TODO: partial payloads
            let available = entry.payload_length;
            let (static_token_handle, static_token_bind_msg) =
                self.session.bind_our_static_token(static_token);
            if let Some(msg) = static_token_bind_msg {
                self.send(msg).await?;
            }
            let msg = ReconciliationSendEntry {
                entry: LengthyEntry::new(entry, available),
                static_token_handle,
                dynamic_token,
            };
            self.send(msg).await?;
        }
        Ok(())
    }

    async fn split_range_and_send_parts(
        &mut self,
        namespace: NamespaceId,
        range: &ThreeDRange,
        our_handle: AreaOfInterestHandle,
        their_handle: AreaOfInterestHandle,
        range_count: u64,
    ) -> Result<(), Error> {
        // TODO: expose this config
        let config = SyncConfig::default();
        // clone to avoid borrow checker trouble
        let snapshot = self.snapshot.clone();
        let mut iter = snapshot.split_range(namespace, &range, &config)?.peekable();
        while let Some(res) = iter.next() {
            let (subrange, action) = res?;
            let is_last = iter.peek().is_none();
            let covers = is_last.then(|| range_count);
            match action {
                SplitAction::SendEntries(count) => {
                    self.announce_and_send_entries(
                        namespace,
                        &subrange,
                        our_handle,
                        their_handle,
                        true,
                        covers,
                        Some(count),
                    )
                    .await?;
                }
                SplitAction::SendFingerprint(fingerprint) => {
                    self.send_fingerprint(subrange, fingerprint, our_handle, their_handle, covers)
                        .await?;
                }
            }
        }
        Ok(())
    }

    async fn send(&self, message: impl Into<Message>) -> Result<(), WriteError> {
        self.session.send(message).await
    }
}
