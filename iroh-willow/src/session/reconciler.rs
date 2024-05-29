use bytes::Bytes;
use futures_lite::{future::BoxedLocal, FutureExt, StreamExt};
use tracing::{debug, trace};

use iroh_blobs::{
    store::{bao_tree::io::fsm::AsyncSliceReader, MapEntry, Store as PayloadStore},
    util::progress::IgnoreProgressSender,
    TempTag,
};

use crate::{
    proto::{
        grouping::ThreeDRange,
        keys::NamespaceId,
        sync::{
            AreaOfInterestHandle, Fingerprint, LengthyEntry, Message,
            ReconciliationAnnounceEntries, ReconciliationMessage, ReconciliationSendEntry,
            ReconciliationSendFingerprint, ReconciliationSendPayload,
            ReconciliationTerminatePayload,
        },
        willow::{AuthorisedEntry, Entry},
    },
    session::{channels::MessageReceiver, AreaOfInterestIntersection, Error, Session},
    store::{EntryStore, ReadonlyStore, Shared, SplitAction, SyncConfig},
    util::channel::WriteError,
};

#[derive(Debug)]
struct CurrentPayload {
    entry: Entry,
    writer: Option<PayloadWriter>,
}

#[derive(derive_more::Debug)]
struct PayloadWriter {
    #[debug(skip)]
    fut: BoxedLocal<std::io::Result<(TempTag, u64)>>,
    sender: flume::Sender<std::io::Result<Bytes>>,
}

impl CurrentPayload {
    async fn recv_chunk<P: PayloadStore>(&mut self, store: P, chunk: Bytes) -> anyhow::Result<()> {
        let writer = self.writer.get_or_insert_with(move || {
            let (tx, rx) = flume::bounded(1);
            let fut = async move {
                store
                    .import_stream(
                        rx.into_stream(),
                        iroh_blobs::BlobFormat::Raw,
                        IgnoreProgressSender::default(),
                    )
                    .await
            };
            let writer = PayloadWriter {
                fut: fut.boxed_local(),
                sender: tx,
            };
            writer
        });
        writer.sender.send_async(Ok(chunk)).await?;
        Ok(())
    }

    fn is_active(&self) -> bool {
        self.writer.is_some()
    }

    async fn finalize(self) -> Result<(), Error> {
        let writer = self
            .writer
            .ok_or_else(|| Error::InvalidMessageInCurrentState)?;
        drop(writer.sender);
        let (tag, len) = writer.fut.await.map_err(Error::PayloadStore)?;
        if *tag.hash() != self.entry.payload_digest {
            return Err(Error::PayloadDigestMismatch);
        }
        if len != self.entry.payload_length {
            return Err(Error::PayloadDigestMismatch);
        }
        // TODO: protect from gc
        // we could store a tag for each blob
        // however we really want reference counting here, not individual tags
        // can also fallback to the naive impl from iroh-docs to just protect all docs hashes on gc
        // let hash_and_format = *tag.inner();
        // let name = b"foo";
        // store.set_tag(name, Some(hash_and_format));
        Ok(())
    }
}

#[derive(derive_more::Debug)]
pub struct Reconciler<S: EntryStore, P: PayloadStore> {
    session: Session,
    store: Shared<S>,
    recv: MessageReceiver<ReconciliationMessage>,
    snapshot: S::Snapshot,
    current_payload: Option<CurrentPayload>,
    payload_store: P,
}

impl<S: EntryStore, P: PayloadStore> Reconciler<S, P> {
    pub fn new(
        session: Session,
        store: Shared<S>,
        payload_store: P,
        recv: MessageReceiver<ReconciliationMessage>,
    ) -> Result<Self, Error> {
        let snapshot = store.snapshot()?;
        Ok(Self {
            recv,
            store,
            payload_store,
            snapshot,
            session,
            current_payload: None,
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
            if self.session.reconciliation_is_complete() && !self.has_active_payload() {
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
            ReconciliationMessage::SendPayload(message) => self.on_send_payload(message).await?,
            ReconciliationMessage::TerminatePayload(message) => {
                self.on_terminate_payload(message).await?
            }
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
        self.assert_no_active_payload()?;
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
        self.assert_no_active_payload()?;
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

        self.current_payload = Some(CurrentPayload {
            entry: authorised_entry.into_entry(),
            writer: None,
        });

        Ok(())
    }

    async fn on_send_payload(&mut self, message: ReconciliationSendPayload) -> Result<(), Error> {
        let state = self
            .current_payload
            .as_mut()
            .ok_or(Error::InvalidMessageInCurrentState)?;
        state
            .recv_chunk(self.payload_store.clone(), message.bytes)
            .await?;
        Ok(())
    }

    async fn on_terminate_payload(
        &mut self,
        _message: ReconciliationTerminatePayload,
    ) -> Result<(), Error> {
        let state = self
            .current_payload
            .take()
            .ok_or(Error::InvalidMessageInCurrentState)?;
        state.finalize().await?;
        Ok(())
    }

    fn assert_no_active_payload(&self) -> Result<(), Error> {
        if self.has_active_payload() {
            Err(Error::InvalidMessageInCurrentState)
        } else {
            Ok(())
        }
    }

    fn has_active_payload(&self) -> bool {
        self.current_payload
            .as_ref()
            .map(|cp| cp.is_active())
            .unwrap_or(false)
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
            let digest = entry.payload_digest;
            let msg = ReconciliationSendEntry {
                entry: LengthyEntry::new(entry, available),
                static_token_handle,
                dynamic_token,
            };
            self.send(msg).await?;

            // TODO: only send payload if configured to do so and/or under size limit.
            let send_payloads = true;
            if send_payloads {
                let payload_entry = self
                    .payload_store
                    .get(&digest)
                    .await
                    .map_err(Error::PayloadStore)?;
                if let Some(entry) = payload_entry {
                    let mut reader = entry.data_reader().await.map_err(Error::PayloadStore)?;
                    let len: u64 = entry.size().value();
                    let chunk_size = 1024usize * 64;
                    let mut pos = 0;
                    while pos < len {
                        let bytes = reader
                            .read_at(pos, chunk_size)
                            .await
                            .map_err(Error::PayloadStore)?;
                        pos += bytes.len() as u64;
                        let msg = ReconciliationSendPayload { bytes };
                        self.send(msg).await?;
                    }
                    let msg = ReconciliationTerminatePayload;
                    self.send(msg).await?;
                }
            }
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
