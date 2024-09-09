use futures_lite::StreamExt;

use crate::{
    proto::{
        data_model::AuthorisedEntry,
        wgps::{DataMessage, DataSendEntry, DataSendPayload, StaticToken},
    },
    session::{channels::ChannelSenders, static_tokens::StaticTokens, Error, SessionId},
    store::{
        traits::{EntryOrigin, EntryStorage, Storage, StoreEvent, SubscribeParams},
        Store,
    },
    util::stream::CancelableReceiver,
};

use super::{
    aoi_finder::AoiIntersection,
    payload::{send_payload_chunked, CurrentPayload},
};

#[derive(Debug)]
pub enum Input {
    AoiIntersection(AoiIntersection),
}

#[derive(derive_more::Debug)]
pub struct DataSender<S: Storage> {
    inbox: CancelableReceiver<Input>,
    store: Store<S>,
    send: ChannelSenders,
    static_tokens: StaticTokens,
    session_id: SessionId,
}

impl<S: Storage> DataSender<S> {
    pub fn new(
        inbox: CancelableReceiver<Input>,
        store: Store<S>,
        send: ChannelSenders,
        static_tokens: StaticTokens,
        session_id: SessionId,
    ) -> Self {
        Self {
            inbox,
            store,
            send,
            static_tokens,
            session_id,
        }
    }
    pub async fn run(mut self) -> Result<(), Error> {
        let mut entry_stream = futures_concurrency::stream::StreamGroup::new();
        loop {
            tokio::select! {
                input = self.inbox.next() => {
                    let Some(input) = input else {
                        break;
                    };
                    let Input::AoiIntersection(intersection) = input;
                    let params = SubscribeParams::default().ingest_only().ignore_remote(self.session_id);
                    // TODO: We could start at the progress id at the beginning of the session.
                    let stream = self
                        .store
                        .entries()
                        .subscribe_area(
                            intersection.namespace,
                            intersection.intersection.area.clone(),
                            params,
                        )
                        .filter_map(|event| match event {
                            StoreEvent::Ingested(_id, entry, _origin) => Some(entry),
                            // We get only Ingested events because we set ingest_only() param above.
                            _ => unreachable!("expected only Ingested event but got another event"),
                        });
                    entry_stream.insert(stream);
                },
                entry = entry_stream.next(), if !entry_stream.is_empty() => {
                    match entry {
                        Some(entry) => self.send_entry(entry).await?,
                        None => break,
                    }
                }
            }
        }
        Ok(())
    }

    async fn send_entry(&mut self, authorised_entry: AuthorisedEntry) -> Result<(), Error> {
        let (entry, token) = authorised_entry.into_parts();
        let static_token: StaticToken = token.capability.into();
        let dynamic_token = token.signature;
        // TODO: partial payloads
        // let available = entry.payload_length;
        let static_token_handle = self
            .static_tokens
            .bind_and_send_ours(static_token, &self.send)
            .await?;
        let digest = *entry.payload_digest();
        let offset = 0;
        let msg = DataSendEntry {
            entry: entry.into(),
            static_token_handle,
            dynamic_token,
            offset,
        };
        self.send.send(msg).await?;

        // TODO: only send payload if configured to do so and/or under size limit.
        let send_payloads = true;
        if send_payloads {
            send_payload_chunked(digest, self.store.payloads(), &self.send, offset, |bytes| {
                DataSendPayload { bytes }.into()
            })
            .await?;
        }
        Ok(())
    }
}

#[derive(derive_more::Debug)]
pub struct DataReceiver<S: Storage> {
    store: Store<S>,
    current_payload: CurrentPayload,
    static_tokens: StaticTokens,
    session_id: SessionId,
}

impl<S: Storage> DataReceiver<S> {
    pub fn new(store: Store<S>, static_tokens: StaticTokens, session_id: SessionId) -> Self {
        Self {
            store,
            static_tokens,
            session_id,
            current_payload: Default::default(),
        }
    }

    pub async fn on_message(&mut self, message: DataMessage) -> Result<(), Error> {
        match message {
            DataMessage::SendEntry(message) => self.on_send_entry(message).await?,
            DataMessage::SendPayload(message) => self.on_send_payload(message).await?,
            DataMessage::SetMetadata(_) => {}
        }
        Ok(())
    }

    async fn on_send_entry(&mut self, message: DataSendEntry) -> Result<(), Error> {
        self.current_payload.ensure_none()?;
        let authorised_entry = self
            .static_tokens
            .authorise_entry_eventually(
                message.entry.into(),
                message.static_token_handle,
                message.dynamic_token,
            )
            .await?;
        self.store
            .entries()
            .ingest_entry(&authorised_entry, EntryOrigin::Remote(self.session_id))?;
        let (entry, _token) = authorised_entry.into_parts();
        // TODO: handle offset
        self.current_payload.set(
            *entry.payload_digest(),
            entry.payload_length(),
            None,
            Some(message.offset),
        )?;
        Ok(())
    }

    async fn on_send_payload(&mut self, message: DataSendPayload) -> Result<(), Error> {
        self.current_payload
            .recv_chunk(self.store.payloads(), message.bytes)
            .await?;
        if self.current_payload.is_complete() {
            self.current_payload.finalize().await?;
        }
        Ok(())
    }
}
