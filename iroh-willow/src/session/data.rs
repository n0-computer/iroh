use futures_lite::StreamExt;

use iroh_blobs::store::Store as PayloadStore;
use tokio::sync::broadcast;

use crate::{
    proto::{
        sync::{DataMessage, DataSendEntry, DataSendPayload},
        willow::AuthorisedEntry,
    },
    session::Error,
    store::{
        broadcaster::{Broadcaster, Origin},
        EntryStore,
    },
};

use super::channels::MessageReceiver;
use super::payload::{send_payload_chunked, CurrentPayload};
use super::Session;

#[derive(derive_more::Debug)]
pub struct DataSender<S: EntryStore, P: PayloadStore> {
    session: Session,
    store: Broadcaster<S>,
    payload_store: P,
}

impl<S: EntryStore, P: PayloadStore> DataSender<S, P> {
    pub fn new(session: Session, store: Broadcaster<S>, payload_store: P) -> Self {
        Self {
            session,
            store,
            payload_store,
        }
    }
    pub async fn run(mut self) -> Result<(), Error> {
        let mut stream = self.store.subscribe(*self.session.id());
        loop {
            match stream.recv().await {
                Ok(entry) => {
                    self.send_entry(entry).await?;
                }
                Err(broadcast::error::RecvError::Closed) => break,
                Err(broadcast::error::RecvError::Lagged(_count)) => {
                    // TODO
                }
            }
        }
        Ok(())
    }

    async fn send_entry(&mut self, authorised_entry: AuthorisedEntry) -> Result<(), Error> {
        let (entry, token) = authorised_entry.into_parts();
        let (static_token, dynamic_token) = token.into_parts();
        // TODO: partial payloads
        // let available = entry.payload_length;
        let (static_token_handle, static_token_bind_msg) =
            self.session.bind_our_static_token(static_token);
        if let Some(msg) = static_token_bind_msg {
            self.session.send(msg).await?;
        }
        let digest = entry.payload_digest;
        let msg = DataSendEntry {
            entry,
            static_token_handle,
            dynamic_token,
            offset: 0,
        };
        self.session.send(msg).await?;

        // TODO: only send payload if configured to do so and/or under size limit.
        let send_payloads = true;
        let chunk_size = 1024 * 64;
        if send_payloads {
            send_payload_chunked(
                digest,
                &self.payload_store,
                &self.session,
                chunk_size,
                |bytes| DataSendPayload { bytes }.into(),
            )
            .await?;
        }
        Ok(())
    }
}

#[derive(derive_more::Debug)]
pub struct DataReceiver<S: EntryStore, P: PayloadStore> {
    session: Session,
    store: Broadcaster<S>,
    payload_store: P,
    current_payload: CurrentPayload,
    recv: MessageReceiver<DataMessage>,
}

impl<S: EntryStore, P: PayloadStore> DataReceiver<S, P> {
    pub fn new(
        session: Session,
        store: Broadcaster<S>,
        payload_store: P,
        recv: MessageReceiver<DataMessage>,
    ) -> Self {
        Self {
            session,
            store,
            payload_store,
            current_payload: Default::default(),
            recv,
        }
    }
    pub async fn run(mut self) -> Result<(), Error> {
        while let Some(message) = self.recv.try_next().await? {
            self.on_message(message).await?;
        }
        Ok(())
    }

    async fn on_message(&mut self, message: DataMessage) -> Result<(), Error> {
        match message {
            DataMessage::SendEntry(message) => self.on_send_entry(message).await?,
            DataMessage::SendPayload(message) => self.on_send_payload(message).await?,
            DataMessage::SetMetadata(_) => todo!(),
        }
        Ok(())
    }

    async fn on_send_entry(&mut self, message: DataSendEntry) -> Result<(), Error> {
        self.current_payload.assert_inactive()?;
        let authorised_entry = self
            .session
            .authorise_sent_entry(
                message.entry,
                message.static_token_handle,
                message.dynamic_token,
            )
            .await?;
        self.store
            .ingest_entry(&authorised_entry, Origin::Remote(*self.session.id()))?;
        self.current_payload
            .set(authorised_entry.into_entry(), None)?;
        Ok(())
    }

    async fn on_send_payload(&mut self, message: DataSendPayload) -> Result<(), Error> {
        self.current_payload
            .recv_chunk(self.payload_store.clone(), message.bytes)
            .await?;
        if self.current_payload.is_complete() {
            self.current_payload.finalize().await?;
        }
        Ok(())
    }
}
