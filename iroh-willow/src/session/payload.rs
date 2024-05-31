use bytes::Bytes;
use futures_lite::{future::BoxedLocal, FutureExt};
// use iroh_blobs::{store::Store as PayloadStore, util::progress::IgnoreProgressSender, TempTag};
use iroh_blobs::{
    store::{bao_tree::io::fsm::AsyncSliceReader, MapEntry, Store as PayloadStore},
    util::progress::IgnoreProgressSender,
    TempTag,
};

use crate::proto::{
    sync::Message,
    willow::{Entry, PayloadDigest},
};

use super::{Error, Session};

pub async fn send_payload_chunked<P: PayloadStore>(
    digest: PayloadDigest,
    payload_store: &P,
    session: &Session,
    chunk_size: usize,
    map: impl Fn(Bytes) -> Message,
) -> Result<bool, Error> {
    let payload_entry = payload_store
        .get(&digest)
        .await
        .map_err(Error::PayloadStore)?;
    if let Some(entry) = payload_entry {
        let mut reader = entry.data_reader().await.map_err(Error::PayloadStore)?;
        let len: u64 = entry.size().value();
        let mut pos = 0;
        while pos < len {
            let bytes = reader
                .read_at(pos, chunk_size)
                .await
                .map_err(Error::PayloadStore)?;
            pos += bytes.len() as u64;
            let msg = map(bytes);
            session.send(msg).await?;
        }
        Ok(true)
    } else {
        Ok(false)
    }
}

#[derive(Debug, Default)]
pub struct CurrentPayload(Option<CurrentPayloadInner>);

#[derive(Debug)]
struct CurrentPayloadInner {
    entry: Entry,
    expected_length: u64,
    received_length: u64,
    writer: Option<PayloadWriter>,
}

#[derive(derive_more::Debug)]
struct PayloadWriter {
    #[debug(skip)]
    fut: BoxedLocal<std::io::Result<(TempTag, u64)>>,
    sender: flume::Sender<std::io::Result<Bytes>>,
}

impl CurrentPayload {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, entry: Entry, expected_length: Option<u64>) -> Result<(), Error> {
        if self.0.is_some() {
            return Err(Error::InvalidMessageInCurrentState);
        }
        let expected_length = expected_length.unwrap_or(entry.payload_length);
        self.0 = Some(CurrentPayloadInner {
            entry,
            writer: None,
            expected_length,
            received_length: 0,
        });
        Ok(())
    }

    pub async fn recv_chunk<P: PayloadStore>(
        &mut self,
        store: P,
        chunk: Bytes,
    ) -> anyhow::Result<()> {
        let state = self.0.as_mut().ok_or(Error::InvalidMessageInCurrentState)?;
        let len = chunk.len();
        let writer = state.writer.get_or_insert_with(move || {
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
        state.received_length += len as u64;
        // if state.received_length >= state.expected_length {
        //     self.finalize().await?;
        // }
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        let Some(state) = self.0.as_ref() else {
            return false;
        };
        state.received_length >= state.expected_length
    }

    pub async fn finalize(&mut self) -> Result<(), Error> {
        let state = self.0.take().ok_or(Error::InvalidMessageInCurrentState)?;
        let writer = state
            .writer
            .ok_or_else(|| Error::InvalidMessageInCurrentState)?;
        drop(writer.sender);
        let (tag, len) = writer.fut.await.map_err(Error::PayloadStore)?;
        if *tag.hash() != state.entry.payload_digest {
            return Err(Error::PayloadDigestMismatch);
        }
        if len != state.entry.payload_length {
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

    pub fn is_active(&self) -> bool {
        self.0.as_ref().map(|s| s.writer.is_some()).unwrap_or(false)
    }
    pub fn assert_inactive(&self) -> Result<(), Error> {
        if self.is_active() {
            Err(Error::InvalidMessageInCurrentState)
        } else {
            Ok(())
        }
    }
}
