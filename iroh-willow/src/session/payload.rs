use bytes::Bytes;
use futures_lite::{future::BoxedLocal, FutureExt};
use iroh_blobs::{
    store::{bao_tree::io::fsm::AsyncSliceReader, MapEntry, Store as PayloadStore},
    util::progress::IgnoreProgressSender,
    TempTag,
};

use crate::{
    proto::{data_model::PayloadDigest, wgps::Message},
    session::channels::ChannelSenders,
};

use super::Error;

pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 64;

/// Send a payload in chunks.
///
/// Returns `true` if the payload was sent.
/// Returns `false` if blob is not found in `payload_store`.
/// Returns an error if the store or sending on the `senders` return an error.
// TODO: Include outboards.
pub async fn send_payload_chunked<P: PayloadStore>(
    digest: PayloadDigest,
    payload_store: &P,
    senders: &ChannelSenders,
    chunk_size: usize,
    map: impl Fn(Bytes) -> Message,
) -> Result<bool, Error> {
    let payload_entry = payload_store
        .get(&digest.0)
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
            senders.send(msg).await?;
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
    payload_digest: PayloadDigest,
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
    // pub fn new() -> Self {
    //     Self::default()
    // }

    pub fn set(
        &mut self,
        payload_digest: PayloadDigest,
        expected_length: u64,
    ) -> Result<(), Error> {
        if self.0.is_some() {
            return Err(Error::InvalidMessageInCurrentState);
        }
        self.0 = Some(CurrentPayloadInner {
            payload_digest,
            writer: None,
            expected_length,
            received_length: 0,
        });
        Ok(())
    }

    pub async fn recv_chunk<P: PayloadStore>(
        &mut self,
        store: &P,
        chunk: Bytes,
    ) -> anyhow::Result<()> {
        let state = self.0.as_mut().ok_or(Error::InvalidMessageInCurrentState)?;
        let len = chunk.len();
        let store = store.clone();
        let writer = state.writer.get_or_insert_with(move || {
            let (tx, rx) = flume::bounded(1);
            let store = store.clone();
            let fut = async move {
                store
                    .import_stream(
                        rx.into_stream(),
                        iroh_blobs::BlobFormat::Raw,
                        IgnoreProgressSender::default(),
                    )
                    .await
            };
            PayloadWriter {
                fut: fut.boxed_local(),
                sender: tx,
            }
        });
        writer.sender.send_async(Ok(chunk)).await?;
        state.received_length += len as u64;
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
        let (hash, len) = match state.writer {
            Some(writer) => {
                drop(writer.sender);
                let (tag, len) = writer.fut.await.map_err(Error::PayloadStore)?;
                (*tag.hash(), len)
            }
            // The writer is only empty if we did not receive any chunks. In this case, the
            // "received data" is that of the empty hash with size 0.
            None => (iroh_base::hash::Hash::EMPTY, 0),
        };
        if hash != state.payload_digest.0 {
            return Err(Error::PayloadDigestMismatch);
        }
        if len != state.expected_length {
            return Err(Error::PayloadDigestMismatch);
        }
        // TODO: protect from gc
        // we could store a tag for each blob
        // however we really want reference counting here, not individual tags
        // can also fallback to the naive impl from iroh-docs to just protect all docs hashes on gc
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.0.as_ref().map(|s| s.writer.is_some()).unwrap_or(false)
    }
    pub fn ensure_none(&self) -> Result<(), Error> {
        if self.is_active() {
            Err(Error::InvalidMessageInCurrentState)
        } else {
            Ok(())
        }
    }
}
