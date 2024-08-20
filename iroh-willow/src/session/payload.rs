use std::io;

use bytes::Bytes;
use futures_concurrency::future::TryJoin;
use futures_lite::StreamExt;
use futures_util::TryFutureExt;
use iroh_blobs::{
    store::{MapEntry, Store as PayloadStore},
    Hash, HashAndFormat, TempTag,
};
use iroh_io::TokioStreamReader;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::{
    proto::{data_model::PayloadDigest, wgps::Message},
    session::channels::ChannelSenders,
    util::pipe::chunked_pipe,
};

use super::Error;

const CHUNK_SIZE: usize = 1024 * 32;

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
    offset: u64,
    map: impl Fn(Bytes) -> Message,
) -> Result<bool, Error> {
    let hash: Hash = digest.into();
    let entry = payload_store
        .get(&hash)
        .await
        .map_err(Error::PayloadStore)?;
    let Some(entry) = entry else {
        return Ok(false);
    };

    let (writer, mut reader) = chunked_pipe(CHUNK_SIZE);
    let write_stream_fut = entry
        .write_verifiable_stream(offset, writer)
        .map_err(Error::PayloadStore);
    let send_fut = async {
        while let Some(bytes) = reader.try_next().await.map_err(Error::PayloadStore)? {
            let msg = map(bytes);
            senders.send(msg).await?;
        }
        Ok(())
    };
    (write_stream_fut, send_fut).try_join().await?;
    Ok(true)
}

#[derive(Debug, Default)]
pub struct CurrentPayload(Option<CurrentPayloadInner>);

#[derive(Debug)]
struct CurrentPayloadInner {
    payload_digest: PayloadDigest,
    expected_length: u64,
    received_length: u64,
    total_length: u64,
    offset: u64,
    writer: Option<PayloadWriter>,
}

#[derive(derive_more::Debug)]
struct PayloadWriter {
    tag: TempTag,
    task: tokio::task::JoinHandle<io::Result<()>>,
    sender: mpsc::Sender<io::Result<Bytes>>,
}

impl CurrentPayload {
    /// Set the payload to be received.
    pub fn set(
        &mut self,
        payload_digest: PayloadDigest,
        total_length: u64,
        available_length: Option<u64>,
        offset: Option<u64>,
    ) -> Result<(), Error> {
        if self.0.is_some() {
            return Err(Error::InvalidMessageInCurrentState);
        }
        let offset = offset.unwrap_or(0);
        let available_length = available_length.unwrap_or(total_length);
        let expected_length = available_length - offset;
        self.0 = Some(CurrentPayloadInner {
            payload_digest,
            writer: None,
            expected_length,
            total_length,
            offset,
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
        let writer = state.writer.get_or_insert_with(|| {
            let (tx, rx) = tokio::sync::mpsc::channel(2);
            let store = store.clone();
            let hash: Hash = state.payload_digest.into();
            let total_length = state.total_length;
            let offset = state.offset;
            let tag = store.temp_tag(HashAndFormat::raw(hash));
            let mut reader =
                TokioStreamReader(tokio_util::io::StreamReader::new(ReceiverStream::new(rx)));
            let fut = async move {
                store
                    .import_verifiable_stream(hash, total_length, offset, &mut reader)
                    .await?;
                Ok(())
            };
            let task = tokio::task::spawn_local(fut);
            PayloadWriter {
                tag,
                task,
                sender: tx,
            }
        });
        writer.sender.send(Ok(chunk)).await?;
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
        // The writer is only set if we received at least one payload chunk.
        if let Some(writer) = state.writer {
            drop(writer.sender);
            writer
                .task
                .await
                .expect("payload writer panicked")
                .map_err(Error::PayloadStore)?;
            // TODO: Make sure blobs referenced from entries are protected from GC by now.
            drop(writer.tag);
        }
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
