//! Types for forms for entries

use std::{io, path::PathBuf};

use bytes::Bytes;
use futures_lite::Stream;
use iroh_base::hash::Hash;
use iroh_blobs::{
    store::{ImportMode, MapEntry},
    util::progress::IgnoreProgressSender,
    BlobFormat,
};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncRead;

use crate::{
    proto::{
        keys::UserId,
        willow::{Entry, NamespaceId, Path, SubspaceId, Timestamp, WriteCapability},
    },
    store::{traits::Storage, Store},
    util::time::system_time_now,
};

/// Sources where payload data can come from.
#[derive(derive_more::Debug)]
pub enum PayloadForm {
    Hash(HashForm),
    #[debug("Bytes({})", _0.len())]
    Bytes(Bytes),
    File(PathBuf, ImportMode),
    #[debug("Stream")]
    Stream(Box<dyn Stream<Item = io::Result<Bytes>> + Send + Sync + Unpin>),
    #[debug("Reader")]
    Reader(Box<dyn AsyncRead + Send + Sync + Unpin>),
}

impl PayloadForm {
    pub async fn submit<S: iroh_blobs::store::Store>(
        self,
        store: &S,
    ) -> anyhow::Result<(Hash, u64)> {
        let (hash, len) = match self {
            PayloadForm::Hash(HashForm::Exact(digest, len)) => (digest, len),
            PayloadForm::Hash(HashForm::Find(digest)) => {
                let entry = store.get(&digest).await?;
                let entry = entry.ok_or_else(|| anyhow::anyhow!("hash not foundA"))?;
                (digest, entry.size().value())
            }
            PayloadForm::Bytes(bytes) => {
                let len = bytes.len();
                let temp_tag = store.import_bytes(bytes, BlobFormat::Raw).await?;
                (*temp_tag.hash(), len as u64)
            }
            PayloadForm::File(path, mode) => {
                let progress = IgnoreProgressSender::default();
                let (temp_tag, len) = store
                    .import_file(path, mode, BlobFormat::Raw, progress)
                    .await?;
                (*temp_tag.hash(), len)
            }
            PayloadForm::Stream(stream) => {
                let progress = IgnoreProgressSender::default();
                let (temp_tag, len) = store
                    .import_stream(stream, BlobFormat::Raw, progress)
                    .await?;
                (*temp_tag.hash(), len)
            }
            PayloadForm::Reader(reader) => {
                let progress = IgnoreProgressSender::default();
                let (temp_tag, len) = store
                    .import_reader(reader, BlobFormat::Raw, progress)
                    .await?;
                (*temp_tag.hash(), len)
            }
        };
        Ok((hash, len))
    }
}

#[derive(Debug)]
pub enum EntryOrForm {
    Entry(Entry),
    Form(EntryForm),
}

#[derive(Debug)]
pub struct EntryForm {
    pub namespace_id: NamespaceId,
    pub subspace_id: SubspaceForm,
    pub path: Path,
    pub timestamp: TimestampForm,
    pub payload: PayloadForm,
}

impl EntryForm {
    pub async fn into_entry<S: Storage>(
        self,
        store: &Store<S>,
        user_id: UserId, // auth: AuthForm,
    ) -> anyhow::Result<Entry> {
        let timestamp = match self.timestamp {
            TimestampForm::Now => system_time_now(),
            TimestampForm::Exact(timestamp) => timestamp,
        };
        let subspace_id = match self.subspace_id {
            SubspaceForm::User => user_id,
            SubspaceForm::Exact(subspace) => subspace,
        };
        let (payload_digest, payload_length) = self.payload.submit(store.payloads()).await?;
        let entry = Entry {
            namespace_id: self.namespace_id,
            subspace_id,
            path: self.path,
            timestamp,
            payload_length,
            payload_digest,
        };
        Ok(entry)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HashForm {
    Find(Hash),
    Exact(Hash, u64),
}

#[derive(Debug, Clone, Serialize, Deserialize, derive_more::From)]
pub enum AuthForm {
    Any(UserId),
    // TODO: WriteCapabilityHash
    Exact(WriteCapability),
}

impl AuthForm {
    pub fn user_id(&self) -> UserId {
        match self {
            AuthForm::Any(user) => *user,
            AuthForm::Exact(cap) => cap.receiver().id(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubspaceForm {
    User,
    Exact(SubspaceId),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimestampForm {
    Now,
    Exact(Timestamp),
}
