//! Structs that allow constructing entries and other structs where some fields may be
//! automatically filled.

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

use crate::proto::{
    data_model::{Entry, NamespaceId, Path, SubspaceId, Timestamp},
    keys::UserId,
    meadowcap::{self, WriteCapability},
};

/// Sources where payload data can come from.
#[derive(derive_more::Debug)]
pub enum PayloadForm {
    /// Set the payload hash directly. The blob must exist in the node's blob store, this will fail
    /// otherwise.
    Hash(Hash),
    /// Set the payload hash directly. The blob must exist in the node's blob store, this will fail
    /// otherwise.
    HashUnchecked(Hash, u64),
    /// Import data from the provided bytes and set as payload.
    #[debug("Bytes({})", _0.len())]
    Bytes(Bytes),
    /// Import data from a file on the node's local file system and set as payload.
    File(PathBuf, ImportMode),
    #[debug("Stream")]
    /// Import data from a [`Stream`] of bytes and set as payload.
    Stream(Box<dyn Stream<Item = io::Result<Bytes>> + Send + Sync + Unpin>),
    /// Import data from a [`AsyncRead`] and set as payload.
    #[debug("Reader")]
    Reader(Box<dyn AsyncRead + Send + Sync + Unpin>),
}

impl PayloadForm {
    pub async fn submit<S: iroh_blobs::store::Store>(
        self,
        store: &S,
    ) -> anyhow::Result<(Hash, u64)> {
        let (hash, len) = match self {
            PayloadForm::Hash(digest) => {
                let entry = store.get(&digest).await?;
                let entry = entry.ok_or_else(|| anyhow::anyhow!("hash not foundA"))?;
                (digest, entry.size().value())
            }
            PayloadForm::HashUnchecked(digest, len) => (digest, len),
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

/// Either a [`Entry`] or a [`EntryForm`].
#[derive(Debug, derive_more::From)]
pub enum EntryOrForm {
    Entry(Entry),
    Form(EntryForm),
}

/// Creates an entry while setting some fields automatically.
#[derive(Debug)]
pub struct EntryForm {
    pub namespace_id: NamespaceId,
    pub subspace_id: SubspaceForm,
    pub path: Path,
    pub timestamp: TimestampForm,
    pub payload: PayloadForm,
}

impl EntryForm {
    /// Creates a new [`EntryForm`] where the subspace is set to the user authenticating the entry,
    /// the timestamp is the current system time, and the payload is set to the provided [`Bytes`].
    pub fn new_bytes(namespace_id: NamespaceId, path: Path, payload: impl Into<Bytes>) -> Self {
        EntryForm {
            namespace_id,
            subspace_id: SubspaceForm::User,
            path,
            timestamp: TimestampForm::Now,
            payload: PayloadForm::Bytes(payload.into()),
        }
    }

    /// Sets the subspace for the entry.
    pub fn subspace(mut self, subspace: SubspaceId) -> Self {
        self.subspace_id = SubspaceForm::Exact(subspace);
        self
    }
}

/// Select which capability to use for authenticating a new entry.
#[derive(Debug, Clone, Serialize, Deserialize, derive_more::From)]
pub enum AuthForm {
    /// Use any available capability which covers the entry and whose receiver is the provided
    /// user.
    Any(UserId),
    /// Use the provided [`WriteCapability`].
    Exact(#[serde(with = "meadowcap::serde_encoding::mc_capability")] WriteCapability),
}

impl AuthForm {
    /// Get the user id of the user who is the receiver of the capability selected by this
    /// [`AuthForm`].
    pub fn user_id(&self) -> UserId {
        match self {
            AuthForm::Any(user) => *user,
            AuthForm::Exact(cap) => *cap.receiver(),
        }
    }
}

/// Set the subspace either to a provided [`SubspaceId`], or use the user authenticating the entry
/// as subspace.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum SubspaceForm {
    /// Set the subspace to the [`UserId`] of the user authenticating the entry.
    #[default]
    User,
    /// Set the subspace to the provided [`SubspaceId`].
    Exact(SubspaceId),
}

/// Set the timestamp either to the provided [`Timestamp`] or to the current system time.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum TimestampForm {
    /// Set the timestamp to the current system time.
    #[default]
    Now,
    /// Set the timestamp to the provided value.
    Exact(Timestamp),
}
