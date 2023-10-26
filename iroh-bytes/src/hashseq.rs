//! traits related to collections of blobs
use crate::Hash;
use bytes::Bytes;
use iroh_io::{AsyncSliceReader, AsyncSliceReaderExt};
use std::{fmt::Debug, io};

/// A sequence of links, backed by a [`Bytes`] object.
#[derive(Debug, Clone, derive_more::Into)]
pub struct HashSeq(Bytes);

impl FromIterator<Hash> for HashSeq {
    fn from_iter<T: IntoIterator<Item = Hash>>(iter: T) -> Self {
        let iter = iter.into_iter();
        let (lower, _upper) = iter.size_hint();
        let mut bytes = Vec::with_capacity(lower * 32);
        for hash in iter {
            bytes.extend_from_slice(hash.as_ref());
        }
        Self(bytes.into())
    }
}

impl TryFrom<Bytes> for HashSeq {
    type Error = anyhow::Error;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        Self::new(bytes).ok_or_else(|| anyhow::anyhow!("invalid hash sequence"))
    }
}

impl IntoIterator for HashSeq {
    type Item = Hash;
    type IntoIter = HashSeqIter;

    fn into_iter(self) -> Self::IntoIter {
        HashSeqIter(self)
    }
}

/// Stream over the hashes in a [`HashSeq`].
///
/// todo: make this wrap a reader instead of a [`HashSeq`].
#[derive(Debug, Clone)]
pub struct HashSeqStream(HashSeq);

impl HashSeqStream {
    /// Get the next hash in the sequence.
    #[allow(clippy::should_implement_trait, clippy::unused_async)]
    pub async fn next(&mut self) -> io::Result<Option<Hash>> {
        Ok(self.0.pop_front())
    }

    /// Skip a number of hashes in the sequence.
    #[allow(clippy::unused_async)]
    pub async fn skip(&mut self, n: u64) -> io::Result<()> {
        let ok = self.0.drop_front(n as usize);
        if !ok {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "end of sequence",
            ))
        } else {
            Ok(())
        }
    }
}

impl HashSeq {
    /// Create a new sequence of hashes.
    pub fn new(bytes: Bytes) -> Option<Self> {
        if bytes.len() % 32 == 0 {
            Some(Self(bytes))
        } else {
            None
        }
    }

    fn drop_front(&mut self, n: usize) -> bool {
        let start = n * 32;
        if start > self.0.len() {
            false
        } else {
            self.0 = self.0.slice(start..);
            true
        }
    }

    /// Iterate over the hashes in this sequence.
    pub fn iter(&self) -> impl Iterator<Item = Hash> + '_ {
        self.0.chunks_exact(32).map(|chunk| {
            let hash: [u8; 32] = chunk.try_into().unwrap();
            hash.into()
        })
    }

    /// Get the number of hashes in this sequence.
    pub fn len(&self) -> usize {
        self.0.len() / 32
    }

    /// Check if this sequence is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get the hash at the given index.
    pub fn get(&self, index: usize) -> Option<Hash> {
        if index < self.len() {
            let hash: [u8; 32] = self.0[index * 32..(index + 1) * 32].try_into().unwrap();
            Some(hash.into())
        } else {
            None
        }
    }

    /// Get and remove the first hash in this sequence.
    pub fn pop_front(&mut self) -> Option<Hash> {
        if self.is_empty() {
            None
        } else {
            let hash = self.get(0).unwrap();
            self.0 = self.0.slice(32..);
            Some(hash)
        }
    }

    /// Get the underlying bytes.
    pub fn into_inner(self) -> Bytes {
        self.0
    }
}

/// Iterator over the hashes in a [`HashSeq`].
#[derive(Debug, Clone)]
pub struct HashSeqIter(HashSeq);

impl Iterator for HashSeqIter {
    type Item = Hash;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.pop_front()
    }
}

/// Parse a sequence of hashes.
pub async fn parse_hash_seq<'a, R: AsyncSliceReader + 'a>(
    mut reader: R,
) -> anyhow::Result<(HashSeqStream, u64)> {
    let bytes = reader.read_to_end().await?;
    let hashes = HashSeq::try_from(bytes)?;
    let num_hashes = hashes.len() as u64;
    let stream = HashSeqStream(hashes);
    Ok((stream, num_hashes))
}
