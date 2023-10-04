//! traits related to collections of blobs
use crate::util::Hash;
use bytes::Bytes;
use futures::{future::LocalBoxFuture, FutureExt};
use iroh_io::{AsyncSliceReader, AsyncSliceReaderExt};
use std::fmt::Debug;

/// A stream (async iterator) over the hashes of a collection.
///
/// Allows to get the next hash or skip a number of hashes.  Does not
/// implement `Stream` because of the extra `skip` method.
pub trait LinkStream: Debug {
    /// Get the next hash in the collection.
    fn next(&mut self) -> LocalBoxFuture<'_, anyhow::Result<Option<Hash>>>;
    /// Skip a number of hashes in the collection.
    fn skip(&mut self, n: u64) -> LocalBoxFuture<'_, anyhow::Result<()>>;
}

/// A sequence of links, backed by a [`Bytes`] object.
#[derive(Debug, Clone)]
pub struct LinkSeq(Bytes);

impl FromIterator<Hash> for LinkSeq {
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

impl TryFrom<Bytes> for LinkSeq {
    type Error = anyhow::Error;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        Self::new(bytes).ok_or_else(|| anyhow::anyhow!("invalid link sequence"))
    }
}

impl IntoIterator for LinkSeq {
    type Item = Hash;
    type IntoIter = LinkSeqIter;

    fn into_iter(self) -> Self::IntoIter {
        LinkSeqIter(self)
    }
}

impl LinkStream for LinkSeqIter {
    fn next(&mut self) -> LocalBoxFuture<'_, anyhow::Result<Option<Hash>>> {
        futures::future::ok(self.0.pop_front()).boxed_local()
    }

    fn skip(&mut self, n: u64) -> LocalBoxFuture<'_, anyhow::Result<()>> {
        let ok = self.0.drop_front(n as usize);
        if ok {
            futures::future::ok(())
        } else {
            futures::future::err(anyhow::anyhow!("out of bounds"))
        }
        .boxed_local()
    }
}

impl LinkSeq {
    /// Create a new sequence of links.
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

/// Iterator over the hashes in a [`LinkSeq`].
#[derive(Debug, Clone)]
pub struct LinkSeqIter(LinkSeq);

impl Iterator for LinkSeqIter {
    type Item = Hash;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.pop_front()
    }
}

/// Information about a collection.
#[derive(Debug, Clone, Copy, Default)]
pub struct CollectionStats {
    /// The number of blobs in the collection. `None` for unknown.
    pub num_blobs: Option<u64>,
    /// The total size of all blobs in the collection. `None` for unknown.
    pub total_blob_size: Option<u64>,
}

/// A collection parser that parses a sequence of links.
#[derive(Debug, Clone)]
pub struct LinkSeqCollectionParser;

impl LinkSeqCollectionParser {
    /// Parse a sequence of links.
    pub fn parse<'a, R: AsyncSliceReader + 'a>(
        &'a self,
        mut reader: R,
    ) -> LocalBoxFuture<'a, anyhow::Result<(Box<dyn LinkStream>, CollectionStats)>> {
        async move {
            let bytes = reader.read_to_end().await?;
            let links = LinkSeq::try_from(bytes)?;
            let num_blobs = links.len().saturating_sub(1);
            let stream: Box<dyn LinkStream> = Box::new(links.into_iter());
            Ok((
                stream,
                CollectionStats {
                    num_blobs: Some(num_blobs as u64),
                    total_blob_size: None,
                },
            ))
        }
        .boxed_local()
    }
}
