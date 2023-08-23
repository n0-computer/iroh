//! The collection type used by iroh
use anyhow::{Context, Result};
use futures::{
    future::{self, LocalBoxFuture},
    FutureExt,
};
use iroh_bytes::collection::{CollectionParser, CollectionStats, LinkStream};
use iroh_bytes::Hash;
use iroh_io::{AsyncSliceReader, AsyncSliceReaderExt};
use serde::{Deserialize, Serialize};

/// A collection of blobs
///
/// Note that the format is subject to change.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Collection {
    /// Links to the blobs in this collection
    pub(crate) blobs: Vec<Blob>,
    /// The total size of the raw_data referred to by all links
    pub(crate) total_blobs_size: u64,
}

impl Collection {
    /// Create a new collection from a list of blobs and total size of the raw data
    pub fn new(blobs: Vec<Blob>, total_blobs_size: u64) -> anyhow::Result<Self> {
        let mut blobs = blobs;
        let n = blobs.len();
        blobs.sort_by(|a, b| a.name.cmp(&b.name));
        blobs.dedup_by(|a, b| a.name == b.name);
        anyhow::ensure!(n == blobs.len(), "duplicate blob names");
        Ok(Self {
            blobs,
            total_blobs_size,
        })
    }

    /// Serialize this collection to a std `Vec<u8>`
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(postcard::to_stdvec(self)?)
    }

    /// Deserialize a collection from a byte slice
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let c: Collection =
            postcard::from_bytes(data).context("failed to deserialize Collection data")?;
        Ok(c)
    }

    /// Blobs in this collection
    pub fn blobs(&self) -> &[Blob] {
        &self.blobs
    }

    /// Take ownership of the blobs in this collection
    pub fn into_inner(self) -> Vec<Blob> {
        self.blobs
    }

    /// Total size of the raw data referred to by all blobs in this collection
    pub fn total_blobs_size(&self) -> u64 {
        self.total_blobs_size
    }

    /// The number of blobs in this collection
    pub fn total_entries(&self) -> u64 {
        self.blobs.len() as u64
    }
}

/// A blob entry of a collection
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Blob {
    /// The name of this blob of data
    pub name: String,
    /// The hash of the blob of data
    pub hash: Hash,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bao_tree::blake3;

    #[test]
    fn roundtrip_blob() {
        let b = Blob {
            name: "test".to_string(),
            hash: blake3::Hash::from_hex(
                "3aa61c409fd7717c9d9c639202af2fae470c0ef669be7ba2caea5779cb534e9d",
            )
            .unwrap()
            .into(),
        };

        let mut buf = bytes::BytesMut::zeroed(1024);
        postcard::to_slice(&b, &mut buf).unwrap();
        let deserialize_b: Blob = postcard::from_bytes(&buf).unwrap();
        assert_eq!(b, deserialize_b);
    }
}

/// Parser for the current iroh default collections
///
/// This is a custom collection parser that supports the current iroh default collections.
/// It loads the entire collection into memory and then extracts an array of hashes.
/// So this will not work for extremely large collections.
#[derive(Debug, Clone, Copy, Default)]
pub struct IrohCollectionParser;

/// Stream of links that is used by the default collections
///
/// Just contains an array of hashes, so it requires at least all hashes to be loaded into memory.
#[derive(Debug, Clone)]
pub struct ArrayLinkStream {
    hashes: Box<[Hash]>,
    offset: usize,
}

impl ArrayLinkStream {
    /// Create a new iterator over the given hashes.
    pub fn new(hashes: Box<[Hash]>) -> Self {
        Self { hashes, offset: 0 }
    }
}

impl LinkStream for ArrayLinkStream {
    fn next(&mut self) -> LocalBoxFuture<'_, anyhow::Result<Option<Hash>>> {
        let res = if self.offset < self.hashes.len() {
            let hash = self.hashes[self.offset];
            self.offset += 1;
            Some(hash)
        } else {
            None
        };
        future::ok(res).boxed_local()
    }

    fn skip(&mut self, n: u64) -> LocalBoxFuture<'_, anyhow::Result<()>> {
        let res = if let Some(offset) = self
            .offset
            .checked_add(usize::try_from(n).unwrap_or(usize::MAX))
        {
            self.offset = offset;
            Ok(())
        } else {
            Err(anyhow::anyhow!("overflow"))
        };
        future::ready(res).boxed_local()
    }
}

impl CollectionParser for IrohCollectionParser {
    fn parse<'a, R: AsyncSliceReader + 'a>(
        &'a self,
        _format: u64,
        mut reader: R,
    ) -> LocalBoxFuture<'a, anyhow::Result<(Box<dyn LinkStream>, CollectionStats)>> {
        async move {
            // read to end
            let data = reader.read_to_end().await?;
            // parse the collection and just take the hashes
            let collection = Collection::from_bytes(&data)?;
            let stats = CollectionStats {
                num_blobs: Some(collection.blobs.len() as u64),
                total_blob_size: Some(collection.total_blobs_size),
            };
            let hashes = collection
                .into_inner()
                .into_iter()
                .map(|x| x.hash)
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let res: Box<dyn LinkStream> = Box::new(ArrayLinkStream { hashes, offset: 0 });
            Ok((res, stats))
        }
        .boxed_local()
    }
}
