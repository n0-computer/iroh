//! The collection type used by iroh
use anyhow::{Context, Result};
use futures::{future::LocalBoxFuture, FutureExt};
use iroh_bytes::collection::{ArrayLinkStream, CollectionParser, CollectionStats, LinkStream};
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
    ///
    pub fn from_parts(links: &[Hash], names: &[String]) -> anyhow::Result<Self> {
        let blobs = links
            .iter()
            .zip(names.iter())
            .map(|(hash, name)| Blob {
                name: name.clone(),
                hash: *hash,
            })
            .collect();
        Self::new(blobs, 0)
    }

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

    /// Get the links to the blobs in this collection
    pub fn links(&self) -> Vec<Hash> {
        self.blobs.iter().map(|x| x.hash).collect()
    }

    /// Get the names of the blobs in this collection
    pub fn names(&self) -> Vec<String> {
        self.blobs.iter().map(|x| x.name.clone()).collect()
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
            let hashes = postcard::from_bytes::<Box<[Hash]>>(&data)?;
            let res: Box<dyn LinkStream> = Box::new(ArrayLinkStream::new(hashes));
            Ok((res, CollectionStats::default()))
        }
        .boxed_local()
    }
}
