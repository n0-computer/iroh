use std::io::Read;

use anyhow::{Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Collection {
    ///
    /// The name of this collection
    pub(crate) name: String,
    /// Links to the blobs in this collection
    pub(crate) blobs: Vec<Blob>,
    /// The total size of the raw_data referred to by all links
    pub(crate) total_blobs_size: u64,
}

impl Collection {
    pub fn decode_from(encoded: Bytes, hash: bao::Hash) -> Result<Self> {
        // verify that the content of data matches the expected hash
        let mut decoder = bao::decode::Decoder::new(std::io::Cursor::new(&encoded[..]), &hash);
        // decoded size can be at most encoded size
        let mut data = Vec::with_capacity(encoded.len());
        decoder
            .read_to_end(&mut data)
            .context("hash of Collection data does not match")?;
        let c: Collection =
            postcard::from_bytes(&data).context("failed to serialize Collection data")?;
        Ok(c)
    }

    pub fn total_blobs_size(&self) -> u64 {
        self.total_blobs_size
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn total_entries(&self) -> u64 {
        self.blobs.len() as u64
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Blob {
    /// The name of this blob of data
    pub(crate) name: String,
    /// The hash of the blob of data
    #[serde(with = "crate::protocol::serde_hash")]
    pub(crate) hash: bao::Hash,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_blob() {
        let b = Blob {
            name: "test".to_string(),
            hash: bao::Hash::from_hex(
                "3aa61c409fd7717c9d9c639202af2fae470c0ef669be7ba2caea5779cb534e9d",
            )
            .unwrap(),
        };

        let mut buf = bytes::BytesMut::zeroed(1024);
        postcard::to_slice(&b, &mut buf).unwrap();
        let deserialize_b: Blob = postcard::from_bytes(&buf).unwrap();
        assert_eq!(b, deserialize_b);
    }
}
