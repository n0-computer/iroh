use std::fmt::Debug;

use bytes::Bytes;
use cid::Cid;
use multihash::{Code, MultihashDigest};

/// A wrapper around bytes with their `Cid`.
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct Block {
    pub cid: Cid,
    pub data: Bytes,
}

impl Debug for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Block")
            .field("cid", &self.cid.to_string())
            .field("data", &format!("[{} bytes]", self.data.len()))
            .finish()
    }
}

impl Block {
    pub fn new(data: Bytes, cid: Cid) -> Self {
        Self { cid, data }
    }

    pub fn from_v0_data(data: Bytes) -> cid::Result<Self> {
        let digest = Code::Sha2_256.digest(&data);
        let cid = Cid::new_v0(digest)?;
        Ok(Self { cid, data })
    }

    pub fn cid(&self) -> &Cid {
        &self.cid
    }

    pub fn data(&self) -> &Bytes {
        &self.data
    }
}

pub mod tests {
    use super::*;
    use bytes::BytesMut;
    use rand::{thread_rng, Rng};

    const RAW: u64 = 0x55;

    pub fn create_random_block_v1() -> Block {
        let mut bytes = BytesMut::with_capacity(64);
        bytes.resize(64, 0);
        thread_rng().fill(&mut bytes[..]);
        create_block_v1(bytes)
    }

    pub fn create_block_v1<B: Into<Bytes>>(bytes: B) -> Block {
        let bytes = bytes.into();
        let digest = Code::Sha2_256.digest(&bytes);
        let cid = Cid::new_v1(RAW, digest);
        Block::new(bytes, cid)
    }

    pub fn create_block_v0<B: Into<Bytes>>(bytes: B) -> Block {
        let bytes = bytes.into();
        let digest = Code::Sha2_256.digest(&bytes);
        let cid = Cid::new_v0(digest).unwrap();
        Block::new(bytes, cid)
    }
}
