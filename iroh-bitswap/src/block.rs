use bytes::Bytes;
use cid::Cid;

/// A wrapper around bytes with their `Cid`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    pub cid: Cid,
    pub data: Bytes,
}

impl Block {
    pub fn new(data: Bytes, cid: Cid) -> Self {
        Self { cid, data }
    }

    pub fn cid(&self) -> &Cid {
        &self.cid
    }

    pub fn data(&self) -> &Bytes {
        &self.data
    }
}

pub mod tests {
    use multihash::{Code, MultihashDigest};

    use super::*;

    const RAW: u64 = 0x55;

    pub fn create_block<B: Into<Bytes>>(bytes: B) -> Block {
        let bytes = bytes.into();
        let digest = Code::Sha2_256.digest(&bytes);
        let cid = Cid::new_v1(RAW, digest);
        Block::new(bytes, cid)
    }
}
