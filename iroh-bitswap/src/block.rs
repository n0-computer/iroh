use bytes::Bytes;
use cid::Cid;
use multihash::{Code, MultihashDigest};

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

    const RAW: u64 = 0x55;

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
