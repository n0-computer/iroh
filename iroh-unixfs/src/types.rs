use anyhow::Result;
use bytes::Bytes;
use cid::Cid;
use multihash::{Code, MultihashDigest};

use libipld::error::{InvalidMultihash, UnsupportedMultihash};

use crate::{codecs::Codec, parse_links};

#[derive(Debug)]
pub struct LoadedCid {
    pub data: Bytes,
    pub source: Source,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Bitswap,
    Http(String),
    Store(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    cid: Cid,
    data: Bytes,
    links: Vec<Cid>,
}

impl Block {
    pub fn new(cid: Cid, data: Bytes, links: Vec<Cid>) -> Self {
        Self { cid, data, links }
    }

    pub fn cid(&self) -> &Cid {
        &self.cid
    }

    pub fn data(&self) -> &Bytes {
        &self.data
    }

    pub fn links(&self) -> &[Cid] {
        &self.links
    }

    pub fn raw_data_size(&self) -> Option<u64> {
        let codec = Codec::try_from(self.cid.codec()).unwrap();
        match codec {
            Codec::Raw => Some(self.data.len() as u64),
            _ => None,
        }
    }

    /// Validate the block. Will return an error if the hash or the links are wrong.
    pub fn validate(&self) -> Result<()> {
        // check that the cid is supported
        let code = self.cid.hash().code();
        let mh = Code::try_from(code)
            .map_err(|_| UnsupportedMultihash(code))?
            .digest(&self.data);
        // check that the hash matches the data
        if mh.digest() != self.cid.hash().digest() {
            return Err(InvalidMultihash(mh.to_bytes()).into());
        }
        // check that the links are complete
        let expected_links = parse_links(&self.cid, &self.data)?;
        let mut actual_links = self.links.clone();
        actual_links.sort();
        // TODO: why do the actual links need to be deduplicated?
        actual_links.dedup();
        anyhow::ensure!(expected_links == actual_links, "links do not match");
        Ok(())
    }

    pub fn into_parts(self) -> (Cid, Bytes, Vec<Cid>) {
        (self.cid, self.data, self.links)
    }
}

/// Holds information if we should clip the response and to what offset
#[derive(Debug, Clone, Copy)]
pub enum ResponseClip {
    NoClip,
    Clip(usize),
}

impl From<usize> for ResponseClip {
    fn from(item: usize) -> Self {
        if item == 0 {
            ResponseClip::NoClip
        } else {
            ResponseClip::Clip(item)
        }
    }
}
