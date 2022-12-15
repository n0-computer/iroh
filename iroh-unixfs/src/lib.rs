pub mod balanced_tree;
pub mod builder;
pub mod chunker;
pub mod codecs;
pub mod content_loader;
pub mod hamt;
pub mod indexer;
mod types;
pub mod unixfs;

pub use crate::types::{Block, Link, LinkRef, Links, LoadedCid, PbLinks, Source};

use std::collections::BTreeSet;

use crate::codecs::Codec;
use anyhow::{bail, Context as _, Result};
use cid::Cid;
use libipld::{prelude::Codec as _, Ipld, IpldCodec};

/// Extract links from the given content.
///
/// Links will be returned as a sorted vec
pub fn parse_links(cid: &Cid, bytes: &[u8]) -> Result<Vec<Cid>> {
    let codec = Codec::try_from(cid.codec()).context("unknown codec")?;
    let mut cids = BTreeSet::new();
    let codec = match codec {
        Codec::DagCbor => IpldCodec::DagCbor,
        Codec::DagPb => IpldCodec::DagPb,
        Codec::DagJson => IpldCodec::DagJson,
        Codec::Raw => IpldCodec::Raw,
        _ => bail!("unsupported codec {:?}", codec),
    };
    codec.references::<Ipld, _>(bytes, &mut cids)?;
    let links = cids.into_iter().collect();
    Ok(links)
}
