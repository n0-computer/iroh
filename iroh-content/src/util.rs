use std::collections::BTreeSet;

use anyhow::{bail, Context as _, Result};
use cid::Cid;
use libipld::{prelude::Codec as _, Ipld, IpldCodec};

use crate::codecs::Codec;

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
