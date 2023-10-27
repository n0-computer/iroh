//! Utilities for advanced use of iroh_bytes.
use std::sync::Arc;

use bao_tree::{ByteNum, ChunkNum, ChunkRanges};
use bytes::Bytes;
use iroh_bytes::{
    get::{
        fsm::{BlobContentNext, EndBlobNext},
        Stats,
    },
    hashseq::HashSeq,
    protocol::{GetRequest, RangeSpecSeq},
    Hash, HashAndFormat,
};
use rand::Rng;

use crate::log;

/// Get the claimed size of a blob from a peer.
///
/// This is just reading the size header and then immediately closing the connection.
/// It can be used to check if a peer has any data at all.
pub async fn unverified_size(
    connection: &quinn::Connection,
    hash: &Hash,
) -> anyhow::Result<(u64, Stats)> {
    let request = iroh_bytes::protocol::GetRequest::new(
        *hash,
        RangeSpecSeq::from_ranges(vec![ChunkRanges::from(ChunkNum(u64::MAX)..)]),
    );
    let request = iroh_bytes::get::fsm::start(connection.clone(), request);
    let connected = request.next().await?;
    let iroh_bytes::get::fsm::ConnectedNext::StartRoot(start) = connected.next().await? else {
        unreachable!("expected start root");
    };
    let at_blob_header = start.next();
    let (curr, size) = at_blob_header.next().await?;
    let stats = curr.finish().next().await?;
    Ok((size, stats))
}

/// Get the verified size of a blob from a peer.
///
/// This asks for the last chunk of the blob and validates the response.
/// Note that this does not validate that the peer has all the data.
pub async fn verified_size(
    connection: &quinn::Connection,
    hash: &Hash,
) -> anyhow::Result<(u64, Stats)> {
    log!("Getting verified size of {}", hash.to_hex());
    let request = iroh_bytes::protocol::GetRequest::new(
        *hash,
        RangeSpecSeq::from_ranges(vec![ChunkRanges::from(ChunkNum(u64::MAX)..)]),
    );
    let request = iroh_bytes::get::fsm::start(connection.clone(), request);
    let connected = request.next().await?;
    let iroh_bytes::get::fsm::ConnectedNext::StartRoot(start) = connected.next().await? else {
        unreachable!("expected start root");
    };
    let header = start.next();
    let (mut curr, size) = header.next().await?;
    let end = loop {
        match curr.next().await {
            BlobContentNext::More((next, res)) => {
                let _ = res?;
                curr = next;
            }
            BlobContentNext::Done(end) => {
                break end;
            }
        }
    };
    let EndBlobNext::Closing(closing) = end.next() else {
        unreachable!("expected closing");
    };
    let stats = closing.next().await?;
    log!(
        "Got verified size of {}, {:.6}s",
        hash.to_hex(),
        stats.elapsed.as_secs_f64()
    );
    Ok((size, stats))
}

pub async fn get_hash_seq_and_sizes(
    connection: &quinn::Connection,
    hash: &Hash,
    max_size: u64,
) -> anyhow::Result<(HashSeq, Arc<[u64]>)> {
    let content = HashAndFormat::hash_seq(*hash);
    log!("Getting hash seq and children sizes of {}", content);
    let request = iroh_bytes::protocol::GetRequest::new(
        *hash,
        RangeSpecSeq::from_ranges_infinite([
            ChunkRanges::all(),
            ChunkRanges::from(ChunkNum(u64::MAX)..),
        ]),
    );
    let at_start = iroh_bytes::get::fsm::start(connection.clone(), request);
    let at_connected = at_start.next().await?;
    let iroh_bytes::get::fsm::ConnectedNext::StartRoot(start) = at_connected.next().await? else {
        unreachable!("query includes root");
    };
    let at_start_root = start.next();
    let (at_blob_content, size) = at_start_root.next().await?;
    // check the size to avoid parsing a maliciously large hash seq
    if size > max_size {
        anyhow::bail!("size too large");
    }
    let (mut curr, hash_seq) = at_blob_content.concatenate_into_vec().await?;
    let hash_seq = HashSeq::try_from(Bytes::from(hash_seq))?;
    let mut sizes = Vec::with_capacity(hash_seq.len());
    let closing = loop {
        match curr.next() {
            EndBlobNext::MoreChildren(more) => {
                let hash = match hash_seq.get(sizes.len()) {
                    Some(hash) => hash,
                    None => break more.finish(),
                };
                let at_header = more.next(hash);
                let (at_content, size) = at_header.next().await?;
                let next = at_content.drain().await?;
                sizes.push(size);
                curr = next;
            }
            EndBlobNext::Closing(closing) => break closing,
        }
    };
    let _stats = closing.next().await?;
    log!(
        "Got hash seq and children sizes of {}: {:?}",
        content,
        sizes
    );
    Ok((hash_seq, sizes.into()))
}

/// Probe for a single chunk of a blob.
pub async fn chunk_probe(
    connection: &quinn::Connection,
    hash: &Hash,
    chunk: ChunkNum,
) -> anyhow::Result<Stats> {
    let ranges = ChunkRanges::from(chunk..chunk + 1);
    let ranges = RangeSpecSeq::from_ranges([ranges]);
    let request = GetRequest::new(*hash, ranges);
    let request = iroh_bytes::get::fsm::start(connection.clone(), request);
    let connected = request.next().await?;
    let iroh_bytes::get::fsm::ConnectedNext::StartRoot(start) = connected.next().await? else {
        unreachable!("query includes root");
    };
    let header = start.next();
    let (mut curr, _size) = header.next().await?;
    let end = loop {
        match curr.next().await {
            BlobContentNext::More((next, res)) => {
                res?;
                curr = next;
            }
            BlobContentNext::Done(end) => {
                break end;
            }
        }
    };
    let EndBlobNext::Closing(closing) = end.next() else {
        unreachable!("query contains only one blob");
    };
    let stats = closing.next().await?;
    Ok(stats)
}

/// Given a sequence of sizes of children, generate a range spec that selects a
/// random chunk of a random child.
///
/// The random chunk is chosen uniformly from the chunks of the children, so
/// larger children are more likely to be selected.
pub fn random_hash_seq_ranges(sizes: &[u64], mut rng: impl Rng) -> RangeSpecSeq {
    let total_chunks = sizes
        .iter()
        .map(|size| ByteNum(*size).full_chunks().0)
        .sum::<u64>();
    let random_chunk = rng.gen_range(0..total_chunks);
    let mut remaining = random_chunk;
    let mut ranges = vec![];
    ranges.push(ChunkRanges::empty());
    for size in sizes.iter() {
        let chunks = ByteNum(*size).full_chunks().0;
        if remaining < chunks {
            ranges.push(ChunkRanges::from(
                ChunkNum(remaining)..ChunkNum(remaining + 1),
            ));
            break;
        } else {
            remaining -= chunks;
            ranges.push(ChunkRanges::empty());
        }
    }
    RangeSpecSeq::from_ranges(ranges)
}
