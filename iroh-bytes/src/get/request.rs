//! Utilities for complex get requests.
use std::sync::Arc;

use crate::{
    hashseq::HashSeq,
    protocol::{GetRequest, RangeSpecSeq},
    Hash, HashAndFormat,
};
use bao_tree::{ChunkNum, ChunkRanges};
use bytes::Bytes;
use rand::Rng;

use super::{fsm, Stats};

/// Get the claimed size of a blob from a peer.
///
/// This is just reading the size header and then immediately closing the connection.
/// It can be used to check if a peer has any data at all.
pub async fn get_unverified_size(
    connection: &quinn::Connection,
    hash: &Hash,
) -> anyhow::Result<(u64, Stats)> {
    let request = GetRequest::new(
        *hash,
        RangeSpecSeq::from_ranges(vec![ChunkRanges::from(ChunkNum(u64::MAX)..)]),
    );
    let request = fsm::start(connection.clone(), request);
    let connected = request.next().await?;
    let fsm::ConnectedNext::StartRoot(start) = connected.next().await? else {
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
pub async fn get_verified_size(
    connection: &quinn::Connection,
    hash: &Hash,
) -> anyhow::Result<(u64, Stats)> {
    tracing::trace!("Getting verified size of {}", hash.to_hex());
    let request = GetRequest::new(
        *hash,
        RangeSpecSeq::from_ranges(vec![ChunkRanges::from(ChunkNum(u64::MAX)..)]),
    );
    let request = fsm::start(connection.clone(), request);
    let connected = request.next().await?;
    let fsm::ConnectedNext::StartRoot(start) = connected.next().await? else {
        unreachable!("expected start root");
    };
    let header = start.next();
    let (mut curr, size) = header.next().await?;
    let end = loop {
        match curr.next().await {
            fsm::BlobContentNext::More((next, res)) => {
                let _ = res?;
                curr = next;
            }
            fsm::BlobContentNext::Done(end) => {
                break end;
            }
        }
    };
    let fsm::EndBlobNext::Closing(closing) = end.next() else {
        unreachable!("expected closing");
    };
    let stats = closing.next().await?;
    tracing::trace!(
        "Got verified size of {}, {:.6}s",
        hash.to_hex(),
        stats.elapsed.as_secs_f64()
    );
    Ok((size, stats))
}

/// Given a hash of a hash seq, get the hash seq and the verified sizes of its
/// children.
///
/// This can be used to compute the total size when requesting a hash seq.
pub async fn get_hash_seq_and_sizes(
    connection: &quinn::Connection,
    hash: &Hash,
    max_size: u64,
) -> anyhow::Result<(HashSeq, Arc<[u64]>)> {
    let content = HashAndFormat::hash_seq(*hash);
    tracing::debug!("Getting hash seq and children sizes of {}", content);
    let request = GetRequest::new(
        *hash,
        RangeSpecSeq::from_ranges_infinite([
            ChunkRanges::all(),
            ChunkRanges::from(ChunkNum(u64::MAX)..),
        ]),
    );
    let at_start = fsm::start(connection.clone(), request);
    let at_connected = at_start.next().await?;
    let fsm::ConnectedNext::StartRoot(start) = at_connected.next().await? else {
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
            fsm::EndBlobNext::MoreChildren(more) => {
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
            fsm::EndBlobNext::Closing(closing) => break closing,
        }
    };
    let _stats = closing.next().await?;
    tracing::debug!(
        "Got hash seq and children sizes of {}: {:?}",
        content,
        sizes
    );
    Ok((hash_seq, sizes.into()))
}

/// Probe for a single chunk of a blob.
///
/// This is used to check if a peer has a specific chunk.
pub async fn get_chunk_probe(
    connection: &quinn::Connection,
    hash: &Hash,
    chunk: ChunkNum,
) -> anyhow::Result<Stats> {
    let ranges = ChunkRanges::from(chunk..chunk + 1);
    let ranges = RangeSpecSeq::from_ranges([ranges]);
    let request = GetRequest::new(*hash, ranges);
    let request = fsm::start(connection.clone(), request);
    let connected = request.next().await?;
    let fsm::ConnectedNext::StartRoot(start) = connected.next().await? else {
        unreachable!("query includes root");
    };
    let header = start.next();
    let (mut curr, _size) = header.next().await?;
    let end = loop {
        match curr.next().await {
            fsm::BlobContentNext::More((next, res)) => {
                res?;
                curr = next;
            }
            fsm::BlobContentNext::Done(end) => {
                break end;
            }
        }
    };
    let fsm::EndBlobNext::Closing(closing) = end.next() else {
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
    let total_chunks = sizes.iter().map(|size| ChunkNum::full_chunks(*size).0).sum::<u64>();
    let random_chunk = rng.gen_range(0..total_chunks);
    let mut remaining = random_chunk;
    let mut ranges = vec![];
    ranges.push(ChunkRanges::empty());
    for size in sizes.iter() {
        let chunks = ChunkNum::full_chunks(*size).0;
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
