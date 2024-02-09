//! Utilities that really belong into bao-tree but have not made it there yet.
use std::{io, ops::Range};

use bao_tree::{io::fsm::Outboard, ChunkNum, ChunkRangesRef};
use futures::Stream;
use iroh_io::AsyncSliceReader;

/// Given a data file and an outboard, compute the valid ranges of the data file.
pub fn compute_valid_ranges<D, O>(
    mut data: D,
    mut outboard: O,
    ranges: &ChunkRangesRef,
) -> impl Stream<Item = io::Result<Range<ChunkNum>>>
where
    D: AsyncSliceReader,
    O: Outboard,
{
    futures::stream::empty()
    // // buffer for writing incomplete subtrees.
    // // for queries that don't have incomplete subtrees, this will never be used.
    // let mut out_buf = Vec::new();
    // let mut stack = SmallVec::<[blake3::Hash; 10]>::new();
    // stack.push(outboard.root());
    // let mut encoded = encoded;
    // let tree = outboard.tree();
    // let ranges = truncate_ranges(ranges, tree.size());
    // // write header
    // encoded.write(tree.size.0.to_le_bytes().as_slice()).await?;
    // for item in tree.ranges_pre_order_chunks_iter_ref(ranges, 0) {
    //     match item {
    //         BaoChunk::Parent {
    //             is_root,
    //             left,
    //             right,
    //             node,
    //             ..
    //         } => {
    //             let (l_hash, r_hash) = outboard.load(node).await?.unwrap();
    //             let actual = parent_cv(&l_hash, &r_hash, is_root);
    //             let expected = stack.pop().unwrap();
    //             if actual != expected {
    //                 return Err(EncodeError::ParentHashMismatch(node));
    //             }
    //             if right {
    //                 stack.push(r_hash);
    //             }
    //             if left {
    //                 stack.push(l_hash);
    //             }
    //             let pair = combine_hash_pair(&l_hash, &r_hash);
    //             encoded
    //                 .write(&pair)
    //                 .await
    //                 .map_err(|e| EncodeError::maybe_parent_write(e, node))?;
    //         }
    //         BaoChunk::Leaf {
    //             start_chunk,
    //             size,
    //             is_root,
    //             ranges,
    //             ..
    //         } => {
    //             let expected = stack.pop().unwrap();
    //             let start = start_chunk.to_bytes();
    //             let bytes = data.read_at(start.0, size).await?;
    //             let (actual, to_write) = if !ranges.is_all() {
    //                 // we need to encode just a part of the data
    //                 //
    //                 // write into an out buffer to ensure we detect mismatches
    //                 // before writing to the output.
    //                 out_buf.clear();
    //                 let actual = encode_selected_rec(
    //                     start_chunk,
    //                     &bytes,
    //                     is_root,
    //                     ranges,
    //                     tree.block_size.to_u32(),
    //                     true,
    //                     &mut out_buf,
    //                 );
    //                 (actual, &out_buf[..])
    //             } else {
    //                 let actual = hash_subtree(start_chunk.0, &bytes, is_root);
    //                 (actual, &bytes[..])
    //             };
    //             if actual != expected {
    //                 return Err(EncodeError::LeafHashMismatch(start_chunk));
    //             }
    //             encoded
    //                 .write(to_write)
    //                 .await
    //                 .map_err(|e| EncodeError::maybe_leaf_write(e, start_chunk))?;
    //         }
    //     }
    // }
    // Ok(())
}
