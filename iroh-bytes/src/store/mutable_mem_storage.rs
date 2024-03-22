use bao_tree::{
    io::{fsm::BaoContentItem, sync::WriteAt},
    BaoTree, ByteNum,
};
use bytes::Bytes;

use crate::{
    util::{copy_limited_slice, raw_outboard, SparseMemFile},
    IROH_BLOCK_SIZE,
};

/// Mutable in memory storage for a bao file.
///
/// This is used for incomplete files if they are not big enough to warrant
/// writing to disk. We must keep track of ranges in both data and outboard
/// that have been written to, and track the most precise known size.
#[derive(Debug, Default)]
pub struct MutableMemStorage {
    /// Data file, can be any size.
    pub data: SparseMemFile,
    /// Outboard file, must be a multiple of 64 bytes.
    pub outboard: SparseMemFile,
    /// Size that was announced as we wrote that chunk
    pub sizes: SizeInfo,
}

/// Keep track of the most precise size we know of.
///
/// When in memory, we don't have to write the size for every chunk to a separate
/// slot, but can just keep the best one.
#[derive(Debug, Default)]
pub struct SizeInfo {
    pub offset: u64,
    pub size: u64,
}

impl SizeInfo {
    /// Create a new size info for a complete file of size `size`.
    pub(crate) fn complete(size: u64) -> Self {
        let mask = (1 << IROH_BLOCK_SIZE.0) - 1;
        // offset of the last bao chunk in a file of size `size`
        let last_chunk_offset = size & mask;
        Self {
            offset: last_chunk_offset,
            size,
        }
    }

    /// Write a size at the given offset. The size at the highest offset is going to be kept.
    fn write(&mut self, offset: u64, size: u64) {
        // >= instead of > because we want to be able to update size 0, the initial value.
        if offset >= self.offset {
            self.offset = offset;
            self.size = size;
        }
    }

    /// The current size, representing the most correct size we know.
    pub fn current_size(&self) -> u64 {
        self.size
    }
}

impl MutableMemStorage {
    /// Create a new mutable mem storage from the given data
    pub fn complete(bytes: Bytes) -> (Self, iroh_base::hash::Hash) {
        let (outboard, hash) = raw_outboard(bytes.as_ref());
        let res = Self {
            data: bytes.to_vec().into(),
            outboard: outboard.into(),
            sizes: SizeInfo::complete(bytes.len() as u64),
        };
        (res, hash)
    }

    pub(super) fn current_size(&self) -> u64 {
        self.sizes.current_size()
    }

    pub(super) fn read_data_at(&self, offset: u64, len: usize) -> Bytes {
        copy_limited_slice(&self.data, offset, len)
    }

    pub(super) fn data_len(&self) -> u64 {
        self.data.len() as u64
    }

    pub(super) fn read_outboard_at(&self, offset: u64, len: usize) -> Bytes {
        copy_limited_slice(&self.outboard, offset, len)
    }

    pub(super) fn outboard_len(&self) -> u64 {
        self.outboard.len() as u64
    }

    pub(super) fn write_batch(
        &mut self,
        size: u64,
        batch: &[BaoContentItem],
    ) -> std::io::Result<()> {
        let tree = BaoTree::new(ByteNum(size), IROH_BLOCK_SIZE);
        for item in batch {
            match item {
                BaoContentItem::Parent(parent) => {
                    if let Some(offset) = tree.pre_order_offset(parent.node) {
                        let o0 = offset
                            .checked_mul(64)
                            .expect("u64 overflow multiplying to hash pair offset");
                        let o1 = o0.checked_add(32).expect("u64 overflow");
                        let outboard = &mut self.outboard;
                        outboard.write_all_at(o0, parent.pair.0.as_bytes().as_slice())?;
                        outboard.write_all_at(o1, parent.pair.1.as_bytes().as_slice())?;
                    }
                }
                BaoContentItem::Leaf(leaf) => {
                    self.sizes.write(leaf.offset.0, size);
                    self.data.write_all_at(leaf.offset.0, leaf.data.as_ref())?;
                }
            }
        }
        Ok(())
    }
}
