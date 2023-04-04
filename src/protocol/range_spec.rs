use bao_tree::ChunkNum;
use range_collections::RangeSet2;
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};

/// A chunk range specification.
///
/// this is a sequence of spans, where the first span is considered false, and each subsequent span is alternating.
///
/// Examples:
/// The range 10..33 would be encoded as [10, 23]
/// The empty range would be encoded as the empty array []
/// A full interval .. would be encoded as [0]
/// A half open interval 15.. would be encoded as [15]
///
/// All values except for the first one must be non-zero. The first value may be zero.
/// Values are bao chunk numbers, not byte offsets.
///
/// This is a SmallVec so we can avoid allocations for the very common case of a single chunk range.
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
#[repr(transparent)]
pub(crate) struct RangeSpec(SmallVec<[u64; 2]>);

impl RangeSpec {
    pub fn empty() -> Self {
        Self(SmallVec::new())
    }

    pub fn all() -> Self {
        Self(smallvec![0])
    }

    /// Convert a range set from this range spec
    pub fn to_chunk_ranges(&self) -> RangeSet2<ChunkNum> {
        // this is zero allocation for single ranges
        // todo: optimize this in range collections
        let mut ranges = RangeSet2::empty();
        let mut current = ChunkNum(0);
        let mut on = false;
        for &width in self.0.iter() {
            let next = current + width;
            if on {
                ranges |= RangeSet2::from(current..next);
            }
            current = next;
            on = !on;
        }
        if on {
            ranges |= RangeSet2::from(current..);
        }
        ranges
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub(crate) struct RequestRangeSpec {
    /// ranges for the document itself
    pub blob: RangeSpec,
    /// sub ranges for the items of this collection, empty means nothing
    ///
    /// This is also a sequence of spans, but the value after the span is given by the second argument
    ///
    /// Examples:
    ///
    /// All child ranges: `[(0, [0])]` starting at offset 0, all offsets (see above)
    /// First chunk of all child: `[(0, [0, 1])]` starting at offset 0, chunk range 0..1
    /// All of child 1234: `[(1234, [0]), [1, []]]`.
    /// First 33 chunks of child 5678: `[(5678, [0, 33]), (1, [])]`.
    /// Chunks 10 to 30 of child 6789: `[(6789, [10, 20]), (1, [])]`.
    /// No child ranges: `[]`
    ///
    /// This is a smallvec so that we can avoid allocations in the common case of a single child range.
    pub children: SmallVec<[(u64, RangeSpec); 2]>,
}

impl RequestRangeSpec {
    #[allow(dead_code)]
    pub fn empty() -> Self {
        Self {
            blob: RangeSpec::empty(),
            children: SmallVec::new(),
        }
    }

    pub fn all() -> Self {
        Self {
            blob: RangeSpec::all(),
            children: smallvec![(0, RangeSpec::all())],
        }
    }

    /// An infinite iterator of range specs
    ///
    /// default is what to use if the children of this RequestRangeSpec are empty.
    pub fn iter<'a>(&'a self, default: &'a RangeSpec) -> RequestRangeSpecIter<'a> {
        RequestRangeSpecIter {
            count: 0,
            value: default,
            remaining: &self.children,
        }
    }
}

pub(crate) struct RequestRangeSpecIter<'a> {
    /// number of times we emit the current value
    count: u64,
    /// the current value
    value: &'a RangeSpec,
    /// remaining ranges
    remaining: &'a [(u64, RangeSpec)],
}

impl<'a> Iterator for RequestRangeSpecIter<'a> {
    type Item = &'a RangeSpec;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.count > 0 {
                self.count -= 1;
                break Some(self.value);
            } else if let Some(((count, value), rest)) = self.remaining.split_first() {
                self.count = *count;
                self.value = value;
                self.remaining = rest;
            } else {
                break Some(self.value);
            }
        }
    }
}
