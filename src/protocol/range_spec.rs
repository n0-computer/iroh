use bao_tree::ChunkNum;
use range_collections::{RangeSet2, RangeSetRef};
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
    pub fn new(ranges: impl AsRef<RangeSetRef<ChunkNum>>) -> Self {
        let ranges = ranges.as_ref().boundaries();
        let mut res = SmallVec::new();
        if let Some((start, rest)) = ranges.split_first() {
            let mut prev = start.0;
            res.push(prev);
            for v in rest {
                res.push(v.0 - prev);
                prev = v.0;
            }
        }
        Self(res)
    }

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
            current: default,
            count: None,
            remaining: &self.children,
        }
    }

    pub fn new(
        blob: RangeSet2<ChunkNum>,
        children: impl IntoIterator<Item = RangeSet2<ChunkNum>>,
    ) -> Self {
        let mut prev = RangeSet2::empty();
        let mut count = 0;
        let mut res = SmallVec::new();
        for v in children
            .into_iter()
            .chain(std::iter::once(RangeSet2::empty()))
        {
            if v == prev {
                count += 1;
            } else {
                res.push((count, RangeSpec::new(&v)));
                prev = v;
                count = 1;
            }
        }
        Self {
            blob: RangeSpec::new(blob),
            children: res,
        }
    }
}

/// An infinite iterator of range specs
///
/// default is what to use if the children of this RequestRangeSpec are empty.
pub(crate) struct RequestRangeSpecIter<'a> {
    current: &'a RangeSpec,
    //
    count: Option<u64>,
    /// remaining ranges
    remaining: &'a [(u64, RangeSpec)],
}

impl<'a> Iterator for RequestRangeSpecIter<'a> {
    type Item = &'a RangeSpec;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(count) = &mut self.count {
                if *count > 0 {
                    *count -= 1;
                    return Some(self.current);
                } else {
                    if let Some(((_, new), rest)) = self.remaining.split_first() {
                        self.current = new;
                        self.remaining = rest;
                    }
                    self.count = None;
                }
            } else if self.remaining.is_empty() {
                return Some(self.current);
            } else {
                self.count = Some(self.remaining[0].0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use super::*;
    use bao_tree::ChunkNum;
    use proptest::prelude::*;
    use range_collections::RangeSet2;

    fn ranges(value_range: Range<u64>) -> impl Strategy<Value = RangeSet2<ChunkNum>> {
        prop::collection::vec((value_range.clone(), value_range), 0..16).prop_map(|v| {
            let mut res = RangeSet2::empty();
            for (a, b) in v {
                let start = a.min(b) as u64;
                let end = a.max(b) as u64;
                res |= RangeSet2::from(ChunkNum(start)..ChunkNum(end));
            }
            res
        })
    }

    fn request_range_spec_impl(ranges: &[RangeSet2<ChunkNum>]) -> Vec<RangeSet2<ChunkNum>> {
        let spec = RequestRangeSpec::new(RangeSet2::empty(), ranges.iter().cloned());
        println!("{:?} {:?}", ranges, spec);
        spec.iter(&RangeSpec::empty())
            .map(|x| x.to_chunk_ranges())
            .take(ranges.len())
            .collect::<Vec<_>>()
    }

    #[test]
    fn request_range_spec_roundtrip_cases() {
        for case in [vec![0..1, 0..0]] {
            let case = case
                .iter()
                .map(|x| RangeSet2::from(ChunkNum(x.start)..ChunkNum(x.end)))
                .collect::<Vec<_>>();
            let expected = case.clone();
            let actual = request_range_spec_impl(&case);
            assert_eq!(expected, actual);
        }
    }

    proptest! {
        #[test]
        fn range_spec_roundtrip(ranges in ranges(0..1000)) {
            let spec = RangeSpec::new(&ranges);
            let ranges2 = spec.to_chunk_ranges();
            prop_assert_eq!(ranges, ranges2);
        }

        #[test]
        fn request_range_spec_roundtrip(ranges in proptest::collection::vec(ranges(0..100), 0..10)) {
            let expected = ranges.clone();
            let actual = request_range_spec_impl(&ranges);
            prop_assert_eq!(expected, actual);
        }
    }
}
