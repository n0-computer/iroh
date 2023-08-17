//! Specifications for ranges selection in blobs and collections.
//!
//! The [`RangeSpec`] allows specifying which BAO chunks inside a single blob should be
//! selected.
//!
//! The [`RangeSpecSeq`] builds on top of this to select blob chunks in an entire
//! collection.
use std::fmt;

use bao_tree::ChunkNum;
use range_collections::{RangeSet2, RangeSetRef};
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};

/// A chunk range specification as a sequence of chunk offsets.
///
/// Offsets encode alternating spans starting on 0, where the first span is always deselected.
///
/// ## Examples:
///
/// - `[2, 5, 3, 1]` encodes five spans, of which two are selected:
///   - `[0, 0+2) = [0, 2)` is deselected.
///   - `[2, 2+5) = [2, 7)` is selected.
///   - `[7, 7+3) = [7, 10)` is deselected.
///   - `[10, 10+1) = [10, 11)` is selected.
///   - `[11, inf)` is deselected.
///   Iterating such a [`RangeSpec`] would then produce the [`RangeSet`] `RangeSet{2..7, 10..11}`
///
/// - An empty range selected no spans, encoded as `[]`.  This means nothing of the blob is
///   selected.
///
/// - To select an entire blob create a single half-open span starting at the first chunk:
///   `[0]`.
///
/// - To select the tail of a blob, create a single half-open span: `[15]`.
///
/// This is a SmallVec so we can avoid allocations for the very common case of a single
/// chunk range.
#[derive(Deserialize, Serialize, PartialEq, Eq, Clone)]
#[repr(transparent)]
pub struct RangeSpec(SmallVec<[u64; 2]>);

impl RangeSpec {
    /// Creates a new [`RangeSpec`] from a range set.
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

    /// A [`RangeSpec`] deselecting the entire blob.
    pub const EMPTY: Self = Self(SmallVec::new_const());

    /// Creates a [`RangeSpec`] selecting the entire blob.
    pub fn all() -> Self {
        Self(smallvec![0])
    }

    /// Checks if this [`RangeSpec`] does not select any chunks in the blob.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Checks if this [`RangeSpec`] selects all chunks in the blob.
    pub fn is_all(&self) -> bool {
        self.0.len() == 1 && self.0[0] == 0
    }

    /// Creates a [`RangeSet2`] from this [`RangeSpec`].
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

impl fmt::Debug for RangeSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.debug_list()
                .entries(self.to_chunk_ranges().iter())
                .finish()
        } else if self.is_all() {
            write!(f, "all")
        } else if self.is_empty() {
            write!(f, "empty")
        } else {
            f.debug_list().entries(self.0.iter()).finish()
        }
    }
}

/// A chunk range specification for a collection of blobs.
///
/// To select chunks in an entire collection this is encoded as a sequence of
/// `(blob_index, range_spec)` tuples.  This is interpreted as:
///
/// - Starting from the blob at `blob_index` in the collection, select the ranges specified
///   by the `range_spec` [`RangeSpec`] for that **and all subsequent** blobs.
///
/// - The next tuple will update the [`RangeSpec`] for the blob at `blob_index` and all
///   subsequent blobs.
///
/// - If the sequence is empty or does not start with a blob index of `0` there is an
///   implicit `(0, [])` tuple at the start of this sequence: that is initially no chunks
///   are selected from any chunks.
///
/// Examples:
///
/// - Select all chunks from all blobs in the collection: `[(0, [0])]`.
///
/// - Select the first chunk from all blobs in the collection: `[(0, [0, 1])]`.
///
/// - Select all chunks from blob 1234: `[(1234, [0]), (1235, [])]`.
///
/// - Select first 33 chunks of child 5678: `[(5678, [0, 34]), (5679, [])]`.
///
/// - Select chunk 10 to 30 of child 6789: `[(6789, [10, 31]), (6790, [])]`.
///
/// - Select nothing: `[]`.
///
/// Note that the `blob_index` of a tuple must always be larger than the `blob_index` of any
/// previous tuple in the sequence.
///
/// This is a smallvec so that we can avoid allocations in the common case of a single child
/// range.
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
#[repr(transparent)]
pub struct RangeSpecSeq(SmallVec<[(u64, RangeSpec); 2]>);

impl RangeSpecSeq {
    #[allow(dead_code)]
    /// A [`RangeSpecSeq`] containing no chunks from any blobs in the collection.
    ///
    /// [`RangeSpecSeq::iter`], will return an empty range forever.
    pub const fn empty() -> Self {
        Self(SmallVec::new_const())
    }

    /// Returns the blob index and [`RangeSpec`] of the first blob.
    ///
    /// If the selected chunk spans cover only the first blob, this will return the offset
    /// of this blob (always `0`) and the selected spans of this blob as a [`RangeSpec`].
    pub fn single(&self) -> Option<(u64, &RangeSpec)> {
        // we got two elements,
        // the first element starts at offset 0,
        // and the second element is empty
        if self.0.len() != 2 {
            return None;
        }
        let (fst_ofs, fst_val) = &self.0[0];
        let (snd_ofs, snd_val) = &self.0[1];
        if *fst_ofs == 0 && *snd_ofs == 1 && snd_val.is_empty() {
            Some((*fst_ofs, fst_val))
        } else {
            None
        }
    }

    /// A [`RangeSpecSeq`] containing all chunks from all blobs.
    ///
    /// [`RangeSpecSeq::iter`], will return a full range forever.
    pub fn all() -> Self {
        Self(smallvec![(0, RangeSpec::all())])
    }

    /// Creates a new range spec sequence from a sequence of range sets
    pub fn new(children: impl IntoIterator<Item = RangeSet2<ChunkNum>>) -> Self {
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
        Self(res)
    }

    /// An infinite iterator of range specs for blobs in the collection.
    ///
    /// Each item yielded by the iterator is the [`RangeSpec`] for a blob in the collection.
    /// Thus the first call to `.next()` returns the range spec for the first blob, the next
    /// call returns the range spec of the second blob, etc.
    pub fn iter(&self) -> RequestRangeSpecIter<'_> {
        let before_first = self.0.get(0).map(|(c, _)| *c).unwrap_or_default();
        RequestRangeSpecIter {
            current: &EMPTY_RANGE_SPEC,
            count: before_first,
            remaining: &self.0,
        }
    }

    /// An iterator over blobs in the collection with a non-emtpy range specs.
    ///
    /// This iterator will only yield items for blobs which have at least one chunk
    /// selected.  It yields items of `(blob_index, range_spec)` to know which blob the
    /// range spec applies to.
    ///
    /// This iterator is infinite if the [`RangeSpecSeq`] ends on a non-empty [`RangeSpec`],
    /// that is all further blobs have selected chunks spans.
    pub fn iter_non_empty(&self) -> NonEmptyRequestRangeSpecIter<'_> {
        NonEmptyRequestRangeSpecIter::new(self.iter())
    }
}

static EMPTY_RANGE_SPEC: RangeSpec = RangeSpec::EMPTY;

/// An infinite iterator yielding [`RangeSpec`]s for each blob in a collection.
///
/// The first item yielded is the [`RangeSpec`] for the first blob in the collection, the
/// next item is the [`RangeSpec`] for the next blob, etc.
#[derive(Debug)]
pub struct RequestRangeSpecIter<'a> {
    /// current value
    current: &'a RangeSpec,
    /// number of times to emit current before grabbing next value
    /// if remaining is empty, this is ignored and current is emitted forever
    count: u64,
    /// remaining ranges
    remaining: &'a [(u64, RangeSpec)],
}

impl<'a> RequestRangeSpecIter<'a> {
    pub fn new(ranges: &'a [(u64, RangeSpec)]) -> Self {
        let before_first = ranges.get(0).map(|(c, _)| *c).unwrap_or_default();
        RequestRangeSpecIter {
            current: &EMPTY_RANGE_SPEC,
            count: before_first,
            remaining: ranges,
        }
    }

    /// True if we are at the end of the iterator.
    ///
    /// This does not mean that the iterator is terminated, it just means that
    /// it will repeat the same value forever.
    pub fn is_at_end(&self) -> bool {
        self.count == 0 && self.remaining.is_empty()
    }
}

impl<'a> Iterator for RequestRangeSpecIter<'a> {
    type Item = &'a RangeSpec;

    fn next(&mut self) -> Option<Self::Item> {
        Some(loop {
            break if self.count > 0 {
                // emit current value count times
                self.count -= 1;
                self.current
            } else if let Some(((_, new), rest)) = self.remaining.split_first() {
                // get next current value, new count, and set remaining
                self.current = new;
                self.count = rest.get(0).map(|(c, _)| *c).unwrap_or_default();
                self.remaining = rest;
                continue;
            } else {
                // no more values, just repeat current forever
                self.current
            };
        })
    }
}

/// An iterator over blobs in the collection with a non-emtpy range specs.
///
/// This iterator will only yield items for blobs which have at least one chunk
/// selected.  It yields items of `(blob_index, range_spec)` to know which blob the
/// range spec applies to.
///
/// This iterator is infinite if the [`RangeSpecSeq`] ends on a non-empty [`RangeSpec`],
/// that is all further blobs have selected chunks spans.
#[derive(Debug)]
pub struct NonEmptyRequestRangeSpecIter<'a> {
    inner: RequestRangeSpecIter<'a>,
    count: u64,
}

impl<'a> NonEmptyRequestRangeSpecIter<'a> {
    fn new(inner: RequestRangeSpecIter<'a>) -> Self {
        Self { inner, count: 0 }
    }
}

impl<'a> Iterator for NonEmptyRequestRangeSpecIter<'a> {
    type Item = (u64, &'a RangeSpec);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // unwrapping is safe because we know that the inner iterator will never terminate
            let curr = self.inner.next().unwrap();
            let count = self.count;
            // increase count in any case until we are at the end of possible u64 values
            // we are unlikely to ever reach this limit.
            self.count = self.count.checked_add(1)?;
            // yield only if the current value is non-empty
            if !curr.is_empty() {
                break Some((count, curr));
            } else if self.inner.is_at_end() {
                // terminate instead of looping until we run out of u64 values
                break None;
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
                let start = a.min(b);
                let end = a.max(b);
                res |= RangeSet2::from(ChunkNum(start)..ChunkNum(end));
            }
            res
        })
    }

    fn range_spec_seq_roundtrip_impl(ranges: &[RangeSet2<ChunkNum>]) -> Vec<RangeSet2<ChunkNum>> {
        let spec = RangeSpecSeq::new(ranges.iter().cloned());
        spec.iter()
            .map(|x| x.to_chunk_ranges())
            .take(ranges.len())
            .collect::<Vec<_>>()
    }

    #[test]
    fn range_spec_seq_roundtrip_cases() {
        for case in [
            vec![0..1, 0..0],
            vec![1..2, 1..2, 1..2],
            vec![1..2, 1..2, 2..3, 2..3],
        ] {
            let case = case
                .iter()
                .map(|x| RangeSet2::from(ChunkNum(x.start)..ChunkNum(x.end)))
                .collect::<Vec<_>>();
            let expected = case.clone();
            let actual = range_spec_seq_roundtrip_impl(&case);
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
        fn range_spec_seq_roundtrip(ranges in proptest::collection::vec(ranges(0..100), 0..10)) {
            let expected = ranges.clone();
            let actual = range_spec_seq_roundtrip_impl(&ranges);
            prop_assert_eq!(expected, actual);
        }
    }
}
