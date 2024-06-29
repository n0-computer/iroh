use std::{cmp::Ordering, io};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::{
    proto::willow::encodings::RelativePath,
    util::codec::{compact_width, CompactWidth, Encoder},
};

use super::{
    keys::NamespaceId,
    willow::{Entry, Path, SubspaceId, Timestamp},
};

/// A three-dimensional range on a specific namespace.
#[derive(Debug)]
pub struct NamespacedRange {
    /// The namespace
    pub namespace: NamespaceId,
    /// The 3DRange
    pub range: ThreeDRange,
}

/// A three-dimensional range that includes every [`Entry`] included in all three of its ranges.
#[derive(Debug, Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
pub struct ThreeDRange {
    /// Range of [`SubspaceId`]
    pub subspaces: Range<SubspaceId>,
    /// Range of [`Path`]
    pub paths: Range<Path>,
    /// Range of [`Timestamp`]
    pub times: Range<Timestamp>,
}

impl ThreeDRange {
    /// Create a new range from its parts.
    pub fn new(subspaces: Range<SubspaceId>, paths: Range<Path>, times: Range<Timestamp>) -> Self {
        Self {
            subspaces,
            paths,
            times,
        }
    }

    /// Create a new range that covers everything.
    pub fn full() -> Self {
        Self::new(Default::default(), Default::default(), Default::default())
    }

    /// Create a new empty range.
    pub fn empty() -> Self {
        Self::new(
            Default::default(),
            Default::default(),
            Range::new(0, RangeEnd::Closed(0)),
        )
    }

    /// Returns `true` if `entry` is included in this range.
    pub fn includes_entry(&self, entry: &Entry) -> bool {
        self.subspaces.includes(&entry.subspace_id)
            && self.paths.includes(&entry.path)
            && self.times.includes(&entry.timestamp)
    }

    /// Returns `true` if this range is completely empty.
    pub fn is_empty(&self) -> bool {
        self.subspaces.is_empty() || self.paths.is_empty() || self.times.is_empty()
    }

    /// Returns the intersection between `self` and `other`.
    pub fn intersection(&self, other: &ThreeDRange) -> Option<Self> {
        let paths = self.paths.intersection(&other.paths)?;
        let times = self.times.intersection(&other.times)?;
        let subspaces = self.subspaces.intersection(&other.subspaces)?;
        Some(Self {
            paths,
            times,
            subspaces,
        })
    }
}

// pub trait Successor: Sized {
//     fn successor(&self) -> Option<Self>;
// }
//
// impl Successor for Timestamp {
//     fn successor(&self) -> Option<Self> {
//         self.checked_add(1)
//     }
// }

/// Ranges are simple, one-dimensional ways of grouping Entries.
///
/// They can express groupings such as “last week’s Entries”. A range is either a closed range or an open range.
/// A closed range consists of a start value and an end value, an open range consists only of a start value.
/// A range includes all values greater than or equal to its start value and strictly less than its end value
/// (if it is has one). A range is empty if it includes no values.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Hash)]
pub struct Range<T> {
    /// A value must be equal or greater than the `start` value to be included in the range.
    pub start: T,
    /// If [`RangeEnd::Open`], this is an open range. Otherwise, a value must be strictly less than
    /// the `end` value to be included in the range.
    pub end: RangeEnd<T>,
}

impl<T: Ord + PartialOrd> Ord for Range<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.start.cmp(&other.start) {
            Ordering::Less => Ordering::Less,
            Ordering::Equal => Ordering::Greater,
            Ordering::Greater => self.end.cmp(&other.end),
        }
    }
}

impl<T: Ord + PartialOrd> PartialOrd for Range<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> From<(T, RangeEnd<T>)> for Range<T> {
    fn from((start, end): (T, RangeEnd<T>)) -> Self {
        Range { start, end }
    }
}

impl<T> Range<T> {
    /// Create a new range.
    pub fn new(start: T, end: RangeEnd<T>) -> Self {
        Self { start, end }
    }

    /// Returns `true` if this range is closed.
    pub fn is_closed(&self) -> bool {
        matches!(self.end, RangeEnd::Closed(_))
    }

    /// Returns `true` if this range is open.
    pub fn is_open(&self) -> bool {
        matches!(self.end, RangeEnd::Open)
    }
}

impl<T: Default> Range<T> {
    /// Create a new range that covers everything.
    pub fn full() -> Self {
        Self::new(T::default(), RangeEnd::Open)
    }
}

impl<T: Default> Default for Range<T> {
    fn default() -> Self {
        Self::full()
    }
}

impl<T: Ord + Eq + Clone> Range<T> {
    /// Create the intersection between this range and another range.
    pub fn intersection(&self, other: &Self) -> Option<Self> {
        let start = (&self.start).max(&other.start);
        let end = match (&self.end, &other.end) {
            (RangeEnd::Open, RangeEnd::Closed(b)) => RangeEnd::Closed(b),
            (RangeEnd::Closed(a), RangeEnd::Closed(b)) => RangeEnd::Closed(a.min(b)),
            (RangeEnd::Closed(a), RangeEnd::Open) => RangeEnd::Closed(a),
            (RangeEnd::Open, RangeEnd::Open) => RangeEnd::Open,
        };
        match end {
            RangeEnd::Open => Some(Self::new(start.clone(), RangeEnd::Open)),
            RangeEnd::Closed(t) if t >= start => {
                Some(Self::new(start.clone(), RangeEnd::Closed(t.clone())))
            }
            RangeEnd::Closed(_) => None,
        }
    }
}

impl<T: Ord + Eq> Range<T> {
    /// Returns `true` if this range includes nothing.
    pub fn is_empty(&self) -> bool {
        match &self.end {
            RangeEnd::Open => false,
            RangeEnd::Closed(t) => t <= &self.start,
        }
    }
}

impl<T: Ord + PartialOrd> Range<T> {
    /// Returns `true` if `value` is included in this range.
    pub fn includes(&self, value: &T) -> bool {
        value >= &self.start && self.end.includes(value)
    }

    /// Returns `true` if `other` range is fully included in this range.
    pub fn includes_range(&self, other: &Range<T>) -> bool {
        self.start <= other.start && self.end >= other.end
    }
}

/// The end of a range, either open or closed.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Hash)]
pub enum RangeEnd<T> {
    /// Closed end: a value has to be strictly less than the close value to be included.
    Closed(T),
    /// Open range (no end value)
    Open,
}

impl<T> RangeEnd<T> {
    /// Returns `true` if this range is closed.
    pub fn is_closed(&self) -> bool {
        matches!(self, RangeEnd::Closed(_))
    }

    /// Returns `true` if this range is open.
    pub fn is_open(&self) -> bool {
        matches!(self, RangeEnd::Open)
    }
}

impl<T: Copy> RangeEnd<T> {
    pub fn or_max(self, max: T) -> T {
        match self {
            Self::Closed(value) => value,
            Self::Open => max,
        }
    }
}

impl<T: Ord + PartialOrd> PartialOrd for RangeEnd<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Ord + PartialOrd> Ord for RangeEnd<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (RangeEnd::Open, RangeEnd::Closed(_)) => Ordering::Greater,
            (RangeEnd::Closed(_), RangeEnd::Open) => Ordering::Less,
            (RangeEnd::Closed(a), RangeEnd::Closed(b)) => a.cmp(b),
            (RangeEnd::Open, RangeEnd::Open) => Ordering::Equal,
        }
    }
}

impl<T: Ord + PartialOrd> RangeEnd<T> {
    /// Returns `true` if the range end is open, or if `value` is strictly less than the range end.
    pub fn includes(&self, value: &T) -> bool {
        match self {
            Self::Open => true,
            Self::Closed(end) => value < end,
        }
    }
}

/// A grouping of Entries that are among the newest in some store.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Hash, Ord, PartialOrd)]
pub struct AreaOfInterest {
    /// To be included in this AreaOfInterest, an Entry must be included in the area.
    pub area: Area,
    /// To be included in this AreaOfInterest, an Entry’s timestamp must be among the max_count greatest Timestamps, unless max_count is zero.
    pub max_count: u64,
    /// The total payload_lengths of all included Entries is at most max_size, unless max_size is zero.
    pub max_size: u64,
}

impl AreaOfInterest {
    pub fn new(area: Area) -> Self {
        Self {
            area,
            max_count: 0,
            max_size: 0,
        }
    }
    /// Create a new [`AreaOfInterest`] that covers everything.
    pub fn full() -> Self {
        Self {
            area: Area::full(),
            max_count: 0,
            max_size: 0,
        }
    }
}

/// A grouping of Entries.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Area {
    /// To be included in this Area, an Entry’s subspace_id must be equal to the subspace_id, unless it is any.
    pub subspace: SubspaceArea,
    /// To be included in this Area, an Entry’s path must be prefixed by the path.
    pub path: Path,
    /// To be included in this Area, an Entry’s timestamp must be included in the times.
    pub times: Range<Timestamp>,
}

impl Area {
    pub const fn new(subspace: SubspaceArea, path: Path, times: Range<Timestamp>) -> Self {
        Self {
            subspace,
            path,
            times,
        }
    }

    pub fn full() -> Self {
        Self::new(SubspaceArea::Any, Path::empty(), Range::<Timestamp>::FULL)
    }

    pub fn empty() -> Self {
        Self::new(SubspaceArea::Any, Path::empty(), Range::<Timestamp>::EMPTY)
    }

    pub fn subspace(subspace_id: SubspaceId) -> Self {
        Self::new(
            SubspaceArea::Id(subspace_id),
            Path::empty(),
            Range::<Timestamp>::FULL,
        )
    }

    pub fn includes_entry(&self, entry: &Entry) -> bool {
        self.includes(&entry.subspace_id, &entry.path, &entry.timestamp)
    }

    pub fn includes(&self, subspace_id: &SubspaceId, path: &Path, timestamp: &Timestamp) -> bool {
        self.subspace.includes_subspace(subspace_id)
            && self.path.is_prefix_of(path)
            && self.times.includes(timestamp)
    }

    pub fn includes_point(&self, point: &Point) -> bool {
        self.includes(&point.subspace_id, &point.path, &point.timestamp)
    }

    pub fn includes_area(&self, other: &Area) -> bool {
        self.subspace.includes(&other.subspace)
            && self.path.is_prefix_of(&other.path)
            && self.times.includes_range(&other.times)
    }

    pub fn includes_range(&self, range: &ThreeDRange) -> bool {
        let path_start = self.path.is_prefix_of(&range.paths.start);
        let path_end = match &range.paths.end {
            RangeEnd::Open => true,
            RangeEnd::Closed(path) => self.path.is_prefix_of(path),
        };
        let subspace_start = self.subspace.includes_subspace(&range.subspaces.start);
        let subspace_end = match range.subspaces.end {
            RangeEnd::Open => true,
            RangeEnd::Closed(subspace) => self.subspace.includes_subspace(&subspace),
        };
        subspace_start
            && subspace_end
            && path_start
            && path_end
            && self.times.includes_range(&range.times)
    }

    pub fn into_range(&self) -> ThreeDRange {
        let subspace_start = match self.subspace {
            SubspaceArea::Any => SubspaceId::default(),
            SubspaceArea::Id(id) => id,
        };
        let subspace_end = match self.subspace {
            SubspaceArea::Any => RangeEnd::Open,
            SubspaceArea::Id(id) => subspace_range_end(id),
        };
        let path_start = self.path.clone();
        let path_end = path_range_end(&self.path);
        ThreeDRange {
            subspaces: Range::new(subspace_start, subspace_end),
            paths: Range::new(path_start, path_end),
            times: self.times,
        }
    }

    pub fn intersection(&self, other: &Area) -> Option<Area> {
        let subspace_id = self.subspace.intersection(&other.subspace)?;
        let path = self.path.intersection(&other.path)?;
        let times = self.times.intersection(&other.times)?;
        Some(Self {
            subspace: subspace_id,
            times,
            path,
        })
    }
}

pub fn path_range_end(path: &Path) -> RangeEnd<Path> {
    if path.is_empty() {
        RangeEnd::Open
    } else {
        let mut out = vec![];
        for component in path.iter().rev() {
            // component can be incremented
            if out.is_empty() && component.iter().any(|x| *x != 0xff) {
                let mut bytes = Vec::with_capacity(component.len());
                bytes.copy_from_slice(component);
                let incremented = increment_by_one(&mut bytes);
                debug_assert!(incremented, "checked above");
                out.push(Bytes::from(bytes));
                break;
            // component cannot be incremented
            } else if out.is_empty() {
                continue;
            } else {
                out.push(component.clone())
            }
        }
        if out.is_empty() {
            RangeEnd::Open
        } else {
            out.reverse();
            RangeEnd::Closed(Path::new_unchecked(out))
        }
    }
}

pub fn subspace_range_end(id: SubspaceId) -> RangeEnd<SubspaceId> {
    let mut bytes = id.to_bytes();
    if increment_by_one(&mut bytes) {
        RangeEnd::Closed(SubspaceId::from_bytes_unchecked(bytes))
    } else {
        RangeEnd::Open
    }
}

/// Increment a byte string by one, by incrementing the last byte that is not 255 by one.
///
/// Returns false if all bytes are 255.
fn increment_by_one(value: &mut [u8]) -> bool {
    for char in value.iter_mut().rev() {
        if *char != 255 {
            *char += 1;
            return true;
        } else {
            *char = 0;
        }
    }
    false
}

impl Range<Timestamp> {
    pub const FULL: Self = Self {
        start: 0,
        end: RangeEnd::Open,
    };

    pub const EMPTY: Self = Self {
        start: 0,
        end: RangeEnd::Closed(0),
    };
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum SubspaceArea {
    Any,
    Id(SubspaceId),
}

impl SubspaceArea {
    pub fn is_any(&self) -> bool {
        matches!(self, SubspaceArea::Any)
    }

    fn includes(&self, other: &SubspaceArea) -> bool {
        match (self, other) {
            (SubspaceArea::Any, SubspaceArea::Any) => true,
            (SubspaceArea::Id(_), SubspaceArea::Any) => false,
            (_, SubspaceArea::Id(id)) => self.includes_subspace(id),
        }
    }
    fn includes_subspace(&self, subspace_id: &SubspaceId) -> bool {
        match self {
            Self::Any => true,
            Self::Id(id) => id == subspace_id,
        }
    }

    fn intersection(&self, other: &Self) -> Option<Self> {
        match (self, other) {
            (Self::Any, Self::Any) => Some(Self::Any),
            (Self::Id(a), Self::Any) => Some(Self::Id(*a)),
            (Self::Any, Self::Id(b)) => Some(Self::Id(*b)),
            (Self::Id(a), Self::Id(b)) if a == b => Some(Self::Id(*a)),
            (Self::Id(_a), Self::Id(_b)) => None,
        }
    }
}

/// A single point in the 3D range space.
///
/// I.e. an entry.
#[derive(Debug, Clone)]
pub struct Point {
    pub path: Path,
    pub timestamp: Timestamp,
    pub subspace_id: SubspaceId,
}

impl Point {
    pub fn new(subspace_id: SubspaceId, path: Path, timestamp: Timestamp) -> Self {
        Self {
            subspace_id,
            path,
            timestamp,
        }
    }
    pub fn from_entry(entry: &Entry) -> Self {
        Self {
            path: entry.path.clone(),
            timestamp: entry.timestamp,
            subspace_id: entry.subspace_id,
        }
    }

    pub fn into_area(&self) -> Area {
        let times = Range::new(self.timestamp, RangeEnd::Closed(self.timestamp + 1));
        Area::new(SubspaceArea::Id(self.subspace_id), self.path.clone(), times)
    }
}

#[derive(thiserror::Error, Debug)]
#[error("area is not included in outer area")]
pub struct NotIncluded;

#[derive(Debug, Clone)]
pub struct AreaInArea<'a> {
    a: &'a Area,
    out: &'a Area,
}

impl<'a> AreaInArea<'a> {
    pub fn new(inner: &'a Area, outer: &'a Area) -> Result<Self, NotIncluded> {
        if outer.includes_area(inner) {
            Ok(Self {
                a: inner,
                out: outer,
            })
        } else {
            Err(NotIncluded)
        }
    }
    fn start_diff(&self) -> u64 {
        let a = self.a.times;
        let out = self.out.times;
        Ord::min(
            a.start.saturating_sub(out.start),
            out.end.or_max(Timestamp::MAX) - a.start,
        )
    }

    fn end_diff(&self) -> u64 {
        let a = self.a.times;
        let out = self.out.times;
        Ord::min(
            a.end.or_max(Timestamp::MAX).saturating_sub(out.start),
            out.end
                .or_max(Timestamp::MAX)
                .saturating_sub(a.end.or_max(Timestamp::MAX)),
        )
    }
}

impl<'a> Encoder for AreaInArea<'a> {
    fn encoded_len(&self) -> usize {
        let subspace_is_same = self.a.subspace == self.out.subspace;
        let mut len = 1;
        if !subspace_is_same {
            len += SubspaceId::LENGTH;
        }
        let relative_path = RelativePath::new(&self.a.path, &self.out.path);
        len += relative_path.encoded_len();
        len += CompactWidth(self.start_diff()).encoded_len();
        if self.a.times.end.is_closed() {
            len += CompactWidth(self.end_diff()).encoded_len();
        }
        len
    }

    fn encode_into<W: io::Write>(&self, out: &mut W) -> anyhow::Result<()> {
        let mut bits = 0u8;
        let subspace_is_same = self.a.subspace == self.out.subspace;
        if !subspace_is_same {
            bits |= 0b0000_0001;
        }
        if self.a.times.is_open() {
            bits |= 0b0000_0010;
        }
        let start_diff = self.start_diff();
        let end_diff = self.start_diff();
        if start_diff == self.a.times.start.saturating_sub(self.out.times.start) {
            bits |= 0b0000_0100;
        }
        if end_diff
            == self
                .a
                .times
                .end
                .or_max(Timestamp::MAX)
                .saturating_sub(self.a.times.start)
        {
            bits |= 0b0000_1000;
        }
        if let 4 | 8 = compact_width(start_diff) {
            bits |= 0b0001_0000;
        }
        if let 2 | 8 = compact_width(start_diff) {
            bits |= 0b0010_0000;
        }
        if let 4 | 8 = compact_width(end_diff) {
            bits |= 0b0100_0000;
        }
        if let 2 | 8 = compact_width(end_diff) {
            bits |= 0b1000_0000;
        }
        out.write_all(&[bits])?;
        match self.a.subspace {
            SubspaceArea::Any => {
                debug_assert!(subspace_is_same, "outers subspace must be any");
            }
            SubspaceArea::Id(subspace_id) => {
                out.write_all(subspace_id.as_bytes())?;
            }
        }
        let relative_path = RelativePath::new(&self.a.path, &self.out.path);
        relative_path.encode_into(out)?;
        CompactWidth(start_diff).encode_into(out)?;
        if self.a.times.end.is_closed() {
            CompactWidth(end_diff).encode_into(out)?;
        }
        Ok(())
    }
}
