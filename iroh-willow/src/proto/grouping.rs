use std::cmp::Ordering;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use super::willow::{Entry, Path, SubspaceId, Timestamp};

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

    /// Get the intersection between this and another range.
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
            (RangeEnd::Closed(a), RangeEnd::Closed(b)) => RangeEnd::Closed(a.min(&b)),
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

impl<T: Ord + PartialOrd> PartialOrd for RangeEnd<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (RangeEnd::Open, RangeEnd::Closed(_)) => Some(Ordering::Greater),
            (RangeEnd::Closed(_), RangeEnd::Open) => Some(Ordering::Less),
            (RangeEnd::Closed(a), RangeEnd::Closed(b)) => a.partial_cmp(b),
            (RangeEnd::Open, RangeEnd::Open) => Some(Ordering::Equal),
        }
    }
}

// impl<T: Ord + PartialOrd> PartialOrd<T> for RangeEnd<T> {
//     fn partial_cmp(&self, other: &T) -> Option<Ordering> {
//         // match (self, other) {
//         //     (RangeEnd::Open, RangeEnd::Closed(_)) => Some(Ordering::Greater),
//         //     (RangeEnd::Closed(_), RangeEnd::Open) => Some(Ordering::Less),
//         //     (RangeEnd::Closed(a), RangeEnd::Closed(b)) => a.partial_cmp(b),
//         //     (RangeEnd::Open, RangeEnd::Open) => Some(Ordering::Equal),
//         // }
//     }
// }

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
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct AreaOfInterest {
    /// To be included in this AreaOfInterest, an Entry must be included in the area.
    pub area: Area,
    /// To be included in this AreaOfInterest, an Entry’s timestamp must be among the max_count greatest Timestamps, unless max_count is zero.
    pub max_count: u64,
    /// The total payload_lengths of all included Entries is at most max_size, unless max_size is zero.
    pub max_size: u64,
}

impl AreaOfInterest {
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
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct Area {
    /// To be included in this Area, an Entry’s subspace_id must be equal to the subspace_id, unless it is any.
    pub subspace_id: SubspaceArea,
    /// To be included in this Area, an Entry’s path must be prefixed by the path.
    pub path: Path,
    /// To be included in this Area, an Entry’s timestamp must be included in the times.
    pub times: Range<Timestamp>,
}

impl Area {
    pub const fn new(subspace_id: SubspaceArea, path: Path, times: Range<Timestamp>) -> Self {
        Self {
            subspace_id,
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
        self.subspace_id.includes_subspace(&entry.subspace_id)
            && self.path.is_prefix_of(&entry.path)
            && self.times.includes(&entry.timestamp)
    }

    pub fn includes_area(&self, other: &Area) -> bool {
        self.subspace_id.includes(&other.subspace_id)
            && self.path.is_prefix_of(&other.path)
            && self.times.includes_range(&other.times)
    }

    pub fn includes_range(&self, range: &ThreeDRange) -> bool {
        let path_start = self.path.is_prefix_of(&range.paths.start);
        let path_end = match &range.paths.end {
            RangeEnd::Open => true,
            RangeEnd::Closed(path) => self.path.is_prefix_of(path),
        };
        let subspace_start = self.subspace_id.includes_subspace(&range.subspaces.start);
        let subspace_end = match range.subspaces.end {
            RangeEnd::Open => true,
            RangeEnd::Closed(subspace) => self.subspace_id.includes_subspace(&subspace),
        };
        subspace_start
            && subspace_end
            && path_start
            && path_end
            && self.times.includes_range(&range.times)
    }

    pub fn into_range(&self) -> ThreeDRange {
        let subspace_start = match self.subspace_id {
            SubspaceArea::Any => SubspaceId::default(),
            SubspaceArea::Id(id) => id,
        };
        let subspace_end = match self.subspace_id {
            SubspaceArea::Any => RangeEnd::Open,
            SubspaceArea::Id(id) => subspace_range_end(id),
        };
        let path_start = self.path.clone();
        let path_end = path_range_end(&self.path);
        ThreeDRange {
            subspaces: Range::new(subspace_start, subspace_end),
            paths: Range::new(path_start, path_end),
            times: self.times.clone(),
        }
    }

    pub fn intersection(&self, other: &Area) -> Option<Area> {
        let subspace_id = self.subspace_id.intersection(&other.subspace_id)?;
        let path = self.path.intersection(&other.path)?;
        let times = self.times.intersection(&other.times)?;
        Some(Self {
            subspace_id,
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
                bytes.copy_from_slice(&component);
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
            RangeEnd::Closed(Path::from_bytes_unchecked(out))
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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum SubspaceArea {
    Any,
    Id(SubspaceId),
}

impl SubspaceArea {
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
