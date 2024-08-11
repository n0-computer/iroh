use willow_data_model::grouping::RangeEnd;

use super::data_model::{
    Entry, Path, SubspaceId, Timestamp, MAX_COMPONENT_COUNT, MAX_COMPONENT_LENGTH, MAX_PATH_LENGTH,
};

pub type Range<T> = willow_data_model::grouping::Range<T>;

// /// A three-dimensional range that includes every [`Entry`] included in all three of its ranges.
// #[derive(
//     Debug, Clone, Hash, Eq, PartialEq, derive_more::From, derive_more::Into, derive_more::Deref,
// )]
// pub struct Three3Range(
//     willow_data_model::grouping::Range3d<
//         MAX_COMPONENT_LENGTH,
//         MAX_COMPONENT_COUNT,
//         MAX_PATH_LENGTH,
//         SubspaceId,
//     >,
// );

/// A grouping of entries.
/// [Definition](https://willowprotocol.org/specs/grouping-entries/index.html#areas).
// #[derive(
//     Debug, Clone, Eq, PartialEq, Hash, derive_more::From, derive_more::Into, derive_more::Deref,
// )]
// pub struct Area(
//     willow_data_model::grouping::Area<
//         MAX_COMPONENT_LENGTH,
//         MAX_COMPONENT_COUNT,
//         MAX_PATH_LENGTH,
//         SubspaceId,
//     >,
// );

pub type Three3Range = willow_data_model::grouping::Range3d<
    MAX_COMPONENT_LENGTH,
    MAX_COMPONENT_COUNT,
    MAX_PATH_LENGTH,
    SubspaceId,
>;

pub type Area = willow_data_model::grouping::Area<
    MAX_COMPONENT_LENGTH,
    MAX_COMPONENT_COUNT,
    MAX_PATH_LENGTH,
    SubspaceId,
>;

pub type AreaSubspace = willow_data_model::grouping::AreaSubspace<SubspaceId>;

/// A grouping of [`crate::Entry`]s that are among the newest in some [store](https://willowprotocol.org/specs/data-model/index.html#store).
///
/// [Definition](https://willowprotocol.org/specs/grouping-entries/index.html#aois).
#[derive(Debug, Clone, Eq, PartialEq, derive_more::From, derive_more::Into, derive_more::Deref)]
pub struct AreaOfInterest(
    willow_data_model::grouping::AreaOfInterest<
        MAX_COMPONENT_LENGTH,
        MAX_COMPONENT_COUNT,
        MAX_PATH_LENGTH,
        SubspaceId,
    >,
);

pub trait AreaExt {
    fn includes_point(&self, point: &Point) -> bool;
    fn new_path(path: Path) -> Area;
}

impl AreaExt for Area {
    fn includes_point(&self, point: &Point) -> bool {
        self.includes_area(&point.into_area())
    }

    fn new_path(path: Path) -> Self {
        Self::new(AreaSubspace::Any, path, Range::full())
    }
}

// impl Area {
//     /// Create a new [`Area`].
//     pub fn new(subspace: AreaSubspace, path: Path, times: Range<Timestamp>) -> Self {
//         Self(willow_data_model::grouping::Area::new(
//             subspace,
//             path.into(),
//             times,
//         ))
//     }

//     pub fn includes_point(&self, point: &Point) -> bool {
//         self.includes_area(&point.into_area())
//     }

//     pub fn path(path: Path) -> Self {
//         Self::new(AreaSubspace::Any, path, Range::full())
//     }
// }

/// A single point in the 3D range space.
///
/// I.e. an entry.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
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
            path: entry.path().clone().into(),
            timestamp: entry.timestamp(),
            subspace_id: *entry.subspace_id(),
        }
    }

    pub fn into_area(&self) -> Area {
        let times = Range {
            start: self.timestamp,
            end: RangeEnd::Closed(self.timestamp + 1),
        };
        Area::new(AreaSubspace::Id(self.subspace_id), self.path.clone(), times)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::proto::{
        data_model::{Path, PathExt},
        grouping::{Area, AreaExt},
    };

    #[test]
    fn area_eq() {
        let p1 = Path::new(&[b"foo", b"bar"]).unwrap();
        let a1 = Area::new_path(p1);
        let p2 = Path::new(&[b"foo", b"bar"]).unwrap();
        let a2 = Area::new_path(p2);
        assert_eq!(a1, a2);
        let mut set = HashSet::new();
        set.insert(a1.clone());
        set.insert(a2.clone());
        assert_eq!(set.len(), 1);
    }
}
