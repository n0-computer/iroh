pub use willow_data_model::grouping::{Range, RangeEnd};
use willow_data_model::SubspaceId as _;

use super::data_model::{
    Entry, Path, SubspaceId, Timestamp, MAX_COMPONENT_COUNT, MAX_COMPONENT_LENGTH, MAX_PATH_LENGTH,
};

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

pub type Range3d = willow_data_model::grouping::Range3d<
    MAX_COMPONENT_LENGTH,
    MAX_COMPONENT_COUNT,
    MAX_PATH_LENGTH,
    SubspaceId,
>;

pub type ThreeDRange = Range3d;

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
// #[derive(Debug, Clone, Eq, PartialEq, derive_more::From, derive_more::Into, derive_more::Deref)]
// pub struct AreaOfInterest(
//     willow_data_model::grouping::AreaOfInterest<
//         MAX_COMPONENT_LENGTH,
//         MAX_COMPONENT_COUNT,
//         MAX_PATH_LENGTH,
//         SubspaceId,
//     >,
// );
pub type AreaOfInterest = willow_data_model::grouping::AreaOfInterest<
    MAX_COMPONENT_LENGTH,
    MAX_COMPONENT_COUNT,
    MAX_PATH_LENGTH,
    SubspaceId,
>;

pub trait AreaOfInterestExt {
    fn new(area: Area) -> AreaOfInterest;
}

impl AreaOfInterestExt for AreaOfInterest {
    fn new(area: Area) -> AreaOfInterest {
        AreaOfInterest {
            area,
            max_count: 0,
            max_size: 0,
        }
    }
}

pub trait AreaExt {
    fn includes_point(&self, point: &Point) -> bool;
    fn new_path(path: Path) -> Area;
    fn into_range(&self) -> Range3d;
}

impl AreaExt for Area {
    fn includes_point(&self, point: &Point) -> bool {
        self.includes_area(&point.into_area())
    }

    fn new_path(path: Path) -> Self {
        Self::new(AreaSubspace::Any, path, Range::full())
    }

    fn into_range(&self) -> Range3d {
        let subspaces = match self.subspace() {
            AreaSubspace::Id(id) => match id.successor() {
                None => Range::new_open(*id),
                Some(end) => Range::new_closed(*id, end).expect("successor is bigger"),
            },
            AreaSubspace::Any => Default::default(),
        };
        let path = self.path();
        let path_range = match path.greater_but_not_prefixed() {
            None => Range::new_open(path.clone()),
            Some(end) => Range::new_closed(path.clone(), end).expect("successor is bigger"),
        };
        Range3d::new(subspaces, path_range, self.times().clone())
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

pub mod serde_encoding {
    use serde::{Deserialize, Deserializer, Serialize};
    use ufotofu::sync::{consumer::IntoVec, producer::FromSlice};
    use willow_encoding::sync::{RelativeDecodable, RelativeEncodable};

    use super::*;

    #[derive(
        Debug, Clone, Eq, PartialEq, derive_more::From, derive_more::Into, derive_more::Deref,
    )]
    pub struct SerdeAreaOfInterest(pub AreaOfInterest);

    impl Serialize for SerdeAreaOfInterest {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let relative = Area::new_full();
            let encoded_area = {
                let mut consumer = IntoVec::<u8>::new();
                self.0
                    .area
                    .relative_encode(&relative, &mut consumer)
                    .expect("encoding not to fail");
                consumer.into_vec()
            };
            (encoded_area, self.0.max_count, self.0.max_size).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for SerdeAreaOfInterest {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let relative = Area::new_full();
            let (encoded_area, max_count, max_size): (Vec<u8>, u64, u64) =
                Deserialize::deserialize(deserializer)?;
            let decoded_area = {
                let mut producer = FromSlice::new(&encoded_area);
                let decoded =
                    willow_data_model::grouping::Area::relative_decode(&relative, &mut producer)
                        .map_err(|err| serde::de::Error::custom(format!("{err}")))?;
                decoded
            };
            let aoi = willow_data_model::grouping::AreaOfInterest {
                area: decoded_area,
                max_count,
                max_size,
            };
            Ok(Self(aoi))
        }
    }

    #[derive(Debug, Clone, derive_more::From, derive_more::Into, derive_more::Deref)]
    pub struct SerdeRange3d(pub Range3d);

    impl Serialize for SerdeRange3d {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let relative = Range3d::new(
                Default::default(),
                Range::new_open(Path::new_empty()),
                Default::default(),
            );
            let encoded = {
                let mut consumer = IntoVec::<u8>::new();
                self.0
                    .relative_encode(&relative, &mut consumer)
                    .expect("encoding not to fail");
                consumer.into_vec()
            };
            encoded.serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for SerdeRange3d {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let relative = Range3d::new(
                Default::default(),
                Range::new_open(Path::new_empty()),
                Default::default(),
            );
            let encoded_range: Vec<u8> = Deserialize::deserialize(deserializer)?;
            let decoded_range = {
                let mut producer = FromSlice::new(&encoded_range);
                let decoded =
                    willow_data_model::grouping::Range3d::relative_decode(&relative, &mut producer)
                        .map_err(|err| serde::de::Error::custom(format!("{err}")))?;
                decoded
            };
            Ok(Self(decoded_range))
        }
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
