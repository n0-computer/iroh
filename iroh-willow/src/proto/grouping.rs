//! Utilities for Willow's entry [groupings](https://willowprotocol.org/specs/grouping-entries/index.html#grouping_entries).

use serde::{Deserialize, Serialize};
pub use willow_data_model::grouping::{Range, RangeEnd};
use willow_data_model::SubspaceId as _;

use super::data_model::{
    self, Entry, Path, SubspaceId, Timestamp, MAX_COMPONENT_COUNT, MAX_COMPONENT_LENGTH,
    MAX_PATH_LENGTH,
};

/// See [`willow_data_model::grouping::Range3d`].
pub type Range3d = willow_data_model::grouping::Range3d<
    MAX_COMPONENT_LENGTH,
    MAX_COMPONENT_COUNT,
    MAX_PATH_LENGTH,
    SubspaceId,
>;

/// See [`willow_data_model::grouping::Area`].
pub type Area = willow_data_model::grouping::Area<
    MAX_COMPONENT_LENGTH,
    MAX_COMPONENT_COUNT,
    MAX_PATH_LENGTH,
    SubspaceId,
>;

/// See [`willow_data_model::grouping::AreaSubspace`].
pub type AreaSubspace = willow_data_model::grouping::AreaSubspace<SubspaceId>;

/// See [`willow_data_model::grouping::AreaOfInterest`].
pub type AreaOfInterest = willow_data_model::grouping::AreaOfInterest<
    MAX_COMPONENT_LENGTH,
    MAX_COMPONENT_COUNT,
    MAX_PATH_LENGTH,
    SubspaceId,
>;

/// Extension methods for [`AreaOfInterest`].
pub trait AreaOfInterestExt {
    /// Creates a new area of interest with the specified area and no other limits.
    fn with_area(area: Area) -> AreaOfInterest;
}

impl AreaOfInterestExt for AreaOfInterest {
    fn with_area(area: Area) -> AreaOfInterest {
        AreaOfInterest {
            area,
            max_count: 0,
            max_size: 0,
        }
    }
}

/// Extension methods for [`Area`].
pub trait AreaExt {
    /// Returns `true` if the area contains `point`.
    fn includes_point(&self, point: &Point) -> bool;

    /// Creates a new area with `path` as prefix and no constraints on subspace or timestamp.
    fn new_path(path: Path) -> Area;

    /// Converts the area into a [`Range3d`].
    fn to_range(&self) -> Range3d;
}

impl AreaExt for Area {
    fn includes_point(&self, point: &Point) -> bool {
        self.includes_area(&point.into_area())
    }

    fn new_path(path: Path) -> Self {
        Self::new(AreaSubspace::Any, path, Range::full())
    }

    fn to_range(&self) -> Range3d {
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
        Range3d::new(subspaces, path_range, *self.times())
    }
}

/// A single point in the 3D range space.
///
/// I.e. an entry.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct Point {
    #[serde(with = "data_model::serde_encoding::path")]
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
            path: entry.path().clone(),
            timestamp: entry.timestamp(),
            subspace_id: *entry.subspace_id(),
        }
    }

    pub fn into_area(&self) -> Area {
        let times = Range::new_closed(self.timestamp, self.timestamp + 1).expect("verified");
        Area::new(AreaSubspace::Id(self.subspace_id), self.path.clone(), times)
    }
}

pub mod serde_encoding {
    use serde::{de, Deserialize, Deserializer, Serialize};

    use crate::util::codec2::{from_bytes_relative, to_vec_relative};

    use super::*;

    pub mod area {
        use super::*;
        pub fn serialize<S: serde::Serializer>(
            area: &Area,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let previous = Area::new_full();
            let encoded_area = to_vec_relative(&previous, area);
            encoded_area.serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Area, D::Error>
        where
            D: Deserializer<'de>,
        {
            let relative = Area::new_full();
            let encoded_area: Vec<u8> = Deserialize::deserialize(deserializer)?;
            let area = from_bytes_relative(&relative, &encoded_area).map_err(de::Error::custom)?;
            Ok(area)
        }
    }

    pub mod area_of_interest {
        use super::*;
        pub fn serialize<S: serde::Serializer>(
            aoi: &AreaOfInterest,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let previous = Area::new_full();
            let encoded_area = to_vec_relative(&previous, &aoi.area);
            (encoded_area, aoi.max_count, aoi.max_size).serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<AreaOfInterest, D::Error>
        where
            D: Deserializer<'de>,
        {
            let relative = Area::new_full();
            let (encoded_area, max_count, max_size): (Vec<u8>, u64, u64) =
                Deserialize::deserialize(deserializer)?;
            let area = from_bytes_relative(&relative, &encoded_area).map_err(de::Error::custom)?;
            Ok(AreaOfInterest::new(area, max_count, max_size))
        }
    }

    pub mod range_3d {
        use super::*;
        pub fn serialize<S: serde::Serializer>(
            range: &Range3d,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let previous = Range3d::new_full();
            to_vec_relative(&previous, range).serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Range3d, D::Error>
        where
            D: Deserializer<'de>,
        {
            let previous = Range3d::new_full();
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            let decoded = from_bytes_relative(&previous, &bytes).map_err(de::Error::custom)?;
            Ok(decoded)
        }
    }

    #[derive(
        Debug,
        Clone,
        Eq,
        PartialEq,
        derive_more::From,
        derive_more::Into,
        derive_more::Deref,
        Serialize,
        Deserialize,
    )]
    pub struct SerdeArea(#[serde(with = "area")] pub Area);

    #[derive(
        Debug,
        Clone,
        Eq,
        PartialEq,
        derive_more::From,
        derive_more::Into,
        derive_more::Deref,
        Serialize,
        Deserialize,
    )]
    pub struct SerdeAreaOfInterest(#[serde(with = "area_of_interest")] pub AreaOfInterest);

    #[derive(
        Debug,
        Clone,
        derive_more::From,
        derive_more::Into,
        derive_more::Deref,
        Serialize,
        Deserialize,
    )]
    pub struct SerdeRange3d(#[serde(with = "range_3d")] pub Range3d);
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
        let p1 = Path::from_bytes(&[b"foo", b"bar"]).unwrap();
        let a1 = Area::new_path(p1);
        let p2 = Path::from_bytes(&[b"foo", b"bar"]).unwrap();
        let a2 = Area::new_path(p2);
        assert_eq!(a1, a2);
        let mut set = HashSet::new();
        set.insert(a1.clone());
        set.insert(a2.clone());
        assert_eq!(set.len(), 1);
    }
}
