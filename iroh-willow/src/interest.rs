//! Types for defining synchronisation interests.

use std::collections::{hash_map, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::proto::{
    data_model::Entry,
    grouping::{self, Area, AreaExt, AreaOfInterest, Point},
    keys::{NamespaceId, UserId},
    meadowcap::{self, AccessMode, McCapability, ReadAuthorisation},
};

pub type InterestMap = HashMap<ReadAuthorisation, HashSet<AreaOfInterest>>;

/// Enum for describing synchronisation interests.
///
/// You should use [`Self::builder`] for a straightforward way to construct this.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub enum Interests {
    /// Use all the capabilities we have.
    #[default]
    All,
    /// Use the selected capabilities and areas.
    Select(HashMap<CapSelector, AreaOfInterestSelector>),
    // /// Use exactly the specified capabilities and areas.
    // TODO: removed this for now, maybe we want and need it. Will need serde support.
    // Exact(InterestMap),
}

impl Interests {
    /// Returns a [`InterestBuilder`] to build our [`Interests`].
    pub fn builder() -> InterestBuilder {
        InterestBuilder::default()
    }

    /// Creates interests that include all our capabilities.
    pub fn all() -> Self {
        Self::All
    }
}

/// Builder for [`Interests`].
#[derive(Default, Debug)]
pub struct InterestBuilder(HashMap<CapSelector, AreaOfInterestSelector>);

/// Helper trait to accept both [`Area`] and [`AreaOfInterest`] in the [`InterestBuilder`].
pub trait IntoAreaOfInterest {
    fn into_area_of_interest(self) -> AreaOfInterest;
}

impl IntoAreaOfInterest for AreaOfInterest {
    fn into_area_of_interest(self) -> AreaOfInterest {
        self
    }
}

impl IntoAreaOfInterest for Area {
    fn into_area_of_interest(self) -> AreaOfInterest {
        AreaOfInterest::new(self, 0, 0)
    }
}

impl InterestBuilder {
    /// Add a capability and areas of interest
    ///
    /// See [`CapSelector`] for how to specify the capability to use.
    pub fn add(mut self, cap: impl Into<CapSelector>, areas: AreaOfInterestSelector) -> Self {
        let cap = cap.into();
        self.0.insert(cap, areas);
        self
    }
    /// Add the full area of a capability we have into the interests.
    ///
    /// See [`CapSelector`] for how to specify the capability to use.
    pub fn add_full_cap(self, cap: impl Into<CapSelector>) -> Self {
        self.add(cap, AreaOfInterestSelector::Widest)
    }

    /// Add a specific area included in one of our capabilities into the interests.
    ///
    /// See [`CapSelector`] for how to specify the capability to use.
    pub fn add_area(
        mut self,
        cap: impl Into<CapSelector>,
        aois: impl IntoIterator<Item = impl IntoAreaOfInterest>,
    ) -> Self {
        let cap = cap.into();
        let aois = aois.into_iter();
        let aois = aois.map(|aoi| aoi.into_area_of_interest());
        match self.0.entry(cap) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert(AreaOfInterestSelector::Exact(aois.collect()));
            }
            hash_map::Entry::Occupied(mut entry) => match entry.get_mut() {
                AreaOfInterestSelector::Widest => {}
                AreaOfInterestSelector::Exact(existing) => existing.extend(aois),
            },
        }
        self
    }

    /// Converts this builder into [`Interests`].
    pub fn build(self) -> Interests {
        Interests::Select(self.0)
    }
}

impl From<InterestBuilder> for Interests {
    fn from(builder: InterestBuilder) -> Self {
        builder.build()
    }
}

/// Selector for an [`AreaOfInterest`].
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub enum AreaOfInterestSelector {
    /// Use the widest area allowed by a capability, with no further limits.
    #[default]
    Widest,
    /// Use the specified set of [`AreaOfInterest`].
    #[serde(with = "serde_area_of_interest_set")]
    Exact(HashSet<AreaOfInterest>),
}

mod serde_area_of_interest_set {
    // TODO: Less clones and allocs.
    use crate::proto::grouping::serde_encoding::SerdeAreaOfInterest;
    use serde::Deserializer;

    use super::*;
    pub fn serialize<S: serde::Serializer>(
        items: &HashSet<AreaOfInterest>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let items: Vec<_> = items
            .iter()
            .map(|aoi| SerdeAreaOfInterest(aoi.clone()))
            .collect();
        items.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashSet<AreaOfInterest>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let items: Vec<SerdeAreaOfInterest> = Deserialize::deserialize(deserializer)?;
        Ok(items.into_iter().map(|aoi| aoi.0).collect())
    }
}

/// Selector for a capability.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapSelector {
    /// The namespace to which the capability must grant access.
    pub namespace_id: NamespaceId,
    /// Select the user who may use the capability.
    pub receiver: UserSelector,
    /// Select the area to which the capability grants access.
    pub granted_area: AreaSelector,
}

impl From<NamespaceId> for CapSelector {
    fn from(value: NamespaceId) -> Self {
        Self::any(value)
    }
}

impl CapSelector {
    /// Checks if the provided capability is matched by this [`CapSelector`].
    pub fn is_covered_by(&self, cap: &McCapability) -> bool {
        self.namespace_id == *cap.granted_namespace()
            && self.receiver.includes(cap.receiver())
            && self.granted_area.is_covered_by(&cap.granted_area())
    }

    /// Creates a new [`CapSelector`].
    pub fn new(
        namespace_id: NamespaceId,
        receiver: UserSelector,
        granted_area: AreaSelector,
    ) -> Self {
        Self {
            namespace_id,
            receiver,
            granted_area,
        }
    }

    /// Creates a [`CapSelector`] which selects the widest capability for the provided namespace
    /// and user.
    pub fn with_user(namespace_id: NamespaceId, user_id: UserId) -> Self {
        Self::new(
            namespace_id,
            UserSelector::Exact(user_id),
            AreaSelector::Widest,
        )
    }

    /// Creates a [`CapSelector`] which selects the widest capability for the provided namespace.
    ///
    /// Will use any user available in our secret store and select the capability which grants the
    /// widest area.
    // TODO: Document exact selection process if there are capabilities with distinct areas.
    pub fn any(namespace: NamespaceId) -> Self {
        Self::new(namespace, UserSelector::Any, AreaSelector::Widest)
    }

    /// Select a capability which authorises writing the provided `entry` on behalf of the provided
    /// `user_id`.
    pub fn for_entry(entry: &Entry, user_id: UserSelector) -> Self {
        let granted_area = AreaSelector::ContainsPoint(Point::from_entry(entry));
        Self {
            namespace_id: *entry.namespace_id(),
            receiver: user_id,
            granted_area,
        }
    }
}

/// Select the receiver for a capability.
#[derive(
    Debug, Default, Clone, Copy, Eq, PartialEq, derive_more::From, Serialize, Deserialize, Hash,
)]
pub enum UserSelector {
    /// The receiver may be any user for which we have a secret key stored.
    #[default]
    Any,
    /// The receiver must be the provided user.
    Exact(UserId),
}

impl UserSelector {
    pub fn includes(&self, user: &UserId) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(u) => u == user,
        }
    }
}

/// Selector for the area to which a capability must grant access.
#[derive(Debug, Clone, Default, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum AreaSelector {
    /// Use the capability which covers the biggest area.
    #[default]
    Widest,
    /// Use any capability that covers the provided area.
    ContainsArea(#[serde(with = "grouping::serde_encoding::area")] Area),
    /// Use any capability that covers the provided point (i.e. entry).
    ContainsPoint(Point),
}

impl AreaSelector {
    /// Checks whether the provided [`Area`] is matched by this [`AreaSelector`].
    pub fn is_covered_by(&self, other: &Area) -> bool {
        match self {
            AreaSelector::Widest => true,
            AreaSelector::ContainsArea(area) => other.includes_area(area),
            AreaSelector::ContainsPoint(point) => other.includes_point(point),
        }
    }
}

/// A serializable capability.
// TODO: This doesn't really belong into this module.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CapabilityPack {
    /// A read authorisation.
    Read(#[serde(with = "meadowcap::serde_encoding::read_authorisation")] ReadAuthorisation),
    /// A write authorisation.
    Write(#[serde(with = "meadowcap::serde_encoding::mc_capability")] McCapability),
}

impl CapabilityPack {
    pub fn receiver(&self) -> UserId {
        match self {
            CapabilityPack::Read(auth) => *auth.read_cap().receiver(),
            CapabilityPack::Write(cap) => *cap.receiver(),
        }
    }

    pub fn namespace(&self) -> NamespaceId {
        match self {
            CapabilityPack::Read(cap) => cap.namespace(),
            CapabilityPack::Write(cap) => *cap.granted_namespace(),
        }
    }

    pub fn validate(&self) -> Result<(), InvalidCapabilityPack> {
        // meadowcap capability themselves are validated on creation/deserialization.
        let is_valid = match self {
            Self::Read(cap) => cap.read_cap().access_mode() == AccessMode::Read,
            Self::Write(cap) => cap.access_mode() == AccessMode::Write,
        };
        if !is_valid {
            Err(InvalidCapabilityPack)
        } else {
            Ok(())
        }
        // match self {
        //     CapabilityPack::Read(auth) => {
        //         auth.read_cap().validate()?;
        //         if let Some(subspace_cap) = auth.subspace_cap() {
        //             subspace_cap.validate()?;
        //         }
        //     }
        //     CapabilityPack::Write(cap) => {
        //         cap.0.validate()?;
        //     }
        // }
        // Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Invalid capability pack.")]
pub struct InvalidCapabilityPack;

// TODO: This doesn't really belong into this module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegateTo {
    pub user: UserId,
    pub restrict_area: RestrictArea,
}

impl DelegateTo {
    pub fn new(user: UserId, restrict_area: RestrictArea) -> Self {
        Self {
            user,
            restrict_area,
        }
    }
}

// TODO: This doesn't really belong into this module.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum RestrictArea {
    #[default]
    None,
    Restrict(#[serde(with = "grouping::serde_encoding::area")] Area),
}

impl RestrictArea {
    pub fn or_default(self, default: Area) -> Area {
        match self {
            RestrictArea::None => default.clone(),
            RestrictArea::Restrict(area) => area,
        }
    }
}
