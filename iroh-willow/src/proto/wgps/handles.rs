use serde::{Deserialize, Serialize};

/// The different resource handles employed by the WGPS.
#[derive(Debug, Serialize, Deserialize, strum::Display)]
pub enum HandleType {
    /// Resource handle for the private set intersection part of private area intersection.
    /// More precisely, an IntersectionHandle stores a PsiGroup member together with one of two possible states:
    /// * pending (waiting for the other peer to perform scalar multiplication),
    /// * completed (both peers performed scalar multiplication).
    Intersection,

    /// Resource handle for [`crate::proto::meadowcap::ReadAuthorisation`] that certify access to some Entries.
    Capability,

    /// Resource handle for [`crate::proto::grouping::AreaOfInterest`]s that peers wish to sync.
    AreaOfInterest,

    /// Resource handle that controls the matching from Payload transmissions to Payload requests.
    PayloadRequest,

    /// Resource handle for [`super::StaticToken`]s that peers need to transmit.
    StaticToken,
}

pub trait IsHandle:
    std::fmt::Debug + std::hash::Hash + From<u64> + Into<ResourceHandle> + Copy + Eq + PartialEq
{
    fn handle_type(&self) -> HandleType;
    fn value(&self) -> u64;
}

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, Clone, Copy, derive_more::From)]
pub struct AreaOfInterestHandle(u64);

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, Clone, Copy, derive_more::From)]
pub struct IntersectionHandle(u64);

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, Clone, Copy, derive_more::From)]
pub struct CapabilityHandle(u64);

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq, Clone, Copy, derive_more::From)]
pub struct StaticTokenHandle(u64);

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, derive_more::From)]
pub enum ResourceHandle {
    AreaOfInterest(AreaOfInterestHandle),
    Intersection(IntersectionHandle),
    Capability(CapabilityHandle),
    StaticToken(StaticTokenHandle),
}

impl IsHandle for CapabilityHandle {
    fn handle_type(&self) -> HandleType {
        HandleType::Capability
    }
    fn value(&self) -> u64 {
        self.0
    }
}
impl IsHandle for StaticTokenHandle {
    fn handle_type(&self) -> HandleType {
        HandleType::StaticToken
    }
    fn value(&self) -> u64 {
        self.0
    }
}
impl IsHandle for AreaOfInterestHandle {
    fn handle_type(&self) -> HandleType {
        HandleType::AreaOfInterest
    }
    fn value(&self) -> u64 {
        self.0
    }
}
impl IsHandle for IntersectionHandle {
    fn handle_type(&self) -> HandleType {
        HandleType::Intersection
    }
    fn value(&self) -> u64 {
        self.0
    }
}
