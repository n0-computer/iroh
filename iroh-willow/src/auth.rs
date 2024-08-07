use std::collections::{HashMap, HashSet};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{
    proto::{
        grouping::{Area, AreaOfInterest, Point},
        keys::{NamespaceId, NamespaceKind, NamespacePublicKey, UserId, UserPublicKey},
        meadowcap::{AccessMode, McCapability},
        sync::ReadAuthorisation,
        willow::{Entry, WriteCapability},
    },
    session::{AreaOfInterestSelector, Interests},
    store::traits::{CapsStorage, SecretStorage, SecretStoreError, Storage},
};

pub type InterestMap = HashMap<ReadAuthorisation, HashSet<AreaOfInterest>>;

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub enum RestrictArea {
    None,
    Restrict(Area),
}

impl RestrictArea {
    pub fn with_default(self, default: Area) -> Area {
        match self {
            RestrictArea::None => default.clone(),
            RestrictArea::Restrict(area) => area,
        }
    }
}

/// Selector for a capability.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct CapSelector {
    /// The namespace to which the capability must grant access.
    pub namespace_id: NamespaceId,
    /// Select the user who may use the capability.
    pub receiver: ReceiverSelector,
    /// Select the area to which the capability grants access.
    pub granted_area: AreaSelector,
}

impl From<NamespaceId> for CapSelector {
    fn from(value: NamespaceId) -> Self {
        Self::widest(value)
    }
}

impl CapSelector {
    /// Checks if the provided capability is matched by this [`CapSelector`].
    pub fn is_covered_by(&self, cap: &McCapability) -> bool {
        self.namespace_id == cap.granted_namespace().id()
            && self.receiver.includes(&cap.receiver().id())
            && self.granted_area.is_covered_by(&cap.granted_area())
    }

    /// Creates a new [`CapSelector`].
    pub fn new(
        namespace_id: NamespaceId,
        receiver: ReceiverSelector,
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
            ReceiverSelector::Exact(user_id),
            AreaSelector::Widest,
        )
    }

    /// Creates a [`CapSelector`] which selects the widest capability for the provided namespace.
    ///
    /// Will use any user available in our secret store and select the capability which grants the
    /// widest area.
    // TODO: Document exact selection process if there are capabilities with distinct areas.
    pub fn widest(namespace: NamespaceId) -> Self {
        Self::new(namespace, ReceiverSelector::Any, AreaSelector::Widest)
    }

    /// Select a capability which authorises writing the provided `entry` on behalf of the provided
    /// `user_id`.
    pub fn for_entry(entry: &Entry, user_id: ReceiverSelector) -> Self {
        let granted_area = AreaSelector::ContainsPoint(Point::from_entry(entry));
        Self {
            namespace_id: entry.namespace_id,
            receiver: user_id,
            granted_area,
        }
    }
}

/// Select the receiver for a capability.
#[derive(
    Debug, Default, Clone, Copy, Eq, PartialEq, derive_more::From, Serialize, Deserialize, Hash,
)]
pub enum ReceiverSelector {
    /// The receiver may be any user for which we have a secret key stored.
    #[default]
    Any,
    /// The receiver must be the provided user.
    Exact(UserId),
}

impl ReceiverSelector {
    pub fn includes(&self, user: &UserId) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(u) => u == user,
        }
    }
}

/// Selector for the area to which a capability must grant access.
#[derive(Debug, Clone, Default, Hash, Eq, PartialEq)]
pub enum AreaSelector {
    /// Use the capability which covers the biggest area.
    #[default]
    Widest,
    /// Use any capability that covers the provided area.
    ContainsArea(Area),
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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CapabilityPack {
    /// A read authorisation.
    Read(ReadAuthorisation),
    /// A write authorisation.
    Write(WriteCapability),
}

impl CapabilityPack {
    pub fn receiver(&self) -> UserId {
        match self {
            CapabilityPack::Read(auth) => auth.read_cap().receiver().id(),
            CapabilityPack::Write(cap) => cap.receiver().id(),
        }
    }
    pub fn validate(&self) -> Result<(), AuthError> {
        match self {
            CapabilityPack::Read(auth) => {
                auth.read_cap().validate()?;
                if let Some(subspace_cap) = auth.subspace_cap() {
                    subspace_cap.validate()?;
                }
            }
            CapabilityPack::Write(cap) => {
                cap.validate()?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Auth<S: Storage> {
    secrets: S::Secrets,
    caps: S::Caps,
}

impl<S: Storage> Auth<S> {
    pub fn new(secrets: S::Secrets, caps: S::Caps) -> Self {
        Self { secrets, caps }
    }
    pub fn get_write_cap(
        &self,
        selector: &CapSelector,
    ) -> Result<Option<WriteCapability>, AuthError> {
        let cap = self.caps.get_write_cap(selector)?;
        Ok(cap)
    }

    pub fn get_read_cap(
        &self,
        selector: &CapSelector,
    ) -> Result<Option<ReadAuthorisation>, AuthError> {
        let cap = self.caps.get_read_cap(selector)?;
        Ok(cap)
    }

    pub fn list_read_caps(&self) -> Result<impl Iterator<Item = ReadAuthorisation> + '_> {
        self.caps.list_read_caps(None)
    }

    pub fn import_caps(
        &self,
        caps: impl IntoIterator<Item = CapabilityPack>,
    ) -> Result<(), AuthError> {
        for cap in caps.into_iter() {
            cap.validate()?;
            // Only allow importing caps we can use.
            // TODO: Is this what we want?
            let user_id = cap.receiver();
            if !self.secrets.has_user(&user_id) {
                return Err(AuthError::MissingUserSecret(user_id));
            }
            self.caps.insert(cap)?;
        }
        Ok(())
    }

    pub fn insert_caps_unchecked(
        &self,
        caps: impl IntoIterator<Item = CapabilityPack>,
    ) -> Result<(), AuthError> {
        for cap in caps.into_iter() {
            debug!(?cap, "insert cap");
            self.caps.insert(cap)?;
        }
        Ok(())
    }

    pub fn resolve_interests(&self, interests: Interests) -> Result<InterestMap, AuthError> {
        match interests {
            Interests::All => {
                let out = self
                    .list_read_caps()?
                    .map(|auth| {
                        let area = auth.read_cap().granted_area();
                        let aoi = AreaOfInterest::new(area);
                        (auth, HashSet::from_iter([aoi]))
                    })
                    .collect::<HashMap<_, _>>();
                Ok(out)
            }
            Interests::Select(interests) => {
                let mut out: InterestMap = HashMap::new();
                for (cap_selector, aoi_selector) in interests {
                    let cap = self.get_read_cap(&cap_selector)?;
                    if let Some(cap) = cap {
                        let entry = out.entry(cap.clone()).or_default();
                        match aoi_selector {
                            AreaOfInterestSelector::Widest => {
                                let area = cap.read_cap().granted_area();
                                let aoi = AreaOfInterest::new(area);
                                entry.insert(aoi);
                            }
                            AreaOfInterestSelector::Exact(aois) => {
                                for aoi in aois {
                                    entry.insert(aoi);
                                }
                            }
                        }
                    }
                }
                Ok(out)
            }
            Interests::Exact(interests) => Ok(interests),
        }
    }

    pub fn create_full_caps(
        &self,
        namespace_id: NamespaceId,
        user_id: UserId,
    ) -> Result<[CapabilityPack; 2], AuthError> {
        let namespace_key = namespace_id
            .into_public_key()
            .map_err(|_| AuthError::InvalidNamespaceId(namespace_id))?;
        let user_key: UserPublicKey = user_id
            .into_public_key()
            .map_err(|_| AuthError::InvalidUserId(user_id))?;
        let read_cap = self.create_read_cap(namespace_key, user_key)?;
        let write_cap = self.create_write_cap(namespace_key, user_key)?;
        let pack = [read_cap, write_cap];
        self.insert_caps_unchecked(pack.clone())?;
        Ok(pack)
    }

    pub fn create_read_cap(
        &self,
        namespace_key: NamespacePublicKey,
        user_key: UserPublicKey,
    ) -> Result<CapabilityPack, AuthError> {
        let namespace_id = namespace_key.id();
        let cap = match namespace_key.kind() {
            NamespaceKind::Owned => {
                let namespace_secret = self
                    .secrets
                    .get_namespace(&namespace_id)
                    .ok_or(AuthError::MissingNamespaceSecret(namespace_id))?;
                McCapability::new_owned(&namespace_secret, user_key, AccessMode::ReadOnly)
            }
            NamespaceKind::Communal => {
                McCapability::new_communal(namespace_key, user_key, AccessMode::ReadOnly)
            }
        };
        // TODO: Subspace capability.
        let pack = CapabilityPack::Read(ReadAuthorisation::new(cap, None));
        Ok(pack)
    }

    pub fn create_write_cap(
        &self,
        namespace_key: NamespacePublicKey,
        user_key: UserPublicKey,
    ) -> Result<CapabilityPack, AuthError> {
        let namespace_id = namespace_key.id();
        let cap = match namespace_key.kind() {
            NamespaceKind::Owned => {
                let namespace_secret = self
                    .secrets
                    .get_namespace(&namespace_id)
                    .ok_or(AuthError::MissingNamespaceSecret(namespace_id))?;
                McCapability::new_owned(&namespace_secret, user_key, AccessMode::ReadWrite)
            }
            NamespaceKind::Communal => {
                McCapability::new_communal(namespace_key, user_key, AccessMode::ReadWrite)
            }
        };
        let pack = CapabilityPack::Write(cap);
        Ok(pack)
    }

    pub fn delegate_full_caps(
        &self,
        from: CapSelector,
        access_mode: AccessMode,
        to: DelegateTo,
        store: bool,
    ) -> Result<Vec<CapabilityPack>, AuthError> {
        let mut out = Vec::with_capacity(2);
        let user_key: UserPublicKey = to
            .user
            .into_public_key()
            .map_err(|_| AuthError::InvalidUserId(to.user))?;
        let restrict_area = to.restrict_area;
        let read_cap = self.delegate_read_cap(&from, user_key, restrict_area.clone())?;
        out.push(read_cap);
        if access_mode == AccessMode::ReadWrite {
            let write_cap = self.delegate_write_cap(&from, user_key, restrict_area)?;
            out.push(write_cap);
        }
        if store {
            self.insert_caps_unchecked(out.clone())?;
        }
        Ok(out)
    }

    pub fn delegate_read_cap(
        &self,
        from: &CapSelector,
        to: UserPublicKey,
        restrict_area: RestrictArea,
    ) -> Result<CapabilityPack, AuthError> {
        let auth = self.get_read_cap(from)?.ok_or(AuthError::NoCapability)?;
        let read_cap = auth.read_cap();
        let _subspace_cap = auth.subspace_cap();
        let user_id = read_cap.receiver().id();
        let user_secret = self
            .secrets
            .get_user(&user_id)
            .ok_or(AuthError::MissingUserSecret(user_id))?;
        let area = restrict_area.with_default(read_cap.granted_area());
        let new_read_cap = read_cap.delegate(&user_secret, to, area)?;
        // TODO: Subspace capability
        let new_subspace_cap = None;
        let pack = CapabilityPack::Read(ReadAuthorisation::new(new_read_cap, new_subspace_cap));
        Ok(pack)
    }

    pub fn delegate_write_cap(
        &self,
        from: &CapSelector,
        to: UserPublicKey,
        restrict_area: RestrictArea,
    ) -> Result<CapabilityPack, AuthError> {
        let cap = self.get_write_cap(from)?.ok_or(AuthError::NoCapability)?;
        let user_secret = self
            .secrets
            .get_user(&cap.receiver().id())
            .ok_or(AuthError::MissingUserSecret(cap.receiver().id()))?;
        let area = restrict_area.with_default(cap.granted_area());
        let new_cap = cap.delegate(&user_secret, to, area)?;
        Ok(CapabilityPack::Write(new_cap))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("invalid user id: {}", .0.fmt_short())]
    InvalidUserId(UserId),
    #[error("invalid namespace id: {}", .0.fmt_short())]
    InvalidNamespaceId(NamespaceId),
    #[error("missing user secret: {}", .0.fmt_short())]
    MissingUserSecret(UserId),
    #[error("missing namespace secret: {}", .0.fmt_short())]
    MissingNamespaceSecret(NamespaceId),
    #[error("secret store error: {0}")]
    SecretStore(#[from] SecretStoreError),
    #[error("no capability found")]
    NoCapability,
    // TODO: remove
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
