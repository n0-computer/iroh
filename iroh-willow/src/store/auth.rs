use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, RwLock},
};

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
    session::Interests,
    store::traits::{SecretStorage, SecretStoreError},
};

#[derive(Debug, Clone)]
pub struct DelegateTo {
    pub user: UserId,
    pub restrict_area: Option<Area>,
}

impl DelegateTo {
    pub fn new(user: UserId, restrict_area: Option<Area>) -> Self {
        Self {
            user,
            restrict_area,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CapSelector {
    pub namespace_id: NamespaceId,
    pub user: UserSelector,
    pub area: AreaSelector,
}

impl CapSelector {
    pub fn matches(&self, cap: &McCapability) -> bool {
        self.namespace_id == cap.granted_namespace().id()
            && self.user.includes(&cap.receiver().id())
            && self.area.is_included_in(&cap.granted_area())
    }

    pub fn widest(namespace_id: NamespaceId) -> Self {
        Self {
            namespace_id,
            user: UserSelector::Any,
            area: AreaSelector::Widest,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, derive_more::From, Serialize, Deserialize)]
pub enum UserSelector {
    #[default]
    Any,
    Exact(UserId),
}

impl UserSelector {
    fn includes(&self, user: &UserId) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(u) => u == user,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub enum AreaSelector {
    #[default]
    Widest,
    Area(Area),
    Point(Point),
}

impl AreaSelector {
    pub fn is_included_in(&self, other: &Area) -> bool {
        match self {
            AreaSelector::Widest => true,
            AreaSelector::Area(area) => other.includes_area(area),
            AreaSelector::Point(point) => other.includes_point(point),
        }
    }
}

impl CapSelector {
    pub fn for_entry(entry: &Entry, user_id: UserSelector) -> Self {
        let granted_area = AreaSelector::Point(Point::from_entry(entry));
        Self {
            namespace_id: entry.namespace_id,
            user: user_id,
            area: granted_area,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CapabilityPack {
    Read(ReadAuthorisation),
    Write(WriteCapability),
}

impl CapabilityPack {
    pub fn receiver(&self) -> UserId {
        match self {
            CapabilityPack::Read(auth) => auth.read_cap().receiver().id(),
            CapabilityPack::Write(cap) => cap.receiver().id(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash)]
pub struct CapabilityHash(iroh_base::hash::Hash);

#[derive(Debug, Default, Clone)]
pub struct AuthStore {
    inner: Arc<RwLock<Inner>>,
}
impl AuthStore {
    pub fn get_write_cap(
        &self,
        selector: &CapSelector,
    ) -> Result<Option<WriteCapability>, AuthError> {
        Ok(self.inner.read().unwrap().get_write_cap(selector))
    }

    pub fn get_read_cap(
        &self,
        selector: &CapSelector,
    ) -> Result<Option<ReadAuthorisation>, AuthError> {
        let cap = self.inner.read().unwrap().get_read_cap(selector);
        debug!(?selector, ?cap, "get read cap");
        Ok(cap)
    }

    pub fn list_read_caps(&self) -> impl Iterator<Item = ReadAuthorisation> {
        self.inner
            .read()
            .unwrap()
            .read_caps
            .values()
            .flatten()
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
    }

    pub fn insert_caps(&self, caps: impl IntoIterator<Item = CapabilityPack>) {
        let mut inner = self.inner.write().unwrap();
        for cap in caps.into_iter() {
            debug!(?cap, "insert cap");
            inner.insert_caps(cap);
        }
    }

    pub fn resolve_interests(
        &self,
        interests: Interests,
    ) -> Result<HashMap<ReadAuthorisation, BTreeSet<AreaOfInterest>>, AuthError> {
        match interests {
            Interests::All => {
                let out = self
                    .list_read_caps()
                    .map(|auth| {
                        let area = auth.read_cap().granted_area();
                        let aoi = AreaOfInterest::new(area);
                        (auth, BTreeSet::from_iter([aoi]))
                    })
                    .collect::<HashMap<_, _>>();
                Ok(out)
            }
            Interests::Explicit(interests) => Ok(interests),
            Interests::Some(interests) => {
                let mut out: HashMap<ReadAuthorisation, BTreeSet<AreaOfInterest>> = HashMap::new();
                for (namespace_id, aois) in interests {
                    for aoi in aois {
                        let selector = CapSelector {
                            namespace_id,
                            user: UserSelector::Any,
                            area: AreaSelector::Area(aoi.area.clone()),
                        };
                        let cap = self.get_read_cap(&selector)?;
                        if let Some(cap) = cap {
                            let set = out.entry(cap).or_default();
                            set.insert(aoi);
                        }
                    }
                }
                Ok(out)
            }
        }
    }

    pub fn create_full_caps<S: SecretStorage>(
        &self,
        secrets: &S,
        namespace_id: NamespaceId,
        user_id: UserId,
    ) -> Result<[CapabilityPack; 2], AuthError> {
        let namespace_key = namespace_id
            .into_public_key()
            .map_err(|_| AuthError::InvalidNamespaceId(namespace_id))?;
        let user_key: UserPublicKey = user_id
            .into_public_key()
            .map_err(|_| AuthError::InvalidUserId(user_id))?;
        let read_cap = self.create_read_cap(secrets, namespace_key, user_key)?;
        let write_cap = self.create_write_cap(secrets, namespace_key, user_key)?;
        let pack = [read_cap, write_cap];
        self.insert_caps(pack.clone());
        Ok(pack)
    }

    pub fn create_read_cap<S: SecretStorage>(
        &self,
        secrets: &S,
        namespace_key: NamespacePublicKey,
        user_key: UserPublicKey,
    ) -> Result<CapabilityPack, AuthError> {
        let namespace_id = namespace_key.id();
        let cap = match namespace_key.kind() {
            NamespaceKind::Owned => {
                let namespace_secret = secrets
                    .get_namespace(&namespace_id)
                    .ok_or(AuthError::MissingNamespaceSecret(namespace_id))?;
                McCapability::new_owned(namespace_secret, user_key, AccessMode::Read)
            }
            NamespaceKind::Communal => {
                McCapability::new_communal(namespace_key, user_key, AccessMode::Read)
            }
        };
        // TODO: Subspace capability.
        let pack = CapabilityPack::Read(ReadAuthorisation::new(cap, None));
        Ok(pack)
    }

    pub fn create_write_cap<S: SecretStorage>(
        &self,
        secrets: &S,
        namespace_key: NamespacePublicKey,
        user_key: UserPublicKey,
    ) -> Result<CapabilityPack, AuthError> {
        let namespace_id = namespace_key.id();
        let cap = match namespace_key.kind() {
            NamespaceKind::Owned => {
                let namespace_secret = secrets
                    .get_namespace(&namespace_id)
                    .ok_or(AuthError::MissingNamespaceSecret(namespace_id))?;
                McCapability::new_owned(namespace_secret, user_key, AccessMode::Write)
            }
            NamespaceKind::Communal => {
                McCapability::new_communal(namespace_key, user_key, AccessMode::Write)
            }
        };
        let pack = CapabilityPack::Write(cap);
        Ok(pack)
    }

    pub fn delegate_full_caps<S: SecretStorage>(
        &self,
        secrets: &S,
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
        let read_cap = self.delegate_read_cap(secrets, &from, user_key, restrict_area.clone())?;
        out.push(read_cap);
        if access_mode == AccessMode::Write {
            let write_cap = self.delegate_write_cap(secrets, &from, user_key, restrict_area)?;
            out.push(write_cap);
        }
        if store {
            self.insert_caps(out.clone());
        }
        Ok(out)
    }

    pub fn delegate_read_cap<S: SecretStorage>(
        &self,
        secrets: &S,
        from: &CapSelector,
        to: UserPublicKey,
        restrict_area: Option<Area>,
    ) -> Result<CapabilityPack, AuthError> {
        let auth = self.get_read_cap(from)?.ok_or(AuthError::NoCapability)?;
        let ReadAuthorisation(read_cap, _subspace_cap) = auth;
        let user_id = read_cap.receiver().id();
        let user_secret = secrets
            .get_user(&user_id)
            .ok_or(AuthError::MissingUserSecret(user_id))?;
        let area = restrict_area.unwrap_or(read_cap.granted_area());
        let new_read_cap = read_cap.delegate(&user_secret, to, area)?;
        // TODO: Subspace capability
        let new_subspace_cap = None;
        let pack = CapabilityPack::Read(ReadAuthorisation::new(new_read_cap, new_subspace_cap));
        Ok(pack)
    }

    pub fn delegate_write_cap<S: SecretStorage>(
        &self,
        secrets: &S,
        from: &CapSelector,
        to: UserPublicKey,
        restrict_area: Option<Area>,
    ) -> Result<CapabilityPack, AuthError> {
        let cap = self.get_write_cap(from)?.ok_or(AuthError::NoCapability)?;
        let user_secret = secrets
            .get_user(&cap.receiver().id())
            .ok_or(AuthError::MissingUserSecret(cap.receiver().id()))?;
        let area = restrict_area.unwrap_or(cap.granted_area());
        let new_cap = cap.delegate(&user_secret, to, area)?;
        Ok(CapabilityPack::Write(new_cap))
    }
}

#[derive(Debug, Default)]
pub struct Inner {
    write_caps: HashMap<NamespaceId, Vec<WriteCapability>>,
    read_caps: HashMap<NamespaceId, Vec<ReadAuthorisation>>,
}

impl Inner {
    fn get_write_cap(&self, selector: &CapSelector) -> Option<WriteCapability> {
        let candidates = self
            .write_caps
            .get(&selector.namespace_id)
            .into_iter()
            .flatten()
            .filter(|cap| selector.matches(cap));

        // Select the best candidate, by sorting for
        // * first: widest area
        // * then: smallest number of delegations
        let best = candidates.reduce(
            |prev, next| {
                if next.is_wider_than(prev) {
                    next
                } else {
                    prev
                }
            },
        );
        best.cloned()
    }

    fn get_read_cap(&self, selector: &CapSelector) -> Option<ReadAuthorisation> {
        let candidates = self
            .read_caps
            .get(&selector.namespace_id)
            .into_iter()
            .flatten()
            .filter(|auth| selector.matches(auth.read_cap()));

        // Select the best candidate, by sorting for
        // * smallest number of delegations
        // * widest area
        let best = candidates.reduce(|prev, next| {
            if next.read_cap().is_wider_than(prev.read_cap()) {
                next
            } else {
                prev
            }
        });
        best.cloned()
    }

    fn insert_caps(&mut self, cap: CapabilityPack) {
        match cap {
            CapabilityPack::Read(cap) => {
                self.read_caps
                    .entry(cap.read_cap().granted_namespace().id())
                    .or_default()
                    .push(cap);
            }
            CapabilityPack::Write(cap) => {
                self.write_caps
                    .entry(cap.granted_namespace().id())
                    .or_default()
                    .push(cap);
            }
        }
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
