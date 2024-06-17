use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use anyhow::Result;

use crate::{
    proto::{
        grouping::Area,
        keys::{NamespaceId, NamespaceKind, UserId, UserPublicKey},
        meadowcap::{AccessMode, McCapability},
        sync::ReadAuthorisation,
        willow::{Entry, Path, SubspaceId, Timestamp, WriteCapability},
    },
    store::traits::{SecretStorage, SecretStoreError},
};

#[derive(Debug)]
pub struct CapSelector {
    user_id: UserId,
    namespace_id: NamespaceId,
    granted_area: AreaSelector,
}

#[derive(Debug)]
pub enum AreaSelector {
    Area(Area),
    Point {
        subspace_id: SubspaceId,
        path: Path,
        timestamp: Timestamp,
    },
}

impl AreaSelector {
    pub fn included_in(&self, other: &Area) -> bool {
        match self {
            AreaSelector::Area(area) => other.includes_area(area),
            AreaSelector::Point {
                subspace_id,
                path,
                timestamp,
            } => other.includes_point(subspace_id, path, timestamp),
        }
    }
}

impl CapSelector {
    pub fn for_entry(entry: &Entry, user_id: UserId) -> Self {
        let granted_area = AreaSelector::Point {
            path: entry.path.clone(),
            timestamp: entry.timestamp,
            subspace_id: entry.subspace_id,
        };
        Self {
            namespace_id: entry.namespace_id,
            user_id,
            granted_area,
        }
    }
}

#[derive(Debug)]
pub enum CapabilityPack {
    Read(ReadAuthorisation),
    Write(WriteCapability),
}

// #[derive(Debug)]
// pub enum CapabilityRoot {
//     Owned(NamespaceSecretKey),
//     Communal(NamespacePublicKey),
// }
//
// impl CapabilityRoot {
//     pub fn kind(&self) -> NamespaceKind {
//         match self {
//             CapabilityRoot::Owned(_) => NamespaceKind::Owned,
//             CapabilityRoot::Communal(_) => NamespaceKind::Communal,
//         }
//     }
//     fn for_namespace<S: SecretStorage>(
//         namespace: NamespacePublicKey,
//         secrets: S,
//     ) -> Result<Self, AuthError> {
//         match namespace.kind() {
//             NamespaceKind::Communal => Ok(CapabilityRoot::Communal(namespace)),
//             NamespaceKind::Owned => {
//                 let secret = secrets
//                     .get_namespace(&namespace.id())
//                     .ok_or(AuthError::MissingNamespaceSecret)?;
//                 Ok(CapabilityRoot::Owned(secret))
//             }
//         }
//     }
// }

#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash)]
pub struct CapabilityHash(iroh_base::hash::Hash);

#[derive(Debug, Default, Clone)]
pub struct AuthStore {
    inner: Arc<RwLock<Inner>>,
}
impl AuthStore {
    pub fn get_write(&self, selector: CapSelector) -> Result<Option<WriteCapability>, AuthError> {
        Ok(self.inner.read().unwrap().get_write_authorisation(selector))
    }

    pub fn get_read(&self, selector: CapSelector) -> Result<Option<ReadAuthorisation>, AuthError> {
        Ok(self.inner.read().unwrap().get_read_authorisation(selector))
    }

    pub fn insert(&self, cap: CapabilityPack) {
        self.inner.write().unwrap().insert_capability(cap);
    }

    pub fn mint<S: SecretStorage>(
        &self,
        secrets: &S,
        namespace_id: NamespaceId,
        user_id: UserId,
        access_mode: AccessMode,
    ) -> Result<(), AuthError> {
        let namespace_key = namespace_id
            .into_public_key()
            .map_err(|_| AuthError::InvalidNamespaceId)?;
        let user_key: UserPublicKey = user_id
            .into_public_key()
            .map_err(|_| AuthError::InvalidUserId)?;
        let cap = match namespace_key.kind() {
            NamespaceKind::Owned => {
                let namespace_secret = secrets
                    .get_namespace(&namespace_id)
                    .ok_or(AuthError::MissingNamespaceSecret)?;
                McCapability::new_owned(namespace_secret, user_key, access_mode)
            }
            NamespaceKind::Communal => {
                McCapability::new_communal(namespace_key, user_key, access_mode)
            }
        };
        let pack = match access_mode {
            AccessMode::Read => CapabilityPack::Read(ReadAuthorisation::new(cap, None)),
            AccessMode::Write => CapabilityPack::Write(cap),
        };
        self.insert(pack);
        Ok(())
    }

    pub fn delegate<S: SecretStorage>(
        &self,
        secrets: &S,
        namespace_id: NamespaceId,
        prev_user: UserId,
        access_mode: AccessMode,
        new_user: UserId,
        new_area: Area,
    ) -> Result<CapabilityPack, AuthError> {
        let new_user_key = new_user
            .into_public_key()
            .map_err(|_| AuthError::InvalidUserId)?;
        let selector = CapSelector {
            user_id: prev_user,
            namespace_id,
            granted_area: AreaSelector::Area(new_area.clone()),
        };
        let pack = match access_mode {
            AccessMode::Write => {
                let cap = self
                    .get_write(selector)?
                    .ok_or(AuthError::NoCapabilityFound)?;
                let user_secret = secrets
                    .get_user(&cap.receiver().id())
                    .ok_or(AuthError::MissingUserSecret)?;
                let new_cap = cap.delegate(&user_secret, new_user_key, new_area)?;
                CapabilityPack::Write(new_cap)
            }
            AccessMode::Read => {
                let auth = self
                    .get_read(selector)?
                    .ok_or(AuthError::NoCapabilityFound)?;
                let ReadAuthorisation(read_cap, _subspace_cap) = auth;
                let user_secret = secrets
                    .get_user(&read_cap.receiver().id())
                    .ok_or(AuthError::MissingUserSecret)?;
                let new_read_cap = read_cap.delegate(&user_secret, new_user_key, new_area)?;
                // TODO: Subspace capability
                CapabilityPack::Read(ReadAuthorisation::new(new_read_cap, None))
            }
        };
        Ok(pack)
    }
}
#[derive(Debug, Default)]
pub struct Inner {
    write_caps: HashMap<NamespaceId, Vec<WriteCapability>>,
    read_caps: HashMap<NamespaceId, Vec<ReadAuthorisation>>,
}

impl Inner {
    fn get_write_authorisation(&self, selector: CapSelector) -> Option<WriteCapability> {
        let candidates = self
            .write_caps
            .get(&selector.namespace_id)
            .into_iter()
            .flatten()
            .filter(|cap| {
                cap.receiver().id() == selector.user_id
                    && selector.granted_area.included_in(&cap.granted_area())
            });

        // Select the best candidate, by sorting for
        // * smallest number of delegations
        // * widest area
        let best = candidates.reduce(|prev, next| match next.is_wider_than(prev) {
            true => next,
            false => prev,
        });
        best.cloned()
    }

    fn get_read_authorisation(&self, selector: CapSelector) -> Option<ReadAuthorisation> {
        let candidates = self
            .read_caps
            .get(&selector.namespace_id)
            .into_iter()
            .flatten()
            .filter(|auth| {
                let cap = &auth.0;
                cap.receiver().id() == selector.user_id
                    && selector.granted_area.included_in(&cap.granted_area())
            });

        // Select the best candidate, by sorting for
        // * smallest number of delegations
        // * widest area
        let best = candidates.reduce(|prev, next| match next.0.is_wider_than(&prev.0) {
            true => next,
            false => prev,
        });
        best.cloned()
    }

    fn insert_capability(&mut self, cap: CapabilityPack) {
        match cap {
            CapabilityPack::Read(_) => todo!(),
            CapabilityPack::Write(_) => todo!(),
        }
    }
}

// fn mint_capability(
//     namespace_secret: &NamespaceSecretKey,
//     user_public_key: UserPublicKey,
// ) -> (ReadCapability, WriteCapability) {
//     let read_capability = McCapability::Owned(OwnedCapability::new(
//         namespace_secret,
//         user_public_key,
//         AccessMode::Read,
//     ));
//     let write_capability = McCapability::Owned(OwnedCapability::new(
//         namespace_secret,
//         user_public_key,
//         AccessMode::Write,
//     ));
//     (read_capability, write_capability)
// }

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("invalid user id")]
    InvalidUserId,
    #[error("invalid namespace id")]
    InvalidNamespaceId,
    #[error("missing user secret")]
    MissingUserSecret,
    #[error("missing namespace secret")]
    MissingNamespaceSecret,
    #[error("wrong root token for namespace kind")]
    WrongRootToken,
    #[error("secret store error: {0}")]
    SecretStore(#[from] SecretStoreError),
    #[error("no capability found")]
    NoCapabilityFound,
    // TODO: remove
    #[error("other: {0}")]
    Other(#[from] anyhow::Error),
}
