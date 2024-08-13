//! Authentication backend for Willow.
//!
//! Manages capabilities.

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use ed25519_dalek::SignatureError;
use meadowcap::{IsCommunal, NamespaceIsNotCommunalError, OwnedCapabilityCreationError};
use tracing::debug;

use crate::{
    interest::{
        AreaOfInterestSelector, CapSelector, CapabilityPack, DelegateTo, InterestMap, Interests,
        InvalidCapabilityPack, RestrictArea,
    },
    proto::{
        data_model::WriteCapability,
        grouping::AreaOfInterest,
        keys::{NamespaceId, UserId},
        meadowcap::{AccessMode, FailedDelegationError, McCapability, ReadAuthorisation},
    },
    store::traits::{CapsStorage, SecretStorage, SecretStoreError, Storage},
};

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
            tracing::debug!("import cap {cap:?}");
            cap.validate()?;
            // Only allow importing caps we can use.
            // TODO: Is this what we want?
            let user_id = cap.receiver();
            if !self.secrets.has_user(&user_id) {
                return Err(AuthError::MissingUserSecret(user_id));
            }
            self.caps.insert(cap)?;
            tracing::debug!("imported");
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
                        let aoi = AreaOfInterest::new(area, 0, 0);
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
                                let aoi = AreaOfInterest::new(area, 0, 0);
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
        // let namespace_key = namespace_id
        //     .into_public_key()
        //     .map_err(|_| AuthError::InvalidNamespaceId(namespace_id))?;
        // let user_key: UserPublicKey = user_id
        //     .into_public_key()
        //     .map_err(|_| AuthError::InvalidUserId(user_id))?;
        let read_cap = self.create_read_cap(namespace_id, user_id)?;
        let write_cap = self.create_write_cap(namespace_id, user_id)?;
        let pack = [read_cap, write_cap];
        self.insert_caps_unchecked(pack.clone())?;
        Ok(pack)
    }

    pub fn create_read_cap(
        &self,
        namespace_key: NamespaceId,
        user_key: UserId,
    ) -> Result<CapabilityPack, AuthError> {
        let cap = if namespace_key.is_communal() {
            McCapability::new_communal(namespace_key, user_key, AccessMode::Read)?
        } else {
            let namespace_secret = self
                .secrets
                .get_namespace(&namespace_key)
                .ok_or(AuthError::MissingNamespaceSecret(namespace_key))?;
            McCapability::new_owned(namespace_key, &namespace_secret, user_key, AccessMode::Read)?
        };
        // TODO: Subspace capability.
        let pack = CapabilityPack::Read(ReadAuthorisation::new(cap, None).into());
        Ok(pack)
    }

    pub fn create_write_cap(
        &self,
        namespace_key: NamespaceId,
        user_key: UserId,
    ) -> Result<CapabilityPack, AuthError> {
        let cap = if namespace_key.is_communal() {
            McCapability::new_communal(namespace_key, user_key, AccessMode::Write)?
        } else {
            let namespace_secret = self
                .secrets
                .get_namespace(&namespace_key)
                .ok_or(AuthError::MissingNamespaceSecret(namespace_key))?;
            McCapability::new_owned(
                namespace_key,
                &namespace_secret,
                user_key,
                AccessMode::Write,
            )?
        };
        let pack = CapabilityPack::Write(cap.into());
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
        // let user_key: UserPublicKey = to
        //     .user
        //     .into_public_key()
        //     .map_err(|_| AuthError::InvalidUserId(to.user))?;
        let restrict_area = to.restrict_area;
        let read_cap = self.delegate_read_cap(&from, to.user, restrict_area.clone())?;
        out.push(read_cap);
        if access_mode == AccessMode::Write {
            let write_cap = self.delegate_write_cap(&from, to.user, restrict_area)?;
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
        to: UserId,
        restrict_area: RestrictArea,
    ) -> Result<CapabilityPack, AuthError> {
        let auth = self.get_read_cap(from)?.ok_or(AuthError::NoCapability)?;
        let read_cap = auth.read_cap();
        let subspace_cap = auth.subspace_cap();
        let user_id = read_cap.receiver();
        let user_secret = self
            .secrets
            .get_user(user_id)
            .ok_or(AuthError::MissingUserSecret(*user_id))?;
        let area = restrict_area.with_default(read_cap.granted_area());
        let new_read_cap = read_cap.delegate(&user_secret, &to, &area)?;

        let new_subspace_cap = if let Some(subspace_cap) = subspace_cap {
            if area.subspace().is_any() {
                Some(
                    subspace_cap
                        .delegate(&user_secret, &to)
                        .map_err(AuthError::SubspaceCapDelegationFailed)?,
                )
            } else {
                None
            }
        } else {
            None
        };
        let pack =
            CapabilityPack::Read(ReadAuthorisation::new(new_read_cap, new_subspace_cap).into());
        Ok(pack)
    }

    pub fn delegate_write_cap(
        &self,
        from: &CapSelector,
        to: UserId,
        restrict_area: RestrictArea,
    ) -> Result<CapabilityPack, AuthError> {
        let cap = self.get_write_cap(from)?.ok_or(AuthError::NoCapability)?;
        let user_secret = self
            .secrets
            .get_user(cap.receiver())
            .ok_or(AuthError::MissingUserSecret(*cap.receiver()))?;
        let area = restrict_area.with_default(cap.granted_area());
        let new_cap = cap.delegate(&user_secret, &to, &area)?;
        Ok(CapabilityPack::Write(new_cap.into()))
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
    #[error("Invalid capability pack")]
    InvalidPack(#[from] InvalidCapabilityPack),

    #[error("Failed to create owned capability: {0}")]
    CreateOwnedCap(#[from] OwnedCapabilityCreationError<NamespaceId>),
    #[error("Failed to create communal capability: {0}")]
    CreateCommunalCap(#[from] NamespaceIsNotCommunalError<NamespaceId>),

    #[error("Failed to delegate capability: {0}")]
    DelegationFailed(#[from] FailedDelegationError),
    #[error("Failed to delegate suubspace capability: {0}")]
    SubspaceCapDelegationFailed(SignatureError),
}
