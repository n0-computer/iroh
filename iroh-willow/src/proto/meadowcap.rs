//! The capability system of Willow.
//!
//! Contains an instantiation of [`meadowcap`] for use in iroh-willow.

use serde::{Deserialize, Serialize};
use willow_data_model::AuthorisationToken;

use super::{
    grouping::Area,
    keys::{self, NamespaceSecretKey, UserSecretKey},
};

pub type UserPublicKey = keys::UserPublicKey;
pub type NamespacePublicKey = keys::NamespacePublicKey;
pub type UserId = keys::UserId;
pub type NamespaceId = keys::NamespaceId;
pub type UserSignature = keys::UserSignature;
pub type NamespaceSignature = keys::NamespaceSignature;

use super::data_model::{Entry, MAX_COMPONENT_COUNT, MAX_COMPONENT_LENGTH, MAX_PATH_LENGTH};

pub use meadowcap::{AccessMode, IsCommunal};

#[derive(Debug, derive_more::From, Serialize, Deserialize)]
pub enum SecretKey {
    User(keys::UserSecretKey),
    Namespace(keys::NamespaceSecretKey),
}

pub type McCapability = meadowcap::McCapability<
    MAX_COMPONENT_LENGTH,
    MAX_COMPONENT_COUNT,
    MAX_PATH_LENGTH,
    keys::NamespaceId,
    keys::NamespaceSignature,
    keys::UserId,
    keys::UserSignature,
>;

pub type McSubspaceCapability = meadowcap::McSubspaceCapability<
    keys::NamespaceId,
    keys::NamespaceSignature,
    keys::UserId,
    keys::UserSignature,
>;

pub type SubspaceCapability = McSubspaceCapability;
pub type ReadCapability = McCapability;
pub type WriteCapability = McCapability;

pub type McAuthorisationToken = meadowcap::McAuthorisationToken<
    MAX_COMPONENT_LENGTH,
    MAX_COMPONENT_COUNT,
    MAX_PATH_LENGTH,
    keys::NamespaceId,
    keys::NamespaceSignature,
    keys::UserId,
    keys::UserSignature,
>;

pub fn is_authorised_write(entry: &Entry, token: &McAuthorisationToken) -> bool {
    token.is_authorised_write(entry)
}

pub type FailedDelegationError = meadowcap::FailedDelegationError<
    MAX_COMPONENT_LENGTH,
    MAX_COMPONENT_COUNT,
    MAX_PATH_LENGTH,
    keys::UserId,
>;

/// Represents an authorisation to read an area of data in a Namespace.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ReadAuthorisation(McCapability, Option<McSubspaceCapability>);

impl ReadAuthorisation {
    pub fn new(read_cap: McCapability, subspace_cap: Option<McSubspaceCapability>) -> Self {
        Self(read_cap, subspace_cap)
    }

    pub fn new_owned(
        namespace_secret: &NamespaceSecretKey,
        user_key: UserId,
    ) -> anyhow::Result<Self> {
        let read_cap = McCapability::new_owned(
            namespace_secret.public_key().id(),
            namespace_secret,
            user_key,
            AccessMode::Read,
        )?;
        let subspace_cap = meadowcap::McSubspaceCapability::new(
            namespace_secret.public_key().id(),
            namespace_secret,
            user_key,
        )?;
        Ok(Self::new(read_cap, Some(subspace_cap)))
    }

    pub fn read_cap(&self) -> &McCapability {
        &self.0
    }

    pub fn subspace_cap(&self) -> Option<&McSubspaceCapability> {
        self.1.as_ref()
    }

    pub fn namespace(&self) -> NamespaceId {
        *self.0.granted_namespace()
    }

    pub fn delegate(
        &self,
        user_secret: &UserSecretKey,
        new_user: UserId,
        new_area: Area,
    ) -> anyhow::Result<Self> {
        let subspace_cap = match self.subspace_cap() {
            Some(subspace_cap) if new_area.subspace().is_any() && !new_area.path().is_empty() => {
                Some(subspace_cap.delegate(user_secret, &new_user)?)
            }
            _ => None,
        };
        let read_cap = self
            .read_cap()
            .delegate(user_secret, &new_user, &new_area)?;
        Ok(Self::new(read_cap, subspace_cap))
    }
}

/// Returns `true` if `self` covers a larger area than `other`,
/// or if covers the same area and has less delegations.
pub fn is_wider_than(a: &McCapability, b: &McCapability) -> bool {
    (a.granted_area().includes_area(&b.granted_area()))
        || (a.granted_area() == b.granted_area() && a.delegations().len() < b.delegations().len())
}

pub mod serde_encoding {
    use serde::{de, Deserialize, Deserializer};

    use crate::{
        proto::grouping::Area,
        util::codec2::{from_bytes, from_bytes_relative, to_vec, to_vec_relative},
    };

    use super::*;

    pub mod read_authorisation {
        use super::*;
        pub fn serialize<S: serde::Serializer>(
            value: &ReadAuthorisation,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let encoded_cap = to_vec_relative(&Area::new_full(), value.read_cap());
            let encoded_subspace_cap = value.subspace_cap().map(to_vec);
            (encoded_cap, encoded_subspace_cap).serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<ReadAuthorisation, D::Error>
        where
            D: Deserializer<'de>,
        {
            let (read_cap, subspace_cap): (SerdeMcCapability, Option<SerdeMcSubspaceCapability>) =
                Deserialize::deserialize(deserializer)?;
            Ok(ReadAuthorisation(
                read_cap.into(),
                subspace_cap.map(Into::into),
            ))
        }
    }

    #[derive(
        Debug,
        Clone,
        Eq,
        PartialEq,
        Hash,
        derive_more::From,
        derive_more::Into,
        derive_more::Deref,
        Serialize,
        Deserialize,
    )]
    pub struct SerdeReadAuthorisation(#[serde(with = "read_authorisation")] pub ReadAuthorisation);

    pub mod mc_capability {
        use super::*;
        pub fn serialize<S: serde::Serializer>(
            value: &McCapability,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let previous = Area::new_full();
            to_vec_relative(&previous, value).serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<McCapability, D::Error>
        where
            D: Deserializer<'de>,
        {
            let previous = Area::new_full();
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
        Hash,
        derive_more::From,
        derive_more::Into,
        derive_more::Deref,
        Serialize,
        Deserialize,
    )]
    pub struct SerdeMcCapability(#[serde(with = "mc_capability")] pub McCapability);

    pub mod mc_subspace_capability {
        use super::*;
        pub fn serialize<S: serde::Serializer>(
            value: &McSubspaceCapability,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            to_vec(value).serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<McSubspaceCapability, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            let decoded = from_bytes(&bytes).map_err(de::Error::custom)?;
            Ok(decoded)
        }
    }

    #[derive(
        Debug,
        Clone,
        derive_more::From,
        derive_more::Into,
        derive_more::Deref,
        Serialize,
        Deserialize,
    )]
    pub struct SerdeMcSubspaceCapability(
        #[serde(with = "mc_subspace_capability")] pub McSubspaceCapability,
    );

    pub mod access_mode {
        use super::*;
        pub fn serialize<S: serde::Serializer>(
            value: &AccessMode,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match value {
                AccessMode::Read => 0u8.serialize(serializer),
                AccessMode::Write => 1u8.serialize(serializer),
            }
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<AccessMode, D::Error>
        where
            D: Deserializer<'de>,
        {
            let value: u8 = Deserialize::deserialize(deserializer)?;
            match value {
                0 => Ok(AccessMode::Read),
                1 => Ok(AccessMode::Write),
                _ => Err(de::Error::custom("Invalid access mode")),
            }
        }
    }
}
