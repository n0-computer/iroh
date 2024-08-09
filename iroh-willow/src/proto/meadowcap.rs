use std::{io::Write, sync::Arc};

use serde::{Deserialize, Serialize};

use crate::{proto::grouping::NotIncluded, util::codec::Encoder};

use super::{
    grouping::{Area, AreaInArea},
    keys::{self, NamespaceSecretKey, UserSecretKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH},
    willow::{AuthorisedEntry, Entry, Unauthorised},
};

pub type UserPublicKey = keys::UserPublicKey;
pub type NamespacePublicKey = keys::NamespacePublicKey;
pub type UserId = keys::UserId;
pub type NamespaceId = keys::NamespaceId;
pub type UserSignature = keys::UserSignature;
pub type NamespaceSignature = keys::NamespaceSignature;

#[derive(Debug, derive_more::From)]
pub enum SecretKey {
    User(UserSecretKey),
    Namespace(NamespaceSecretKey),
}

pub fn is_authorised_write(entry: &Entry, token: &MeadowcapAuthorisationToken) -> bool {
    let (capability, signature) = token.as_parts();

    capability.is_valid()
        && capability.access_mode() == AccessMode::ReadWrite
        && capability.granted_area().includes_entry(entry)
        && capability
            .receiver()
            // TODO: This allocates each time, avoid
            .verify(&entry.encode().expect("encoding not to fail"), signature)
            .is_ok()
}

pub fn create_token(
    entry: &Entry,
    capability: McCapability,
    secret_key: &UserSecretKey,
) -> MeadowcapAuthorisationToken {
    // TODO: This allocates each time, avoid
    let signable = entry.encode().expect("encoding not to fail");
    let signature = secret_key.sign(&signable);
    MeadowcapAuthorisationToken::from_parts(capability, signature)
}

pub fn attach_authorisation(
    entry: Entry,
    capability: McCapability,
    secret_key: &UserSecretKey,
) -> Result<AuthorisedEntry, InvalidParams> {
    if capability.access_mode() != AccessMode::ReadWrite
        || capability.granted_namespace().id() != entry.namespace_id
        || !capability.granted_area().includes_entry(&entry)
        || capability.receiver() != &secret_key.public_key()
    {
        return Err(InvalidParams);
    }
    let token = create_token(&entry, capability, secret_key);
    Ok(AuthorisedEntry::from_parts_unchecked(entry, token))
}

#[derive(Debug, thiserror::Error)]
#[error("invalid parameters")]
pub struct InvalidParams;

#[derive(Debug, thiserror::Error)]
#[error("invalid capability")]
pub struct InvalidCapability;

/// To be used as an AuthorisationToken for Willow.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct MeadowcapAuthorisationToken {
    /// Certifies that an Entry may be written.
    pub capability: McCapability,
    /// Proves that the Entry was created by the receiver of the capability.
    pub signature: UserSignature,
}

// TODO: We clone these a bunch where it wouldn't be needed if we could create a reference type to
// which the [`MeadowcapAuthorisationToken`] would deref to, but I couldn't make it work nice
// enough.
// #[derive(Debug, Clone, Eq, PartialEq)]
// pub struct MeadowcapAuthorisationTokenRef<'a> {
//     /// Certifies that an Entry may be written.
//     pub capability: &'a McCapability,
//     /// Proves that the Entry was created by the receiver of the capability.
//     pub signature: &'a UserSignature,
// }

impl MeadowcapAuthorisationToken {
    pub fn from_parts(capability: McCapability, signature: UserSignature) -> Self {
        Self {
            capability,
            signature,
        }
    }
    pub fn as_parts(&self) -> (&McCapability, &UserSignature) {
        (&self.capability, &self.signature)
    }

    pub fn into_parts(self) -> (McCapability, UserSignature) {
        (self.capability, self.signature)
    }
}

impl From<(McCapability, UserSignature)> for MeadowcapAuthorisationToken {
    fn from((capability, signature): (McCapability, UserSignature)) -> Self {
        Self::from_parts(capability, signature)
    }
}

#[derive(Debug, Clone, derive_more::Deref, derive_more::Into)]
pub struct ValidatedCapability(McCapability);

impl ValidatedCapability {
    pub fn new(cap: McCapability) -> Result<Self, InvalidCapability> {
        if cap.is_valid() {
            Ok(Self(cap))
        } else {
            Err(InvalidCapability)
        }
    }

    pub fn is_valid(&self) -> bool {
        true
    }

    pub fn new_unchecked(cap: McCapability) -> Self {
        Self(cap)
    }
}

#[derive(
    Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, derive_more::From,
)]
pub enum McCapability {
    Communal(Arc<CommunalCapability>),
    Owned(Arc<OwnedCapability>),
}

impl McCapability {
    pub fn new_owned(
        namespace_secret: &NamespaceSecretKey,
        user_key: UserPublicKey,
        access_mode: AccessMode,
    ) -> Self {
        McCapability::Owned(Arc::new(OwnedCapability::new(
            namespace_secret,
            user_key,
            access_mode,
        )))
    }

    pub fn new_communal(
        namespace_key: NamespacePublicKey,
        user_key: UserPublicKey,
        access_mode: AccessMode,
    ) -> Self {
        McCapability::Communal(Arc::new(CommunalCapability::new(
            namespace_key,
            user_key,
            access_mode,
        )))
    }
    pub fn access_mode(&self) -> AccessMode {
        match self {
            Self::Communal(cap) => cap.access_mode,
            Self::Owned(cap) => cap.access_mode,
        }
    }
    pub fn receiver(&self) -> &UserPublicKey {
        match self {
            Self::Communal(cap) => cap.receiver(),
            Self::Owned(cap) => cap.receiver(),
        }
    }

    pub fn granted_namespace(&self) -> &NamespacePublicKey {
        match self {
            Self::Communal(cap) => cap.granted_namespace(),
            Self::Owned(cap) => cap.granted_namespace(),
        }
    }

    pub fn granted_area(&self) -> Area {
        match self {
            Self::Communal(cap) => cap.granted_area(),
            Self::Owned(cap) => cap.granted_area(),
        }
    }

    pub fn try_granted_area(&self, area: &Area) -> Result<(), Unauthorised> {
        if !self.granted_area().includes_area(area) {
            Err(Unauthorised)
        } else {
            Ok(())
        }
    }

    pub fn is_valid(&self) -> bool {
        match self {
            Self::Communal(cap) => cap.is_valid(),
            Self::Owned(cap) => cap.is_valid(),
        }
    }
    // pub fn validate(&self) -> Result<(), InvalidCapability> {
    pub fn validate(&self) -> anyhow::Result<()> {
        match self {
            Self::Communal(cap) => cap.validate(),
            Self::Owned(cap) => cap.validate(),
        }
    }

    pub fn delegations(&self) -> &[Delegation] {
        match self {
            Self::Communal(cap) => &cap.delegations,
            Self::Owned(cap) => &cap.delegations,
        }
    }

    /// Returns `true` if `self` covers a larger area than `other`,
    /// or if covers the same area and has less delegations.
    pub fn is_wider_than(&self, other: &Self) -> bool {
        (self.granted_area().includes_area(&other.granted_area()))
            || (self.granted_area() == other.granted_area()
                && self.delegations().len() < other.delegations().len())
    }

    pub fn delegate(
        &self,
        user_secret: &UserSecretKey,
        new_user: UserPublicKey,
        new_area: Area,
    ) -> anyhow::Result<Self> {
        let cap = match self {
            Self::Communal(cap) => {
                Self::Communal(Arc::new(cap.delegate(user_secret, new_user, new_area)?))
            }
            Self::Owned(cap) => {
                Self::Owned(Arc::new(cap.delegate(user_secret, new_user, new_area)?))
            }
        };
        Ok(cap)
    }
}

impl Encoder for McCapability {
    // TODO: Use spec-compliant encoding instead of postcard.
    fn encoded_len(&self) -> usize {
        postcard::experimental::serialized_size(&self).unwrap()
    }

    // TODO: Use spec-compliant encoding instead of postcard.
    fn encode_into<W: std::io::Write>(&self, out: &mut W) -> anyhow::Result<()> {
        postcard::to_io(&self, out)?;
        Ok(())
    }
}

impl Encoder for McSubspaceCapability {
    // TODO: Use spec-compliant encoding instead of postcard.
    fn encoded_len(&self) -> usize {
        postcard::experimental::serialized_size(&self).unwrap()
    }

    // TODO: Use spec-compliant encoding instead of postcard.
    fn encode_into<W: std::io::Write>(&self, out: &mut W) -> anyhow::Result<()> {
        postcard::to_io(&self, out)?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum AccessMode {
    ReadOnly,
    ReadWrite,
}

/// A capability that authorizes reads or writes in communal namespaces.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct CommunalCapability {
    /// The kind of access this grants.
    access_mode: AccessMode,
    /// The namespace in which this grants access.
    namespace_key: NamespacePublicKey,
    /// The subspace for which and to whom this grants access.
    ///
    /// Remember that we assume SubspaceId and UserPublicKey to be the same types.
    user_key: UserPublicKey,
    /// Successive authorisations of new UserPublicKeys, each restricted to a particular Area.
    delegations: Vec<Delegation>,
}

impl CommunalCapability {
    pub fn new(
        namespace_key: NamespacePublicKey,
        user_key: UserPublicKey,
        access_mode: AccessMode,
    ) -> Self {
        Self {
            access_mode,
            namespace_key,
            user_key,
            delegations: Default::default(),
        }
    }
    pub fn receiver(&self) -> &UserPublicKey {
        match self.delegations.last() {
            None => &self.user_key,
            Some(Delegation(_, user_key, _)) => user_key,
        }
    }

    pub fn granted_namespace(&self) -> &NamespacePublicKey {
        &self.namespace_key
    }

    pub fn granted_area(&self) -> Area {
        match self.delegations.last() {
            None => Area::subspace(self.user_key.into()),
            Some(Delegation(area, _, _)) => area.clone(),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.delegations.is_empty() {
            // communal capabilities without delegations are always valid
            Ok(())
        } else {
            let mut prev = None;
            let mut prev_receiver = &self.user_key;
            for delegation in self.delegations.iter() {
                let Delegation(new_area, new_user, new_signature) = &delegation;
                let signable = self.handover(prev, new_area, new_user)?;
                prev_receiver.verify(&signable, new_signature)?;
                prev = Some((new_area, new_signature));
                prev_receiver = new_user;
            }
            Ok(())
        }
    }

    pub fn delegate(
        &self,
        user_secret: &UserSecretKey,
        new_user: UserPublicKey,
        new_area: Area,
    ) -> anyhow::Result<Self> {
        if user_secret.public_key() != *self.receiver() {
            anyhow::bail!("Secret key does not match receiver of current capability");
        }
        let prev = self
            .delegations
            .last()
            .map(|Delegation(area, _user_key, sig)| (area, sig));
        let handover = self.handover(prev, &new_area, &new_user)?;
        let signature = user_secret.sign(&handover);
        let delegation = Delegation(new_area, new_user, signature);
        let mut cap = self.clone();
        cap.delegations.push(delegation);
        Ok(cap)
    }

    fn handover(
        &self,
        prev: Option<(&Area, &UserSignature)>,
        new_area: &Area,
        new_user: &UserPublicKey,
    ) -> anyhow::Result<Vec<u8>> {
        match prev {
            None => self.initial_handover(new_area, new_user),
            Some((prev_area, prev_signature)) => Handover::new(
                prev_area,
                PrevSignature::User(prev_signature),
                new_area,
                new_user,
            )?
            .encode(),
        }
    }

    fn initial_handover(
        &self,
        new_area: &Area,
        new_user: &UserPublicKey,
    ) -> anyhow::Result<Vec<u8>> {
        let prev_area = Area::subspace(self.user_key.into());
        let area_in_area = AreaInArea::new(new_area, &prev_area)?;
        let len =
            1 + NamespacePublicKey::LENGTH + area_in_area.encoded_len() + UserPublicKey::LENGTH;
        let mut out = std::io::Cursor::new(vec![0u8; len]);
        let init = match self.access_mode {
            AccessMode::ReadOnly => 0x00,
            AccessMode::ReadWrite => 0x01,
        };
        out.write_all(&[init])?;
        out.write_all(&self.namespace_key.to_bytes())?;
        area_in_area.encode_into(&mut out)?;
        out.write_all(&new_user.to_bytes())?;
        Ok(out.into_inner())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Hash, Ord, PartialOrd)]
pub struct Delegation(Area, UserPublicKey, UserSignature);

/// A capability that authorizes reads or writes in owned namespaces.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct OwnedCapability {
    /// The kind of access this grants.
    access_mode: AccessMode,
    /// The namespace for which this grants access.
    namespace_key: NamespacePublicKey,
    /// The user to whom this grants access; granting access for the full namespace_key, not just to a subspace.
    user_key: UserPublicKey,
    /// Authorisation of the user_key by the namespace_key.,
    initial_authorisation: NamespaceSignature,
    /// Successive authorisations of new UserPublicKeys, each restricted to a particular Area.
    delegations: Vec<Delegation>,
}

impl OwnedCapability {
    pub fn new(
        namespace_secret_key: &NamespaceSecretKey,
        user_key: UserPublicKey,
        access_mode: AccessMode,
    ) -> Self {
        let namespace_key = namespace_secret_key.public_key();
        let handover = Self::initial_handover(access_mode, &user_key);
        let initial_authorisation = namespace_secret_key.sign(&handover);
        Self {
            access_mode,
            namespace_key,
            user_key,
            initial_authorisation,
            delegations: Default::default(),
        }
    }

    pub fn receiver(&self) -> &UserPublicKey {
        match self.delegations.last() {
            None => &self.user_key,
            Some(Delegation(_, user_key, _)) => user_key,
        }
    }

    pub fn granted_namespace(&self) -> &NamespacePublicKey {
        &self.namespace_key
    }

    pub fn granted_area(&self) -> Area {
        match self.delegations.last() {
            None => Area::full(),
            Some(Delegation(area, _, _)) => area.clone(),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        // verify root authorisation
        let handover = Self::initial_handover(self.access_mode, &self.user_key);
        self.namespace_key
            .verify(&handover, &self.initial_authorisation)?;

        // no delegations: done
        if self.delegations.is_empty() {
            return Ok(());
        }

        let initial_area = Area::full();
        let mut prev = (
            &initial_area,
            &self.user_key,
            PrevSignature::Namespace(&self.initial_authorisation),
        );
        for delegation in self.delegations.iter() {
            let (prev_area, prev_user, prev_signature) = prev;
            let Delegation(new_area, new_user, new_signature) = delegation;
            let handover =
                Handover::new(prev_area, prev_signature, new_area, new_user)?.encode()?;
            prev_user.verify(&handover, new_signature)?;
            prev = (new_area, new_user, PrevSignature::User(new_signature));
        }
        Ok(())
    }

    fn initial_handover(
        access_mode: AccessMode,
        user_key: &UserPublicKey,
    ) -> [u8; PUBLIC_KEY_LENGTH + 1] {
        let mut signable = [0u8; PUBLIC_KEY_LENGTH + 1];
        // https://willowprotocol.org/specs/meadowcap/index.html#owned_cap_valid
        // An OwnedCapability with zero delegations is valid if initial_authorisation
        // is a NamespaceSignature issued by the namespace_key over
        // either the byte 0x02 (if access_mode is read)
        // or the byte 0x03 (if access_mode is write),
        // followed by the user_key (encoded via encode_user_pk).
        signable[0] = match access_mode {
            AccessMode::ReadOnly => 0x02,
            AccessMode::ReadWrite => 0x03,
        };
        signable[1..].copy_from_slice(user_key.as_bytes());
        signable
    }

    pub fn delegate(
        &self,
        secret_key: &UserSecretKey,
        new_user: UserPublicKey,
        new_area: Area,
    ) -> anyhow::Result<Self> {
        if secret_key.public_key() != *self.receiver() {
            anyhow::bail!("Secret key does not match receiver of current capability");
        }
        let prev_signature = match self.delegations.last() {
            None => PrevSignature::Namespace(&self.initial_authorisation),
            Some(Delegation(_, _, prev_signature)) => PrevSignature::User(prev_signature),
        };
        let prev_area = self.granted_area();
        let handover = Handover::new(&prev_area, prev_signature, &new_area, &new_user)?;
        let signable = handover.encode()?;
        let signature = secret_key.sign(&signable);
        let delegation = Delegation(new_area, new_user, signature);
        let mut cap = self.clone();
        cap.delegations.push(delegation);
        Ok(cap)
    }
}

#[derive(Debug)]
enum PrevSignature<'a> {
    User(&'a UserSignature),
    Namespace(&'a NamespaceSignature),
}

impl<'a> PrevSignature<'a> {
    fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        match self {
            Self::User(sig) => sig.to_bytes(),
            Self::Namespace(sig) => sig.to_bytes(),
        }
    }
}

#[derive(Debug)]
struct Handover<'a> {
    prev_signature: PrevSignature<'a>,
    new_user: &'a UserPublicKey,
    area_in_area: AreaInArea<'a>,
}

impl<'a> Handover<'a> {
    fn new(
        prev_area: &'a Area,
        prev_signature: PrevSignature<'a>,
        new_area: &'a Area,
        new_user: &'a UserPublicKey,
    ) -> Result<Self, NotIncluded> {
        let area_in_area = AreaInArea::new(new_area, prev_area)?;
        Ok(Self {
            area_in_area,
            prev_signature,
            new_user,
        })
    }
}

impl<'a> Encoder for Handover<'a> {
    fn encoded_len(&self) -> usize {
        self.area_in_area.encoded_len() + NamespaceSignature::LENGTH + UserId::LENGTH
    }
    fn encode_into<W: std::io::Write>(&self, out: &mut W) -> anyhow::Result<()> {
        self.area_in_area.encode_into(out)?;
        out.write_all(&self.prev_signature.to_bytes())?;
        out.write_all(&self.new_user.to_bytes())?;
        Ok(())
    }
}

#[derive(
    Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash, derive_more::From, Ord, PartialOrd,
)]
/// A capability that certifies read access to arbitrary SubspaceIds at some unspecified Path.
pub struct McSubspaceCapability {
    /// The namespace for which this grants access.
    pub namespace_key: NamespacePublicKey,

    /// The user to whom this grants access.
    pub user_key: UserPublicKey,

    /// Authorisation of the user_key by the namespace_key.
    pub initial_authorisation: NamespaceSignature,

    /// Successive authorisations of new UserPublicKeys.
    pub delegations: Vec<(UserPublicKey, UserSignature)>,
}

impl McSubspaceCapability {
    pub fn new(namespace_secret_key: &NamespaceSecretKey, user_key: UserPublicKey) -> Self {
        let namespace_key = namespace_secret_key.public_key();
        let handover = Self::initial_handover(&user_key);
        let initial_authorisation = namespace_secret_key.sign(&handover);
        Self {
            namespace_key,
            user_key,
            initial_authorisation,
            delegations: Default::default(),
        }
    }
    pub fn receiver(&self) -> &UserPublicKey {
        &self.user_key
    }

    pub fn granted_namespace(&self) -> &NamespacePublicKey {
        &self.namespace_key
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let signable = Self::initial_handover(&self.user_key);
        self.namespace_key
            .verify(&signable, &self.initial_authorisation)?;

        if self.delegations.is_empty() {
            return Ok(());
        }

        let mut prev = (
            &self.user_key,
            PrevSignature::Namespace(&self.initial_authorisation),
        );
        for delegation in &self.delegations {
            let (prev_user, prev_signature) = prev;
            let (new_user, new_signature) = delegation;
            let handover = Self::handover(prev_signature, new_user);
            prev_user.verify(&handover, new_signature)?;
            prev = (new_user, PrevSignature::User(new_signature));
        }
        Ok(())
    }

    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }

    pub fn delegate(
        &self,
        secret_key: &UserSecretKey,
        new_user: UserPublicKey,
    ) -> anyhow::Result<Self> {
        if secret_key.public_key() != *self.receiver() {
            anyhow::bail!("Secret key does not match receiver of current capability");
        }
        let prev_signature = match self.delegations.last() {
            None => PrevSignature::Namespace(&self.initial_authorisation),
            Some((_, prev_signature)) => PrevSignature::User(prev_signature),
        };
        let handover = Self::handover(prev_signature, &new_user);
        let signature = secret_key.sign(&handover);
        let delegation = (new_user, signature);
        let mut cap = self.clone();
        cap.delegations.push(delegation);
        Ok(cap)
    }

    fn handover(
        prev_signature: PrevSignature,
        new_user: &UserPublicKey,
    ) -> [u8; PUBLIC_KEY_LENGTH + SIGNATURE_LENGTH] {
        let mut out = [0u8; PUBLIC_KEY_LENGTH + SIGNATURE_LENGTH];
        out[..SIGNATURE_LENGTH].copy_from_slice(&prev_signature.to_bytes());
        out[SIGNATURE_LENGTH..].copy_from_slice(new_user.as_bytes());
        out
    }

    fn initial_handover(user_key: &UserPublicKey) -> [u8; PUBLIC_KEY_LENGTH + 1] {
        let mut signable = [0u8; PUBLIC_KEY_LENGTH + 1];
        // A McSubspaceCapability with zero delegations is valid if initial_authorisation
        // is a NamespaceSignature issued by the namespace_key over the byte 0x02,
        // followed by the user_key (encoded via encode_user_pk).
        // via https://willowprotocol.org/specs/pai/index.html#subspace_cap_valid
        signable[0] = 0x02;
        signable[1..].copy_from_slice(user_key.as_bytes());
        signable
    }
}

#[cfg(test)]
mod tests {
    use rand_core::SeedableRng;

    use crate::proto::{
        grouping::Area,
        keys::{NamespaceKind, NamespaceSecretKey, UserSecretKey},
    };

    use super::{AccessMode, McCapability};

    #[test]
    fn delegate_owned() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(1);
        let namespace_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let alfie_secret = UserSecretKey::generate(&mut rng);
        let betty_secret = UserSecretKey::generate(&mut rng);
        let alfie_public = alfie_secret.public_key();
        let betty_public = betty_secret.public_key();
        let cap = McCapability::new_owned(&namespace_secret, alfie_public, AccessMode::ReadWrite);
        cap.validate().expect("cap to be valid");
        let cap_betty = cap
            .delegate(&alfie_secret, betty_public, Area::full())
            .expect("not to fail");
        cap_betty.validate().expect("cap to be valid");
        let conny_secret = UserSecretKey::generate(&mut rng);
        let conny_public = conny_secret.public_key();
        let cap_conny = cap_betty
            .delegate(
                &betty_secret,
                conny_public,
                Area::subspace(conny_public.id()),
            )
            .expect("not to fail");
        cap_conny.validate().expect("cap to be valid");
        assert_eq!(cap_conny.granted_area(), Area::subspace(conny_public.id()));
        assert_eq!(cap_conny.receiver(), &conny_public);
    }
}
