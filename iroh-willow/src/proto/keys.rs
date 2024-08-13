//! Public-key crypto types for willow
//!
//! This modules defines types which are wrappers around [`ed25519_dalek`] public-key crypto types.
//!
//! We also define an Id type which is a public key represented as [u8; 32], which is smaller than
//! the expanded PublicKey representation needed for signature verification

use std::{cmp::Ordering, fmt, str::FromStr};

use derive_more::{AsRef, Deref, From, Into};
use ed25519_dalek::{SignatureError, Signer, SigningKey, Verifier, VerifyingKey};
use iroh_base::base32;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::meadowcap::IsCommunal;

pub const PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
pub const SECRET_KEY_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH;
pub const SIGNATURE_LENGTH: usize = ed25519_dalek::SIGNATURE_LENGTH;

/// Helper macro to implement formatting traits for bytestring like types
macro_rules! bytestring {
    ($ty:ty, $n:ident) => {
        impl $ty {
            /// Length of the byte encoding of [`Self`].
            pub const LENGTH: usize = $n;

            /// Convert to a base32 string limited to the first 10 bytes for a friendly string
            /// representation of the key.
            pub fn fmt_short(&self) -> String {
                base32::fmt_short(&self.to_bytes())
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", base32::fmt(&self.to_bytes()))
            }
        }

        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($ty), self.fmt_short())
            }
        }
    };
}

impl IsCommunal for NamespaceId {
    fn is_communal(&self) -> bool {
        self.as_bytes()[31] == 0
    }
}

impl IsCommunal for NamespacePublicKey {
    fn is_communal(&self) -> bool {
        self.id().is_communal()
    }
}

/// The type of the namespace, either communal or owned.
///
/// A [`NamespacePublicKey`] whose last bit is 1 is defined to be a communal namespace,
/// and if the last bit is zero it is an owned namespace.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum NamespaceKind {
    /// Communal namespace, needs [`super::meadowcap::CommunalCapability`] to authorizse.
    Communal,
    /// Owned namespace, needs [`super::meadowcap::OwnedCapability`] to authorize.
    Owned,
}

/// Namespace secret key.
#[derive(Clone, Serialize, Deserialize)]
pub struct NamespaceSecretKey(SigningKey);

bytestring!(NamespaceSecretKey, PUBLIC_KEY_LENGTH);

impl NamespaceSecretKey {
    /// Create a new, random [`NamespaceSecretKey] with an encoded [`NamespaceKind`].
    pub fn generate<R: CryptoRngCore + ?Sized>(rng: &mut R, typ: NamespaceKind) -> Self {
        loop {
            let signing_key = SigningKey::generate(rng);
            let secret_key = NamespaceSecretKey(signing_key);
            if secret_key.public_key().kind() == typ {
                break secret_key;
            }
        }
    }

    /// Create a [`NamespaceSecretKey] from a byte array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        SigningKey::from_bytes(bytes).into()
    }

    /// Convert into a byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Get the [`NamespacePublicKey`] for this namespace.
    pub fn public_key(&self) -> NamespacePublicKey {
        NamespacePublicKey(self.0.verifying_key())
    }

    /// Get the [`NamespaceId`] for this namespace.
    pub fn id(&self) -> NamespaceId {
        NamespaceId::from(self.public_key())
    }

    /// Sign a message with this [`NamespaceSecretKey] key.
    pub fn sign(&self, msg: &[u8]) -> NamespaceSignature {
        NamespaceSignature(self.0.sign(msg))
    }

    /// Strictly verify a signature on a message with this [`NamespaceSecretKey]'s public key.
    pub fn verify(&self, msg: &[u8], signature: &NamespaceSignature) -> Result<(), SignatureError> {
        self.0.verify_strict(msg, &signature.0)
    }
}

/// The corresponding public key for a [`NamespaceSecretKey].
#[derive(Default, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash, derive_more::From)]
pub struct NamespacePublicKey(VerifyingKey);

bytestring!(NamespacePublicKey, PUBLIC_KEY_LENGTH);

impl NamespacePublicKey {
    pub fn kind(&self) -> NamespaceKind {
        if self.is_communal() {
            NamespaceKind::Communal
        } else {
            NamespaceKind::Owned
        }
    }

    /// Verify that a signature matches the `msg` bytes and was created with the [`NamespaceSecretKey]
    /// that corresponds to this [`NamespaceId`].
    pub fn verify(&self, msg: &[u8], signature: &NamespaceSignature) -> Result<(), SignatureError> {
        self.0.verify_strict(msg, &signature.0)
    }

    /// Get this [`NamespaceId`] as a byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Convert into a byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Create from a slice of bytes.
    ///
    /// Will return an error if the input bytes do not represent a valid [`ed25519_dalek`]
    /// curve point. Will never fail for a byte array returned from [`Self::as_bytes`].
    /// See [`VerifyingKey::from_bytes`] for details.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignatureError> {
        Ok(NamespacePublicKey(VerifyingKey::from_bytes(bytes)?))
    }

    /// Convert into a [`NamespaceId`].
    pub fn id(&self) -> NamespaceId {
        self.into()
    }
}

/// User secret key.
#[derive(Clone, Serialize, Deserialize)]
pub struct UserSecretKey(SigningKey);

bytestring!(UserSecretKey, SECRET_KEY_LENGTH);

impl UserSecretKey {
    /// Create a new [`UserSecretKey`] with a random key.
    pub fn generate<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let signing_key = SigningKey::generate(rng);
        UserSecretKey(signing_key)
    }

    /// Create from a byte slice.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        SigningKey::from_bytes(bytes).into()
    }

    /// Convert into a byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Get the [`UserPublicKey`] for this author.
    pub fn public_key(&self) -> UserPublicKey {
        UserPublicKey(self.0.verifying_key())
    }

    /// Get the [`UserId`] for this author.
    pub fn id(&self) -> UserId {
        UserId::from(self.public_key())
    }

    /// Sign a message with this [`UserSecretKey`] key.
    pub fn sign(&self, msg: &[u8]) -> UserSignature {
        UserSignature(self.0.sign(msg))
    }

    /// Strictly verify a signature on a message with this [`UserSecretKey`]'s public key.
    pub fn verify(&self, msg: &[u8], signature: &UserSignature) -> Result<(), SignatureError> {
        self.0.verify_strict(msg, &signature.0)
    }
}

/// The corresponding public key for a [`UserSecretKey].
#[derive(Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash, derive_more::From)]
pub struct UserPublicKey(VerifyingKey);

bytestring!(UserPublicKey, PUBLIC_KEY_LENGTH);

impl UserPublicKey {
    /// Verify that a signature matches the `msg` bytes and was created with the [`UserSecretKey`]
    /// that corresponds to this [`UserId`].
    pub fn verify(&self, msg: &[u8], signature: &UserSignature) -> Result<(), SignatureError> {
        self.0.verify_strict(msg, &signature.0)
    }

    /// Get this [`UserId`] as a byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Convert into a byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Create from a slice of bytes.
    ///
    /// Will return an error if the input bytes do not represent a valid [`ed25519_dalek`]
    /// curve point. Will never fail for a byte array returned from [`Self::as_bytes`].
    /// See [`VerifyingKey::from_bytes`] for details.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignatureError> {
        Ok(UserPublicKey(VerifyingKey::from_bytes(bytes)?))
    }

    /// Convert into a [`UserId`].
    pub fn id(&self) -> UserId {
        self.into()
    }
}

impl FromStr for UserSecretKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_bytes(&base32::parse_array(s)?))
    }
}

impl FromStr for NamespaceSecretKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_bytes(&base32::parse_array(s)?))
    }
}

impl FromStr for UserPublicKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(&base32::parse_array(s)?).map_err(Into::into)
    }
}

impl FromStr for NamespacePublicKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(&base32::parse_array(s)?).map_err(Into::into)
    }
}

impl From<SigningKey> for UserSecretKey {
    fn from(signing_key: SigningKey) -> Self {
        Self(signing_key)
    }
}

impl From<SigningKey> for NamespaceSecretKey {
    fn from(signing_key: SigningKey) -> Self {
        Self(signing_key)
    }
}

impl PartialOrd for NamespacePublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NamespacePublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl PartialOrd for UserPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for UserPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl From<NamespaceSecretKey> for NamespacePublicKey {
    fn from(value: NamespaceSecretKey) -> Self {
        value.public_key()
    }
}

impl From<UserSecretKey> for UserPublicKey {
    fn from(value: UserSecretKey) -> Self {
        value.public_key()
    }
}

impl From<&NamespaceSecretKey> for NamespacePublicKey {
    fn from(value: &NamespaceSecretKey) -> Self {
        value.public_key()
    }
}

impl From<&UserSecretKey> for UserPublicKey {
    fn from(value: &UserSecretKey) -> Self {
        value.public_key()
    }
}

/// The signature obtained by signing a message with a [`NamespaceSecretKey`].
#[derive(Serialize, Deserialize, Clone, From, PartialEq, Eq, Deref)]
pub struct NamespaceSignature(ed25519_dalek::Signature);

impl NamespaceSignature {
    /// Create from a byte array.
    pub fn from_bytes(bytes: [u8; SIGNATURE_LENGTH]) -> Self {
        Self(ed25519_dalek::Signature::from_bytes(&bytes))
    }
}

impl PartialOrd for NamespaceSignature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NamespaceSignature {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

bytestring!(NamespaceSignature, SIGNATURE_LENGTH);

impl std::hash::Hash for NamespaceSignature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

/// The signature obtained by signing a message with a [`UserSecretKey`].
#[derive(Serialize, Deserialize, Clone, From, PartialEq, Eq, Deref)]
pub struct UserSignature(ed25519_dalek::Signature);

impl UserSignature {
    /// Create from a byte array.
    pub fn from_bytes(bytes: [u8; SIGNATURE_LENGTH]) -> Self {
        Self(ed25519_dalek::Signature::from_bytes(&bytes))
    }
}

impl PartialOrd for UserSignature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for UserSignature {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

bytestring!(UserSignature, SIGNATURE_LENGTH);

impl std::hash::Hash for UserSignature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bytes().hash(state);
    }
}

/// [`UserPublicKey`] in bytes
#[derive(
    Default,
    Clone,
    Copy,
    PartialOrd,
    Ord,
    Eq,
    PartialEq,
    Hash,
    From,
    Into,
    AsRef,
    Serialize,
    Deserialize,
)]
pub struct UserId([u8; 32]);

bytestring!(UserId, PUBLIC_KEY_LENGTH);

impl UserId {
    /// Convert to byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert into a byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Convert into [`UserPublicKey`].
    ///
    /// Fails if the bytes of this [`UserId`] are not a valid [`ed25519_dalek`] curve point.
    pub fn into_public_key(&self) -> Result<UserPublicKey, SignatureError> {
        UserPublicKey::from_bytes(&self.0)
    }

    /// Create from a byte array.
    ///
    /// Does not check if the byte array are a valid [`UserPublicKey`]
    pub fn from_bytes_unchecked(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// [`NamespacePublicKey`] in bytes
#[derive(
    Default,
    Clone,
    Copy,
    PartialOrd,
    Ord,
    Eq,
    PartialEq,
    Hash,
    From,
    Into,
    AsRef,
    Serialize,
    Deserialize,
)]
pub struct NamespaceId([u8; 32]);

bytestring!(NamespaceId, PUBLIC_KEY_LENGTH);

impl NamespaceId {
    /// Convert to byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert into a byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Convert into [`NamespacePublicKey`].
    ///
    /// Fails if the bytes of this [`NamespaceId`] are not a valid [`ed25519_dalek`] curve point.
    pub fn into_public_key(&self) -> Result<NamespacePublicKey, SignatureError> {
        NamespacePublicKey::from_bytes(&self.0)
    }

    /// Create from a byte array.
    ///
    /// Does not check if the byte array are a valid [`NamespacePublicKey`]
    pub fn from_bytes_unchecked(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for NamespaceId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for UserId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<UserPublicKey> for UserId {
    fn from(value: UserPublicKey) -> Self {
        Self(*value.as_bytes())
    }
}
impl From<NamespacePublicKey> for NamespaceId {
    fn from(value: NamespacePublicKey) -> Self {
        Self(*value.as_bytes())
    }
}

impl From<&UserPublicKey> for UserId {
    fn from(value: &UserPublicKey) -> Self {
        Self(*value.as_bytes())
    }
}
impl From<&NamespacePublicKey> for NamespaceId {
    fn from(value: &NamespacePublicKey) -> Self {
        Self(*value.as_bytes())
    }
}

impl From<UserSecretKey> for UserId {
    fn from(value: UserSecretKey) -> Self {
        value.id()
    }
}
impl From<NamespaceSecretKey> for NamespaceId {
    fn from(value: NamespaceSecretKey) -> Self {
        value.id()
    }
}

impl TryFrom<NamespaceId> for NamespacePublicKey {
    type Error = SignatureError;
    fn try_from(value: NamespaceId) -> Result<Self, Self::Error> {
        Self::from_bytes(&value.0)
    }
}

impl TryFrom<UserId> for UserPublicKey {
    type Error = SignatureError;
    fn try_from(value: UserId) -> Result<Self, Self::Error> {
        Self::from_bytes(&value.0)
    }
}

impl FromStr for UserId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        UserPublicKey::from_str(s).map(|x| x.into())
    }
}

impl FromStr for NamespaceId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        NamespacePublicKey::from_str(s).map(|x| x.into())
    }
}

mod willow_impls {
    use crate::util::increment_by_one;

    use super::*;

    impl willow_data_model::SubspaceId for UserId {
        fn successor(&self) -> Option<Self> {
            increment_by_one(self.as_bytes()).map(Self::from_bytes_unchecked)
        }
    }

    impl willow_data_model::SubspaceId for UserPublicKey {
        fn successor(&self) -> Option<Self> {
            match increment_by_one(self.as_bytes()) {
                Some(bytes) => Self::from_bytes(&bytes).ok(),
                None => None,
            }
        }
    }

    impl willow_data_model::NamespaceId for NamespaceId {}
    impl willow_data_model::NamespaceId for NamespacePublicKey {}

    impl Verifier<UserSignature> for UserPublicKey {
        fn verify(
            &self,
            msg: &[u8],
            signature: &UserSignature,
        ) -> Result<(), ed25519_dalek::ed25519::Error> {
            self.0.verify(msg, &signature.0)
        }
    }

    impl Verifier<UserSignature> for UserId {
        fn verify(
            &self,
            msg: &[u8],
            signature: &UserSignature,
        ) -> Result<(), ed25519_dalek::ed25519::Error> {
            // TODO: Cache this in a global LRU cache.
            let key = self.into_public_key()?;
            key.0.verify(msg, &signature.0)
        }
    }

    impl Verifier<NamespaceSignature> for NamespacePublicKey {
        fn verify(
            &self,
            msg: &[u8],
            signature: &NamespaceSignature,
        ) -> Result<(), ed25519_dalek::ed25519::Error> {
            self.0.verify(msg, &signature.0)
        }
    }

    impl Verifier<NamespaceSignature> for NamespaceId {
        fn verify(
            &self,
            msg: &[u8],
            signature: &NamespaceSignature,
        ) -> Result<(), ed25519_dalek::ed25519::Error> {
            // TODO: Cache this in a global LRU cache.
            let key = self.into_public_key()?;
            key.0.verify(msg, &signature.0)
        }
    }

    impl Signer<UserSignature> for UserSecretKey {
        fn try_sign(&self, msg: &[u8]) -> Result<UserSignature, ed25519_dalek::ed25519::Error> {
            Ok(UserSignature(self.0.sign(msg)))
        }
    }

    impl Signer<NamespaceSignature> for NamespaceSecretKey {
        fn try_sign(
            &self,
            msg: &[u8],
        ) -> Result<NamespaceSignature, ed25519_dalek::ed25519::Error> {
            Ok(NamespaceSignature(self.0.sign(msg)))
        }
    }
}

use syncify::syncify;
use syncify::syncify_replace;

#[syncify(encoding_sync)]
mod encoding {
    #[syncify_replace(use ufotofu::sync::{BulkConsumer, BulkProducer};)]
    use ufotofu::local_nb::{BulkConsumer, BulkProducer};

    use willow_encoding::DecodeError;
    #[syncify_replace(use willow_encoding::sync::{Encodable, Decodable};)]
    use willow_encoding::{Decodable, Encodable};

    use super::*;

    impl Encodable for NamespacePublicKey {
        async fn encode<Consumer>(&self, consumer: &mut Consumer) -> Result<(), Consumer::Error>
        where
            Consumer: BulkConsumer<Item = u8>,
        {
            consumer
                .bulk_consume_full_slice(self.as_bytes())
                .await
                .map_err(|err| err.reason)
        }
    }

    impl Encodable for UserPublicKey {
        async fn encode<Consumer>(&self, consumer: &mut Consumer) -> Result<(), Consumer::Error>
        where
            Consumer: BulkConsumer<Item = u8>,
        {
            consumer
                .bulk_consume_full_slice(self.as_bytes())
                .await
                .map_err(|err| err.reason)
        }
    }

    impl Encodable for NamespaceSignature {
        async fn encode<Consumer>(&self, consumer: &mut Consumer) -> Result<(), Consumer::Error>
        where
            Consumer: BulkConsumer<Item = u8>,
        {
            consumer
                .bulk_consume_full_slice(&self.to_bytes())
                .await
                .map_err(|err| err.reason)
        }
    }

    impl Encodable for UserSignature {
        async fn encode<Consumer>(&self, consumer: &mut Consumer) -> Result<(), Consumer::Error>
        where
            Consumer: BulkConsumer<Item = u8>,
        {
            consumer
                .bulk_consume_full_slice(&self.to_bytes())
                .await
                .map_err(|err| err.reason)
        }
    }

    impl Encodable for UserId {
        async fn encode<Consumer>(&self, consumer: &mut Consumer) -> Result<(), Consumer::Error>
        where
            Consumer: BulkConsumer<Item = u8>,
        {
            consumer
                .bulk_consume_full_slice(self.as_bytes())
                .await
                .map_err(|err| err.reason)
        }
    }

    impl Encodable for NamespaceId {
        async fn encode<Consumer>(&self, consumer: &mut Consumer) -> Result<(), Consumer::Error>
        where
            Consumer: BulkConsumer<Item = u8>,
        {
            consumer
                .bulk_consume_full_slice(self.as_bytes())
                .await
                .map_err(|err| err.reason)
        }
    }

    impl Decodable for NamespaceId {
        async fn decode<Producer>(
            producer: &mut Producer,
        ) -> Result<Self, DecodeError<Producer::Error>>
        where
            Producer: BulkProducer<Item = u8>,
        {
            let mut bytes = [0; PUBLIC_KEY_LENGTH];
            producer.bulk_overwrite_full_slice(&mut bytes).await?;
            Ok(Self::from_bytes_unchecked(bytes))
        }
    }

    impl Decodable for UserId {
        async fn decode<Producer>(
            producer: &mut Producer,
        ) -> Result<Self, DecodeError<Producer::Error>>
        where
            Producer: BulkProducer<Item = u8>,
        {
            let mut bytes = [0; PUBLIC_KEY_LENGTH];
            producer.bulk_overwrite_full_slice(&mut bytes).await?;
            Ok(Self::from_bytes_unchecked(bytes))
        }
    }

    impl Decodable for NamespaceSignature {
        async fn decode<Producer>(
            producer: &mut Producer,
        ) -> Result<Self, DecodeError<Producer::Error>>
        where
            Producer: BulkProducer<Item = u8>,
        {
            let mut bytes = [0; SIGNATURE_LENGTH];
            producer.bulk_overwrite_full_slice(&mut bytes).await?;
            Ok(Self::from_bytes(bytes))
        }
    }

    impl Decodable for UserSignature {
        async fn decode<Producer>(
            producer: &mut Producer,
        ) -> Result<Self, DecodeError<Producer::Error>>
        where
            Producer: BulkProducer<Item = u8>,
        {
            let mut bytes = [0; SIGNATURE_LENGTH];
            producer.bulk_overwrite_full_slice(&mut bytes).await?;
            Ok(Self::from_bytes(bytes))
        }
    }
}
