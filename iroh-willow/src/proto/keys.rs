//! Keys used in iroh-sync

use std::{cmp::Ordering, fmt, str::FromStr};

use ed25519_dalek::{SignatureError, Signer, SigningKey, VerifyingKey};
use iroh_base::base32;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

// use crate::store::PublicKeyStore;

pub const PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
pub const SECRET_KEY_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH;
pub const SIGNATURE_LENGTH: usize = ed25519_dalek::SIGNATURE_LENGTH;

pub type SubspaceId = UserId;

pub type Signature = ed25519_dalek::Signature;

/// User key to insert entries in a [`crate::Replica`]
///
/// Internally, an author is a [`SigningKey`] which is used to sign entries.
#[derive(Clone, Serialize, Deserialize)]
pub struct UserSecretKey(SigningKey);

impl UserSecretKey {
    /// Create a new [`UserSecretKey`] with a random key.
    pub fn generate<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let signing_key = SigningKey::generate(rng);
        UserSecretKey(signing_key)
    }

    /// Create an [`UserSecretKey`] from a byte array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        SigningKey::from_bytes(bytes).into()
    }

    /// Returns the [`UserSecretKey`] byte representation.
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
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.0.sign(msg)
    }

    /// Strictly verify a signature on a message with this [`UserSecretKey`]'s public key.
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.0.verify_strict(msg, signature)
    }
}

/// Identifier for an [`UserSecretKey`]
///
/// This is the corresponding [`VerifyingKey`] for an author. It is used as an identifier, and can
/// be used to verify [`Signature`]s.
#[derive(Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash, derive_more::From)]
pub struct UserPublicKey(VerifyingKey);

impl UserPublicKey {
    /// Verify that a signature matches the `msg` bytes and was created with the [`UserSecretKey`]
    /// that corresponds to this [`UserId`].
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.0.verify_strict(msg, signature)
    }

    /// Get the byte representation of this [`UserId`].
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Create from a slice of bytes.
    ///
    /// Will return an error if the input bytes do not represent a valid [`ed25519_dalek`]
    /// curve point. Will never fail for a byte array returned from [`Self::as_bytes`].
    /// See [`VerifyingKey::from_bytes`] for details.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignatureError> {
        Ok(UserPublicKey(VerifyingKey::from_bytes(bytes)?))
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum NamespaceType {
    Communal,
    Owned,
}

/// Namespace key of a [`crate::Replica`].
///
/// Holders of this key can insert new entries into a [`crate::Replica`].
/// Internally, a [`NamespaceSecretKey] is a [`SigningKey`] which is used to sign entries.
#[derive(Clone, Serialize, Deserialize)]
pub struct NamespaceSecretKey(SigningKey);

impl NamespaceSecretKey {
    /// Create a new [`NamespaceSecretKey] with a random key.
    pub fn generate<R: CryptoRngCore + ?Sized>(rng: &mut R, typ: NamespaceType) -> Self {
        loop {
            let signing_key = SigningKey::generate(rng);
            let secret_key = NamespaceSecretKey(signing_key);
            if secret_key.public_key().namespace_type() == typ {
                break secret_key;
            }
        }
    }

    /// Create a [`NamespaceSecretKey] from a byte array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        SigningKey::from_bytes(bytes).into()
    }

    /// Returns the [`NamespaceSecretKey] byte representation.
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
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.0.sign(msg)
    }

    /// Strictly verify a signature on a message with this [`NamespaceSecretKey]'s public key.
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.0.verify_strict(msg, signature)
    }
}

/// The corresponding [`VerifyingKey`] for a [`NamespaceSecretKey].
/// It is used as an identifier, and can be used to verify [`Signature`]s.
#[derive(Default, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash, derive_more::From)]
pub struct NamespacePublicKey(VerifyingKey);

impl NamespacePublicKey {
    /// Whether this is the key for a communal namespace.
    pub fn is_communal(&self) -> bool {
        is_communal(self.as_bytes())
    }

    pub fn namespace_type(&self) -> NamespaceType {
        match self.is_communal() {
            true => NamespaceType::Communal,
            false => NamespaceType::Owned,
        }
    }

    /// Verify that a signature matches the `msg` bytes and was created with the [`NamespaceSecretKey]
    /// that corresponds to this [`NamespaceId`].
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.0.verify_strict(msg, signature)
    }

    /// Get the byte representation of this [`NamespaceId`].
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Create from a slice of bytes.
    ///
    /// Will return an error if the input bytes do not represent a valid [`ed25519_dalek`]
    /// curve point. Will never fail for a byte array returned from [`Self::as_bytes`].
    /// See [`VerifyingKey::from_bytes`] for details.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignatureError> {
        Ok(NamespacePublicKey(VerifyingKey::from_bytes(bytes)?))
    }
}

impl fmt::Display for UserSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base32::fmt(self.to_bytes()))
    }
}

impl fmt::Display for NamespaceSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base32::fmt(self.to_bytes()))
    }
}

impl fmt::Display for UserPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base32::fmt(self.as_bytes()))
    }
}

impl fmt::Display for NamespacePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base32::fmt(self.as_bytes()))
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base32::fmt(self.as_bytes()))
    }
}

impl fmt::Display for NamespaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base32::fmt(self.as_bytes()))
    }
}

impl fmt::Debug for NamespaceSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Namespace({})", self)
    }
}

impl fmt::Debug for NamespaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NamespaceId({})", base32::fmt_short(self.0))
    }
}

impl fmt::Debug for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UserId({})", base32::fmt_short(self.0))
    }
}

impl fmt::Debug for UserSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "User({})", self)
    }
}

impl fmt::Debug for NamespacePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NamespacePublicKey({})", self)
    }
}

impl fmt::Debug for UserPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UserPublicKey({})", self)
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
    derive_more::From,
    derive_more::Into,
    derive_more::AsRef,
    Serialize,
    Deserialize,
)]
pub struct NamespaceId([u8; 32]);

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
    derive_more::From,
    derive_more::Into,
    derive_more::AsRef,
    Serialize,
    Deserialize,
)]
pub struct UserId([u8; 32]);

impl UserId {
    /// Convert to byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Convert to byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    // /// Convert into [`UserPublicKey`] by fetching from a [`PublicKeyStore`].
    // ///
    // /// Fails if the bytes of this [`UserId`] are not a valid [`ed25519_dalek`] curve point.
    // pub fn public_key<S: PublicKeyStore>(
    //     &self,
    //     store: &S,
    // ) -> Result<UserPublicKey, SignatureError> {
    //     store.author_key(self)
    // }

    /// Convert into [`UserPublicKey`].
    ///
    /// Fails if the bytes of this [`UserId`] are not a valid [`ed25519_dalek`] curve point.
    pub fn into_public_key(&self) -> Result<UserPublicKey, SignatureError> {
        UserPublicKey::from_bytes(&self.0)
    }

    /// Convert to a base32 string limited to the first 10 bytes for a friendly string
    /// representation of the key.
    pub fn fmt_short(&self) -> String {
        base32::fmt_short(self.0)
    }
}

impl NamespaceId {
    /// Convert to byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Convert to byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    // /// Convert into [`NamespacePublicKey`] by fetching from a [`PublicKeyStore`].
    // ///
    // /// Fails if the bytes of this [`NamespaceId`] are not a valid [`ed25519_dalek`] curve point.
    // pub fn public_key<S: PublicKeyStore>(
    //     &self,
    //     store: &S,
    // ) -> Result<NamespacePublicKey, SignatureError> {
    //     store.namespace_key(self)
    // }

    /// Convert into [`NamespacePublicKey`].
    ///
    /// Fails if the bytes of this [`NamespaceId`] are not a valid [`ed25519_dalek`] curve point.
    pub fn into_public_key(&self) -> Result<NamespacePublicKey, SignatureError> {
        NamespacePublicKey::from_bytes(&self.0)
    }

    /// Convert to a base32 string limited to the first 10 bytes for a friendly string
    /// representation of the key.
    pub fn fmt_short(&self) -> String {
        base32::fmt_short(self.0)
    }
}

impl From<&[u8; 32]> for NamespaceId {
    fn from(value: &[u8; 32]) -> Self {
        Self(*value)
    }
}

impl From<&[u8; 32]> for UserId {
    fn from(value: &[u8; 32]) -> Self {
        Self(*value)
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

pub fn is_communal(pubkey_bytes: &[u8]) -> bool {
    let last = pubkey_bytes.last().expect("pubkey is not empty");
    // Check if last bit is 1.
    (*last & 0x1) == 0x1
}
