//! Keys used in iroh-sync

use std::{cmp::Ordering, fmt, str::FromStr};

use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::store::PublicKeyStore;

/// Author key to insert entries in a [`crate::Replica`]
///
/// Internally, an author is a [`SigningKey`] which is used to sign entries.
#[derive(Clone, Serialize, Deserialize)]
pub struct Author {
    signing_key: SigningKey,
}
impl Author {
    /// Create a new [`Author`] with a random key.
    pub fn new<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let signing_key = SigningKey::generate(rng);
        Author { signing_key }
    }

    /// Create an [`Author`] from a byte array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        SigningKey::from_bytes(bytes).into()
    }

    /// Returns the [`Author`] byte representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get the [`AuthorPublicKey`] for this author.
    pub fn public_key(&self) -> AuthorPublicKey {
        AuthorPublicKey(self.signing_key.verifying_key())
    }

    /// Get the [`AuthorId`] for this author.
    pub fn id(&self) -> AuthorId {
        AuthorId::from(self.public_key())
    }

    /// Sign a message with this [`Author`] key.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }

    /// Strictly verify a signature on a message with this [`Author`]'s public key.
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.signing_key.verify_strict(msg, signature)
    }
}

/// Identifier for an [`Author`]
///
/// This is the corresponding [`VerifyingKey`] for an author. It is used as an identifier, and can
/// be used to verify [`Signature`]s.
#[derive(Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash, derive_more::From)]
pub struct AuthorPublicKey(VerifyingKey);

impl AuthorPublicKey {
    /// Verify that a signature matches the `msg` bytes and was created with the [`Author`]
    /// that corresponds to this [`AuthorId`].
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.0.verify_strict(msg, signature)
    }

    /// Get the byte representation of this [`AuthorId`].
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Create from a slice of bytes.
    ///
    /// Will return an error if the input bytes do not represent a valid [`ed25519_dalek`]
    /// curve point. Will never fail for a byte array returned from [`Self::as_bytes`].
    /// See [`VerifyingKey::from_bytes`] for details.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignatureError> {
        Ok(AuthorPublicKey(VerifyingKey::from_bytes(bytes)?))
    }
}

/// Namespace key of a [`crate::Replica`].
///
/// Holders of this key can insert new entries into a [`crate::Replica`].
/// Internally, a [`NamespaceSecret`] is a [`SigningKey`] which is used to sign entries.
#[derive(Clone, Serialize, Deserialize)]
pub struct NamespaceSecret {
    signing_key: SigningKey,
}

impl NamespaceSecret {
    /// Create a new [`NamespaceSecret`] with a random key.
    pub fn new<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let signing_key = SigningKey::generate(rng);

        NamespaceSecret { signing_key }
    }

    /// Create a [`NamespaceSecret`] from a byte array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        SigningKey::from_bytes(bytes).into()
    }

    /// Returns the [`NamespaceSecret`] byte representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get the [`NamespacePublicKey`] for this namespace.
    pub fn public_key(&self) -> NamespacePublicKey {
        NamespacePublicKey(self.signing_key.verifying_key())
    }

    /// Get the [`NamespaceId`] for this namespace.
    pub fn id(&self) -> NamespaceId {
        NamespaceId::from(self.public_key())
    }

    /// Sign a message with this [`NamespaceSecret`] key.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }

    /// Strictly verify a signature on a message with this [`NamespaceSecret`]'s public key.
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.signing_key.verify_strict(msg, signature)
    }
}

/// Identifier for a [`NamespaceSecret`]
///
/// This is the corresponding [`VerifyingKey`] for a [`NamespaceSecret`]. It is used as an identifier, and can
/// be used to verify [`Signature`]s.
#[derive(Default, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash, derive_more::From)]
pub struct NamespacePublicKey(VerifyingKey);

impl NamespacePublicKey {
    /// Verify that a signature matches the `msg` bytes and was created with the [`NamespaceSecret`]
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

impl fmt::Display for Author {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base32::fmt(self.to_bytes()))
    }
}

impl fmt::Display for NamespaceSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base32::fmt(self.to_bytes()))
    }
}

impl fmt::Display for AuthorPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base32::fmt(self.as_bytes()))
    }
}

impl fmt::Display for NamespacePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base32::fmt(self.as_bytes()))
    }
}

impl fmt::Display for AuthorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base32::fmt(self.as_bytes()))
    }
}

impl fmt::Display for NamespaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base32::fmt(self.as_bytes()))
    }
}

impl fmt::Debug for NamespaceSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Namespace({})", self)
    }
}

impl fmt::Debug for NamespaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NamespaceId({})", base32::fmt_short(self.0))
    }
}

impl fmt::Debug for AuthorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthorId({})", base32::fmt_short(self.0))
    }
}

impl fmt::Debug for Author {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Author({})", self)
    }
}

impl fmt::Debug for NamespacePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NamespacePublicKey({})", self)
    }
}

impl fmt::Debug for AuthorPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthorPublicKey({})", self)
    }
}

impl FromStr for Author {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_bytes(&base32::parse_array(s)?))
    }
}

impl FromStr for NamespaceSecret {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_bytes(&base32::parse_array(s)?))
    }
}

impl FromStr for AuthorPublicKey {
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

impl From<SigningKey> for Author {
    fn from(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }
}

impl From<SigningKey> for NamespaceSecret {
    fn from(signing_key: SigningKey) -> Self {
        Self { signing_key }
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

impl PartialOrd for AuthorPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AuthorPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl From<NamespaceSecret> for NamespacePublicKey {
    fn from(value: NamespaceSecret) -> Self {
        value.public_key()
    }
}

impl From<Author> for AuthorPublicKey {
    fn from(value: Author) -> Self {
        value.public_key()
    }
}

impl From<&NamespaceSecret> for NamespacePublicKey {
    fn from(value: &NamespaceSecret) -> Self {
        value.public_key()
    }
}

impl From<&Author> for AuthorPublicKey {
    fn from(value: &Author) -> Self {
        value.public_key()
    }
}

/// Utilities for working with byte array identifiers
// TODO: copy-pasted from iroh-gossip/src/proto/util.rs
// Unify into iroh-common crate or similar
pub(super) mod base32 {
    /// Convert to a base32 string
    pub fn fmt(bytes: impl AsRef<[u8]>) -> String {
        let mut text = data_encoding::BASE32_NOPAD.encode(bytes.as_ref());
        text.make_ascii_lowercase();
        text
    }
    /// Convert to a base32 string limited to the first 10 bytes
    pub fn fmt_short(bytes: impl AsRef<[u8]>) -> String {
        let len = bytes.as_ref().len().min(10);
        let mut text = data_encoding::BASE32_NOPAD.encode(&bytes.as_ref()[..len]);
        text.make_ascii_lowercase();
        text
    }
    /// Parse from a base32 string into a byte array
    pub fn parse_array<const N: usize>(input: &str) -> anyhow::Result<[u8; N]> {
        data_encoding::BASE32_NOPAD
            .decode(input.to_ascii_uppercase().as_bytes())?
            .try_into()
            .map_err(|_| ::anyhow::anyhow!("Failed to parse: invalid byte length"))
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

/// [`AuthorPublicKey`] in bytes
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
pub struct AuthorId([u8; 32]);

impl AuthorId {
    /// Convert to byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Convert to byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert into [`AuthorPublicKey`] by fetching from a [`PublicKeyStore`].
    ///
    /// Fails if the bytes of this [`AuthorId`] are not a valid [`ed25519_dalek`] curve point.
    pub fn public_key<S: PublicKeyStore>(
        &self,
        store: &S,
    ) -> Result<AuthorPublicKey, SignatureError> {
        store.author_key(self)
    }

    /// Convert into [`AuthorPublicKey`].
    ///
    /// Fails if the bytes of this [`AuthorId`] are not a valid [`ed25519_dalek`] curve point.
    pub fn into_public_key(&self) -> Result<AuthorPublicKey, SignatureError> {
        AuthorPublicKey::from_bytes(&self.0)
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

    /// Convert into [`NamespacePublicKey`] by fetching from a [`PublicKeyStore`].
    ///
    /// Fails if the bytes of this [`NamespaceId`] are not a valid [`ed25519_dalek`] curve point.
    pub fn public_key<S: PublicKeyStore>(
        &self,
        store: &S,
    ) -> Result<NamespacePublicKey, SignatureError> {
        store.namespace_key(self)
    }

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

impl From<&[u8; 32]> for AuthorId {
    fn from(value: &[u8; 32]) -> Self {
        Self(*value)
    }
}

impl AsRef<[u8]> for NamespaceId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for AuthorId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<AuthorPublicKey> for AuthorId {
    fn from(value: AuthorPublicKey) -> Self {
        Self(*value.as_bytes())
    }
}
impl From<NamespacePublicKey> for NamespaceId {
    fn from(value: NamespacePublicKey) -> Self {
        Self(*value.as_bytes())
    }
}

impl From<&AuthorPublicKey> for AuthorId {
    fn from(value: &AuthorPublicKey) -> Self {
        Self(*value.as_bytes())
    }
}
impl From<&NamespacePublicKey> for NamespaceId {
    fn from(value: &NamespacePublicKey) -> Self {
        Self(*value.as_bytes())
    }
}

impl From<Author> for AuthorId {
    fn from(value: Author) -> Self {
        value.id()
    }
}
impl From<NamespaceSecret> for NamespaceId {
    fn from(value: NamespaceSecret) -> Self {
        value.id()
    }
}

impl TryFrom<NamespaceId> for NamespacePublicKey {
    type Error = SignatureError;
    fn try_from(value: NamespaceId) -> Result<Self, Self::Error> {
        Self::from_bytes(&value.0)
    }
}

impl TryFrom<AuthorId> for AuthorPublicKey {
    type Error = SignatureError;
    fn try_from(value: AuthorId) -> Result<Self, Self::Error> {
        Self::from_bytes(&value.0)
    }
}

impl FromStr for AuthorId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AuthorPublicKey::from_str(s).map(|x| x.into())
    }
}

impl FromStr for NamespaceId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        NamespacePublicKey::from_str(s).map(|x| x.into())
    }
}
