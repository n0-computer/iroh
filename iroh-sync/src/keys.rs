//! Keys used in iroh-sync

use std::{cmp::Ordering, fmt, str::FromStr};

use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

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

    /// Get the [`AuthorId`] for this author.
    pub fn id(&self) -> AuthorId {
        AuthorId(self.signing_key.verifying_key())
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
#[derive(Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct AuthorId(VerifyingKey);

impl AuthorId {
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
        Ok(AuthorId(VerifyingKey::from_bytes(bytes)?))
    }
}

/// Namespace key of a [`crate::Replica`].
///
/// Holders of this key can insert new entries into a [`crate::Replica`].
/// Internally, a [`Namespace`] is a [`SigningKey`] which is used to sign entries.
#[derive(Clone, Serialize, Deserialize)]
pub struct Namespace {
    signing_key: SigningKey,
}

impl Namespace {
    /// Create a new [`Namespace`] with a random key.
    pub fn new<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let signing_key = SigningKey::generate(rng);

        Namespace { signing_key }
    }

    /// Create a [`Namespace`] from a byte array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        SigningKey::from_bytes(bytes).into()
    }

    /// Returns the [`Namespace`] byte representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Get the [`NamespaceId`] for this namespace.
    pub fn id(&self) -> NamespaceId {
        NamespaceId(self.signing_key.verifying_key())
    }

    /// Sign a message with this [`Namespace`] key.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }

    /// Strictly verify a signature on a message with this [`Namespace`]'s public key.
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.signing_key.verify_strict(msg, signature)
    }
}

/// Identifier for a [`Namespace`]
///
/// This is the corresponding [`VerifyingKey`] for a [`Namespace`]. It is used as an identifier, and can
/// be used to verify [`Signature`]s.
#[derive(Default, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct NamespaceId(VerifyingKey);

impl NamespaceId {
    /// Verify that a signature matches the `msg` bytes and was created with the [`Namespace`]
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
        Ok(NamespaceId(VerifyingKey::from_bytes(bytes)?))
    }
}

impl fmt::Display for Author {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base32::fmt(self.to_bytes()))
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base32::fmt(self.to_bytes()))
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

impl fmt::Debug for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Namespace({})", self)
    }
}

impl fmt::Debug for Author {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Author({})", self)
    }
}

impl fmt::Debug for NamespaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NamespaceId({})", self)
    }
}

impl fmt::Debug for AuthorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthorId({})", self)
    }
}

impl FromStr for Author {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_bytes(&base32::parse_array(s)?))
    }
}

impl FromStr for Namespace {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_bytes(&base32::parse_array(s)?))
    }
}

impl FromStr for AuthorId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(&base32::parse_array(s)?).map_err(Into::into)
    }
}

impl FromStr for NamespaceId {
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

impl From<SigningKey> for Namespace {
    fn from(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }
}

impl PartialOrd for NamespaceId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NamespaceId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl PartialOrd for AuthorId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AuthorId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl From<Namespace> for NamespaceId {
    fn from(value: Namespace) -> Self {
        value.id()
    }
}

impl From<Author> for AuthorId {
    fn from(value: Author) -> Self {
        value.id()
    }
}

impl From<&Namespace> for NamespaceId {
    fn from(value: &Namespace) -> Self {
        value.id()
    }
}

impl From<&Author> for AuthorId {
    fn from(value: &Author) -> Self {
        value.id()
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
    /// Parse from a base32 string into a byte array
    pub fn parse_array<const N: usize>(input: &str) -> anyhow::Result<[u8; N]> {
        data_encoding::BASE32_NOPAD
            .decode(input.to_ascii_uppercase().as_bytes())?
            .try_into()
            .map_err(|_| ::anyhow::anyhow!("Failed to parse: invalid byte length"))
    }
}
