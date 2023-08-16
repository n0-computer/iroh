//! Keys used in iroh-sync

use std::{cmp::Ordering, fmt, str::FromStr};

use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

/// Author key to insert entries in a [`crate::Replica`]
///
/// Internally, an author is a [`SigningKey`] which is used to sign entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Author {
    signing_key: SigningKey,
}
impl Author {
    /// Create a new author with a random key.
    pub fn new<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let signing_key = SigningKey::generate(rng);
        Author { signing_key }
    }

    /// Create an author from a byte array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        SigningKey::from_bytes(bytes).into()
    }

    /// Returns the Author byte representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Returns the AuthorId byte representation.
    pub fn id_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the [`AuthorId`] for this author.
    pub fn id(&self) -> AuthorId {
        AuthorId(self.signing_key.verifying_key())
    }

    /// Sign a message with this author key.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }

    /// Strictly verify a signature on a message with this author's public key.
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
    /// Verify that a signature matches the `msg` bytes and was created with this the [`Author`]
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
    pub fn from_bytes(bytes: &[u8; 32]) -> anyhow::Result<Self> {
        Ok(AuthorId(VerifyingKey::from_bytes(bytes)?))
    }
}

/// Namespace key of a [`crate::Replica`].
///
/// Holders of this key can insert new entries into a [`crate::Replica`].
/// Internally, a namespace is a [`SigningKey`] which is used to sign entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Namespace {
    signing_key: SigningKey,
}

impl Namespace {
    /// Create a new namespace with a random key.
    pub fn new<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let signing_key = SigningKey::generate(rng);

        Namespace { signing_key }
    }

    /// Create a namespace from a byte array.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        SigningKey::from_bytes(bytes).into()
    }

    /// Returns the namespace byte representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Returns the [`NamespaceId`] byte representation.
    pub fn id_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the [`NamespaceId`] for this namespace.
    pub fn id(&self) -> NamespaceId {
        NamespaceId(self.signing_key.verifying_key())
    }

    /// Sign a message with this namespace key.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing_key.sign(msg)
    }

    /// Strictly verify a signature on a message with this namespaces's public key.
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.signing_key.verify_strict(msg, signature)
    }
}

/// Identifier for a [`Namespace`]
///
/// This is the corresponding [`VerifyingKey`] for an author. It is used as an identifier, and can
/// be used to verify [`Signature`]s.
#[derive(Default, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct NamespaceId(VerifyingKey);

impl NamespaceId {
    /// Verify that a signature matches the `msg` bytes and was created with this the [`Author`]
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
    pub fn from_bytes(bytes: &[u8; 32]) -> anyhow::Result<Self> {
        Ok(NamespaceId(VerifyingKey::from_bytes(bytes)?))
    }
}

impl fmt::Display for Author {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Author({})", hex::encode(self.signing_key.to_bytes()))
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Namespace({})", hex::encode(self.signing_key.to_bytes()))
    }
}

impl fmt::Display for AuthorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_bytes()))
    }
}

impl fmt::Display for NamespaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_bytes()))
    }
}

impl fmt::Debug for NamespaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NamespaceId({})", hex::encode(self.0.as_bytes()))
    }
}

impl fmt::Debug for AuthorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthorId({})", hex::encode(self.0.as_bytes()))
    }
}

impl FromStr for Author {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let signing_key: [u8; 32] = hex::decode(s).map_err(|_| ())?.try_into().map_err(|_| ())?;
        let signing_key = SigningKey::from_bytes(&signing_key);

        Ok(Author { signing_key })
    }
}

impl FromStr for Namespace {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let signing_key: [u8; 32] = hex::decode(s).map_err(|_| ())?.try_into().map_err(|_| ())?;
        let signing_key = SigningKey::from_bytes(&signing_key);

        Ok(Namespace { signing_key })
    }
}

impl FromStr for AuthorId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let verifying_key: [u8; 32] = hex::decode(s)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("failed to parse: invalid key length"))?;
        let verifying_key = VerifyingKey::from_bytes(&verifying_key)?;
        Ok(AuthorId(verifying_key))
    }
}

impl FromStr for NamespaceId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let verifying_key: [u8; 32] = hex::decode(s)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("failed to parse: invalid key length"))?;
        let verifying_key = VerifyingKey::from_bytes(&verifying_key)?;
        Ok(NamespaceId(verifying_key))
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
