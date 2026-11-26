use core::fmt;
use std::str::FromStr;

use iroh_base::PublicKey;
use iroh_dns::pkarr::SignedPacket;
use n0_error::{e, stack_error};

/// A lightweight `[u8; 32]` wrapper used as a key for caches and database lookups.
///
/// Does not validate that the bytes are a valid public key on construction.
/// If constructed from invalid bytes, methods like `Display` and `to_z32`
/// will panic. In practice, bytes always originate from a validated `PublicKey`
/// or a database that was written from one.
#[derive(derive_more::Into, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Copy)]
pub(crate) struct PublicKeyBytes([u8; 32]);

#[stack_error(derive, add_meta, from_sources)]
pub(crate) enum InvalidPublicKeyBytes {
    #[error("invalid z-base-32 encoding")]
    InvalidEncoding,
    #[error("invalid length, must be 32 bytes")]
    InvalidLength,
}

impl PublicKeyBytes {
    /// Wraps raw bytes without validating they are a valid public key.
    ///
    /// # Safety (logical)
    ///
    /// The caller must ensure the bytes represent a valid Ed25519 public key.
    /// Passing invalid bytes will cause panics in `Display`, `Debug`, and `to_z32`.
    pub(crate) fn new_unchecked(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn from_z32(s: &str) -> Result<Self, InvalidPublicKeyBytes> {
        let pk = PublicKey::from_z32(s).map_err(|_| e!(InvalidPublicKeyBytes::InvalidEncoding))?;
        Ok(Self(*pk.as_bytes()))
    }

    pub(crate) fn to_z32(self) -> String {
        PublicKey::from_bytes(&self.0).expect("valid key").to_z32()
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn from_signed_packet(packet: &SignedPacket) -> Self {
        Self(*packet.public_key().as_bytes())
    }
}

impl fmt::Display for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_z32())
    }
}

impl fmt::Debug for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKeyBytes({})", self.to_z32())
    }
}

impl FromStr for PublicKeyBytes {
    type Err = InvalidPublicKeyBytes;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_z32(s)
    }
}

impl AsRef<[u8; 32]> for PublicKeyBytes {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}
