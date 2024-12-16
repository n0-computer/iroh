//! Cryptographic key handling for `iroh`.

mod encryption;

use std::{
    cmp::{Ord, PartialOrd},
    fmt::{Debug, Display},
    hash::Hash,
    str::FromStr,
};

use curve25519_dalek::edwards::CompressedEdwardsY;
pub use ed25519_dalek::Signature;
use ed25519_dalek::{SignatureError, SigningKey, VerifyingKey};
use once_cell::sync::OnceCell;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use ssh_key::LineEnding;

pub use self::encryption::SharedSecret;
use self::encryption::{public_ed_box, secret_ed_box};

/// A public key.
///
/// The key itself is stored as the `CompressedEdwards` y coordinate of the public key
/// It is verified to decompress into a valid key when created.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PublicKey(CompressedEdwardsY);

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The identifier for a node in the (iroh) network.
///
/// Each node in iroh has a unique identifier created as a cryptographic key.  This can be
/// used to globally identify a node.  Since it is also a cryptographic key it is also the
/// mechanism by which all traffic is always encrypted for a specific node only.
///
/// This is equivalent to [`PublicKey`].  By convention we will (or should) use `PublicKey`
/// as type name when performing cryptographic operations, but use `NodeId` when referencing
/// a node.  E.g.:
///
/// - `encrypt(key: PublicKey)`
/// - `send_to(node: NodeId)`
pub type NodeId = PublicKey;

impl Hash for PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            self.0.as_bytes().serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_str(&s).map_err(serde::de::Error::custom)
        } else {
            let data: [u8; 32] = serde::Deserialize::deserialize(deserializer)?;
            Self::try_from(data.as_ref()).map_err(serde::de::Error::custom)
        }
    }
}

impl PublicKey {
    /// Get this public key as a byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    fn public(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(self.0.as_bytes()).expect("already verified")
    }

    fn public_crypto_box(&self) -> crypto_box::PublicKey {
        public_ed_box(&self.public())
    }

    /// Construct a `PublicKey` from a slice of bytes.
    ///
    /// # Warning
    ///
    /// This will return a [`SignatureError`] if the bytes passed into this method do not represent
    /// a valid `ed25519_dalek` curve point. Will never fail for bytes return from [`Self::as_bytes`].
    /// See [`VerifyingKey::from_bytes`] for details.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignatureError> {
        let key = VerifyingKey::from_bytes(bytes)?;
        let y = CompressedEdwardsY(key.to_bytes());
        Ok(Self(y))
    }

    /// Verify a signature on a message with this secret key's public key.
    ///
    /// # Return
    ///
    /// Returns `Ok(())` if the signature is valid, and `Err` otherwise.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.public().verify_strict(message, signature)
    }

    /// Convert to a hex string limited to the first 5 bytes for a friendly string
    /// representation of the key.
    pub fn fmt_short(&self) -> String {
        data_encoding::HEXLOWER.encode(&self.as_bytes()[..5])
    }

    pub const LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = SignatureError;

    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let vk = VerifyingKey::try_from(bytes)?;
        Ok(Self(CompressedEdwardsY(vk.to_bytes())))
    }
}

impl TryFrom<&[u8; 32]> for PublicKey {
    type Error = SignatureError;

    #[inline]
    fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<VerifyingKey> for PublicKey {
    fn from(verifying_key: VerifyingKey) -> Self {
        let key = verifying_key.to_bytes();
        PublicKey(CompressedEdwardsY(key))
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PublicKey({})",
            data_encoding::HEXLOWER.encode(self.as_bytes())
        )
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", data_encoding::HEXLOWER.encode(self.as_bytes()))
    }
}

/// Error when deserialising a [`PublicKey`] or a [`SecretKey`].
#[derive(thiserror::Error, Debug)]
pub enum KeyParsingError {
    /// Error when decoding.
    #[error("decoding: {0}")]
    Decode(#[from] data_encoding::DecodeError),
    /// Error when decoding the public key.
    #[error("key: {0}")]
    Key(#[from] ed25519_dalek::SignatureError),
    #[error("invalid length")]
    DecodeInvalidLength,
}

/// Deserialises the [`PublicKey`] from it's base32 encoding.
///
/// [`Display`] is capable of serialising this format.
impl FromStr for PublicKey {
    type Err = KeyParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = decode_base32_hex(s)?;

        Ok(Self::from_bytes(&bytes)?)
    }
}

/// A secret key.
#[derive(Clone)]
pub struct SecretKey {
    secret: SigningKey,
    secret_crypto_box: OnceCell<crypto_box::SecretKey>,
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey(..)")
    }
}

impl Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO: revivew for security
        write!(
            f,
            "{}",
            data_encoding::HEXLOWER.encode(self.secret.as_bytes())
        )
    }
}

impl FromStr for SecretKey {
    type Err = KeyParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = decode_base32_hex(s)?;
        Ok(SecretKey::from(bytes))
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.secret.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let secret = SigningKey::deserialize(deserializer)?;
        Ok(secret.into())
    }
}

impl SecretKey {
    /// The public key of this [`SecretKey`].
    pub fn public(&self) -> PublicKey {
        self.secret.verifying_key().into()
    }

    /// Generate a new [`SecretKey`] with the default randomness generator.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        Self::generate_with_rng(&mut rng)
    }

    /// Generate a new [`SecretKey`] with a randomness generator.
    pub fn generate_with_rng<R: CryptoRngCore + ?Sized>(csprng: &mut R) -> Self {
        let secret = SigningKey::generate(csprng);

        Self {
            secret,
            secret_crypto_box: OnceCell::default(),
        }
    }

    /// Serialise this key to OpenSSH format.
    pub fn to_openssh(&self) -> ssh_key::Result<zeroize::Zeroizing<String>> {
        let ckey = ssh_key::private::Ed25519Keypair {
            public: self.secret.verifying_key().into(),
            private: self.secret.clone().into(),
        };
        ssh_key::private::PrivateKey::from(ckey).to_openssh(LineEnding::default())
    }

    /// Deserialise this key from OpenSSH format.
    pub fn try_from_openssh<T: AsRef<[u8]>>(data: T) -> anyhow::Result<Self> {
        let ser_key = ssh_key::private::PrivateKey::from_openssh(data)?;
        match ser_key.key_data() {
            ssh_key::private::KeypairData::Ed25519(kp) => Ok(SecretKey {
                secret: kp.private.clone().into(),
                secret_crypto_box: OnceCell::default(),
            }),
            _ => anyhow::bail!("invalid key format"),
        }
    }

    /// Sign the given message and return a digital signature
    pub fn sign(&self, msg: &[u8]) -> Signature {
        use ed25519_dalek::Signer;

        self.secret.sign(msg)
    }

    /// Convert this to the bytes representing the secret part.
    /// The public part can always be recovered.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Create a secret key from its byte representation.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let secret = SigningKey::from_bytes(bytes);
        secret.into()
    }

    fn secret_crypto_box(&self) -> &crypto_box::SecretKey {
        self.secret_crypto_box
            .get_or_init(|| secret_ed_box(&self.secret))
    }
}

impl From<SigningKey> for SecretKey {
    fn from(secret: SigningKey) -> Self {
        SecretKey {
            secret,
            secret_crypto_box: OnceCell::default(),
        }
    }
}

impl From<[u8; 32]> for SecretKey {
    fn from(value: [u8; 32]) -> Self {
        Self::from_bytes(&value)
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = SignatureError;

    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let secret = SigningKey::try_from(bytes)?;
        Ok(secret.into())
    }
}

fn decode_base32_hex(s: &str) -> Result<[u8; 32], KeyParsingError> {
    let mut bytes = [0u8; 32];

    let res = if s.len() == PublicKey::LENGTH * 2 {
        // hex
        data_encoding::HEXLOWER.decode_mut(s.as_bytes(), &mut bytes)
    } else {
        data_encoding::BASE32_NOPAD.decode_mut(s.to_ascii_uppercase().as_bytes(), &mut bytes)
    };
    match res {
        Ok(len) => {
            if len != PublicKey::LENGTH {
                return Err(KeyParsingError::DecodeInvalidLength);
            }
        }
        Err(partial) => return Err(partial.error.into()),
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use iroh_test::{assert_eq_hex, hexdump::parse_hexdump};

    use super::*;

    #[test]
    fn test_public_key_postcard() {
        let public_key =
            PublicKey::from_str("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
                .unwrap();
        let bytes = postcard::to_stdvec(&public_key).unwrap();
        let expected =
            parse_hexdump("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
                .unwrap();
        assert_eq_hex!(bytes, expected);
    }

    #[test]
    fn test_secret_key_openssh_roundtrip() {
        let kp = SecretKey::generate();
        let ser = kp.to_openssh().unwrap();
        let de = SecretKey::try_from_openssh(&ser).unwrap();
        assert_eq!(kp.to_bytes(), de.to_bytes());
    }

    #[test]
    fn public_key_postcard() {
        let key = PublicKey::from_bytes(&[0; 32]).unwrap();
        let bytes = postcard::to_stdvec(&key).unwrap();
        let key2: PublicKey = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn public_key_json() {
        let key = PublicKey::from_bytes(&[0; 32]).unwrap();
        let bytes = serde_json::to_string(&key).unwrap();
        let key2: PublicKey = serde_json::from_str(&bytes).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_display_from_str() {
        let key = SecretKey::generate();
        assert_eq!(
            SecretKey::from_str(&key.to_string()).unwrap().to_bytes(),
            key.to_bytes()
        );

        assert_eq!(
            PublicKey::from_str(&key.public().to_string()).unwrap(),
            key.public()
        );
    }
}
