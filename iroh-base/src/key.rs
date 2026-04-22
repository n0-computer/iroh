//! Cryptographic key handling for `iroh`.

use std::{
    borrow::Borrow,
    cmp::{Ord, PartialOrd},
    fmt::{self, Debug, Display},
    hash::Hash,
    ops::Deref,
    str::FromStr,
};

use curve25519_dalek::edwards::CompressedEdwardsY;
use data_encoding::Encoding;
use data_encoding_macro::new_encoding;
use ed25519_dalek::{SigningKey, VerifyingKey};
use n0_error::{e, ensure, stack_error};
use serde::{Deserialize, Serialize, de, ser};

/// z-base-32 encoding as used by [pkarr](https://pkarr.org) for endpoint id domain names.
const Z_BASE_32: Encoding = new_encoding! {
    symbols: "ybndrfg8ejkmcpqxot1uwisza345h769",
};

/// A public key.
///
/// The key itself is stored as the `CompressedEdwards` y coordinate of the public key
/// It is verified to decompress into a valid key when created.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PublicKey(CompressedEdwardsY);

impl Borrow<[u8; 32]> for PublicKey {
    fn borrow(&self) -> &[u8; 32] {
        self.as_bytes()
    }
}

impl Deref for PublicKey {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

/// The identifier for an endpoint in the (iroh) network.
///
/// Each endpoint in iroh has a unique identifier created as a cryptographic key.  This can be
/// used to globally identify an endpoint.  Since it is also a cryptographic key it is also the
/// mechanism by which all traffic is always encrypted for a specific endpoint only.
///
/// This is equivalent to [`PublicKey`].  By convention we will (or should) use `PublicKey`
/// as type name when performing cryptographic operations, but use `EndpointId` when referencing
/// an endpoint.  E.g.:
///
/// - `encrypt(key: PublicKey)`
/// - `send_to(endpoint: EndpointId)`
pub type EndpointId = PublicKey;

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
    /// The length of an ed25519 `PublicKey`, in bytes.
    pub const LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

    /// Get this public key as a byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Encodes this public key in [z-base-32](https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt) encoding.
    ///
    /// This is the encoding used by [pkarr](https://pkarr.org) domain names.
    pub fn to_z32(&self) -> String {
        Z_BASE_32.encode(self.as_bytes())
    }

    /// Parses a [`PublicKey`] from [z-base-32](https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt) encoding.
    pub fn from_z32(s: &str) -> Result<PublicKey, KeyParsingError> {
        let bytes = Z_BASE_32
            .decode(s.as_bytes())
            .map_err(|_| e!(KeyParsingError::FailedToDecodeBase32))?;
        PublicKey::try_from(bytes.as_slice())
    }

    /// Construct a `PublicKey` from a slice of bytes.
    ///
    /// # Warning
    ///
    /// This will return a [`SignatureError`] if the bytes passed into this method do not represent
    /// a valid `ed25519_dalek` curve point. Will never fail for bytes return from [`Self::as_bytes`].
    /// See [`VerifyingKey::from_bytes`] for details.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, KeyParsingError> {
        let key =
            VerifyingKey::from_bytes(bytes).map_err(|_| e!(KeyParsingError::InvalidKeyData))?;
        let y = CompressedEdwardsY(key.to_bytes());
        Ok(Self(y))
    }

    /// Verify a signature on a message with this secret key's public key.
    ///
    /// # Return
    ///
    /// Returns `Ok(())` if the signature is valid, and `Err` otherwise.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.as_verifying_key()
            .verify_strict(message, &signature.0)
            .map_err(|_| SignatureError::new())
    }

    /// Convert to a hex string limited to the first 5 bytes for a friendly string
    /// representation of the key.
    pub fn fmt_short(&self) -> impl Display + Copy + 'static {
        PublicKeyShort(
            self.0.as_bytes()[0..5]
                .try_into()
                .expect("slice with incorrect length"),
        )
    }

    /// Needed for internal conversions, not part of the stable API.
    #[doc(hidden)]
    pub fn as_verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(self.0.as_bytes()).expect("already verified")
    }

    /// Needed for internal conversions, not part of the stable API.
    #[doc(hidden)]
    pub fn from_verifying_key(key: VerifyingKey) -> Self {
        Self(CompressedEdwardsY(key.to_bytes()))
    }
}

#[derive(Copy, Clone)]
struct PublicKeyShort([u8; 5]);

impl Display for PublicKeyShort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        data_encoding::HEXLOWER.encode_write(&self.0, f)
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = KeyParsingError;

    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let vk = VerifyingKey::try_from(bytes).map_err(|_| e!(KeyParsingError::InvalidKeyData))?;
        Ok(Self(CompressedEdwardsY(vk.to_bytes())))
    }
}

impl TryFrom<&[u8; 32]> for PublicKey {
    type Error = KeyParsingError;

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
#[stack_error(derive, add_meta, from_sources, std_sources)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum KeyParsingError {
    /// The input string could not be decoded as hex.
    #[error("failed to decode hex string")]
    FailedToDecodeHex,
    /// The input string could not be decoded as base32.
    #[error("failed to decode base32 string")]
    FailedToDecodeBase32,
    /// The input has invalid length.
    #[error("invalid length")]
    InvalidLength,
    /// The decoded data is not a valid Ed25591 public key.
    #[error("data is not a valid public key")]
    InvalidKeyData,
}

/// Deserialises the [`PublicKey`] from it's base32 encoding.
///
/// [`Display`] is capable of serialising this format.
impl FromStr for PublicKey {
    type Err = KeyParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = decode_base32_hex(s)?;

        Self::from_bytes(&bytes)
    }
}

/// A secret key.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct SecretKey(SigningKey);

impl Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey(..)")
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
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let secret = SigningKey::deserialize(deserializer)?;
        Ok(Self(secret))
    }
}

impl SecretKey {
    /// The public key of this [`SecretKey`].
    pub fn public(&self) -> PublicKey {
        let key = self.0.verifying_key().to_bytes();
        PublicKey(CompressedEdwardsY(key))
    }

    /// Generate a new [`SecretKey`] with a randomness generator.
    ///
    /// This uses the default random number generator from the `rand` crate.
    /// If you want to customize how the randomness is generated, use
    /// [`Self::from_bytes`] instead and generate the 32 bytes yourself:
    ///
    /// ```rust
    /// # use iroh_base::SecretKey;
    /// # use rand::RngExt;
    /// // Create a random number generator.
    /// let mut rng = rand::rng();
    /// // Use it to generate the 32 bytes that make up a secret key.
    /// let secret_key = SecretKey::from_bytes(&rng.random());
    /// ```
    pub fn generate() -> Self {
        Self::from_bytes(&rand::random())
    }

    /// Sign the given message and return a digital signature
    pub fn sign(&self, msg: &[u8]) -> Signature {
        use ed25519_dalek::Signer;

        let sig = self.0.sign(msg);
        Signature(sig)
    }

    /// Convert this to the bytes representing the secret part.
    /// The public part can always be recovered.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Create a secret key from its byte representation.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let secret = SigningKey::from_bytes(bytes);
        Self(secret)
    }

    /// Needed for internal conversions, not part of the stable API.
    #[doc(hidden)]
    pub fn as_signing_key(&self) -> &SigningKey {
        &self.0
    }
}

impl From<[u8; 32]> for SecretKey {
    fn from(value: [u8; 32]) -> Self {
        Self::from_bytes(&value)
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = KeyParsingError;

    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| e!(KeyParsingError::InvalidLength))?;
        let secret = SigningKey::from_bytes(&bytes);
        Ok(Self(secret))
    }
}

/// Ed25519 signature.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Signature(ed25519_dalek::Signature);

impl Serialize for Signature {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use ser::SerializeTuple;

        let mut seq = serializer.serialize_tuple(Signature::LENGTH)?;

        for byte in self.to_bytes() {
            seq.serialize_element(&byte)?;
        }

        seq.end()
    }
}

// serde lacks support for deserializing arrays larger than 32-bytes
// see: <https://github.com/serde-rs/serde/issues/631>
impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ByteArrayVisitor;

        impl<'de> de::Visitor<'de> for ByteArrayVisitor {
            type Value = [u8; Signature::LENGTH];

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bytestring of length 64")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<[u8; Signature::LENGTH], A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                use de::Error;
                let mut arr = [0u8; Signature::LENGTH];

                for (i, byte) in arr.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| Error::invalid_length(i, &self))?;
                }

                Ok(arr)
            }
        }

        deserializer
            .deserialize_tuple(Signature::LENGTH, ByteArrayVisitor)
            .map(|b| Signature::from_bytes(&b))
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[stack_error(derive, add_meta)]
#[error("Could not parse ed25519 signature")]
pub struct SignatureParsingError;

impl TryFrom<&[u8]> for Signature {
    type Error = SignatureParsingError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let signature =
            ed25519_dalek::Signature::from_slice(bytes).map_err(|_| e!(SignatureParsingError))?;
        Ok(Self(signature))
    }
}

impl Signature {
    /// The length of an ed25519 `Signature`, in bytes.
    pub const LENGTH: usize = ed25519_dalek::Signature::BYTE_SIZE;

    /// Return the inner byte array.
    pub fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.to_bytes()
    }

    /// Parse an Ed25519 signature from a byte slice.
    pub fn from_bytes(bytes: &[u8; Self::LENGTH]) -> Self {
        Self(ed25519_dalek::Signature::from_bytes(bytes))
    }
}

/// Verification of a signature failed.
#[stack_error(derive, add_meta)]
#[error("Invalid signature")]
pub struct SignatureError {}

fn decode_base32_hex(s: &str) -> Result<[u8; 32], KeyParsingError> {
    let mut bytes = [0u8; 32];

    let len = if s.len() == PublicKey::LENGTH * 2 {
        // hex
        data_encoding::HEXLOWER
            .decode_mut(s.as_bytes(), &mut bytes)
            .map_err(|_| e!(KeyParsingError::FailedToDecodeHex))?
    } else {
        let input = s.to_ascii_uppercase();
        let input = input.as_bytes();
        ensure!(
            data_encoding::BASE32_NOPAD.decode_len(input.len()) == Ok(bytes.len()),
            KeyParsingError::InvalidLength
        );
        data_encoding::BASE32_NOPAD
            .decode_mut(input, &mut bytes)
            .map_err(|_| e!(KeyParsingError::FailedToDecodeBase32))?
    };
    ensure!(len == PublicKey::LENGTH, KeyParsingError::InvalidLength);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use data_encoding::HEXLOWER;
    use rand::{RngExt, SeedableRng};

    use super::*;

    #[test]
    fn test_public_key_postcard() {
        let public_key =
            PublicKey::from_str("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
                .unwrap();
        let bytes = postcard::to_stdvec(&public_key).unwrap();
        let expected = HEXLOWER
            .decode(b"ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
            .unwrap();
        assert_eq!(bytes, expected);
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
    fn test_from_str() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let key = SecretKey::from_bytes(&rng.random());
        assert_eq!(
            SecretKey::from_str(&HEXLOWER.encode(&key.to_bytes()))
                .unwrap()
                .to_bytes(),
            key.to_bytes()
        );

        assert_eq!(
            PublicKey::from_str(&key.public().to_string()).unwrap(),
            key.public()
        );
    }

    #[test]
    fn test_regression_parse_endpoint_id_panic() {
        let not_a_endpoint_id = "foobarbaz";
        assert!(PublicKey::from_str(not_a_endpoint_id).is_err());
    }

    #[test]
    fn signature_postcard() {
        let key = SecretKey::generate();
        let signature = key.sign(b"hello world");
        let bytes = postcard::to_stdvec(&signature).unwrap();
        let signature2: Signature = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(signature, signature2);
    }
}
