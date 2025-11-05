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
use ed25519_dalek::{SigningKey, VerifyingKey};
use n0_error::{ensure, stack_error};
use rand_core::CryptoRng;
use serde::{Deserialize, Serialize, de, ser};

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

    /// Construct a `PublicKey` from a slice of bytes.
    ///
    /// # Warning
    ///
    /// This will return a [`SignatureError`] if the bytes passed into this method do not represent
    /// a valid `ed25519_dalek` curve point. Will never fail for bytes return from [`Self::as_bytes`].
    /// See [`VerifyingKey::from_bytes`] for details.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, KeyParsingError> {
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
        self.as_verifying_key()
            .verify_strict(message, &signature.0)
            .map_err(|_| SignatureError::new())
    }

    /// Convert to a hex string limited to the first 5 bytes for a friendly string
    /// representation of the key.
    pub fn fmt_short(&self) -> impl Display + 'static {
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

struct PublicKeyShort([u8; 5]);

impl Display for PublicKeyShort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        data_encoding::BASE32_NOPAD_NOCASE.encode_write(&self.0, f)
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = KeyParsingError;

    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let vk = VerifyingKey::try_from(bytes)?;
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
        let display = self.to_string();
        write!(f, "PublicKey({display})",)
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let short = &self.as_slice()[0..5];
        let rest = &self.as_slice()[5..];

        write!(
            f,
            "{}-{}",
            data_encoding::BASE32_NOPAD_NOCASE.encode(short),
            data_encoding::BASE32_NOPAD_NOCASE.encode(rest)
        )
    }
}

/// Error when deserialising a [`PublicKey`] or a [`SecretKey`].
#[stack_error(derive, add_meta, from_sources, std_sources)]
#[allow(missing_docs)]
pub enum KeyParsingError {
    /// Error when decoding.
    #[error(transparent)]
    Decode(data_encoding::DecodeError),
    /// Error when decoding the public key.
    #[error(transparent)]
    Key(ed25519_dalek::SignatureError),
    /// The encoded information had the wrong length.
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
    /// ```rust
    /// // use the OsRng option for OS depedndent most secure RNG.
    /// let _key = iroh_base::SecretKey::generate(&mut rand::rng());
    /// ```
    pub fn generate<R: CryptoRng + ?Sized>(csprng: &mut R) -> Self {
        let secret = SigningKey::generate(csprng);
        Self(secret)
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
        let secret = SigningKey::try_from(bytes)?;
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

    let res = if s.len() == PublicKey::LENGTH * 2 {
        // hex
        data_encoding::HEXLOWER.decode_mut(s.as_bytes(), &mut bytes)
    } else if s.len() == 53 {
        // the length of base32_nopad for 32bit values are always 52, so 53 is including the short-long separator
        let s = s.replace("-", "");
        data_encoding::BASE32_NOPAD_NOCASE.decode_mut(s.as_bytes(), &mut bytes)
    } else {
        let input = s.to_ascii_uppercase();
        let input = input.as_bytes();
        ensure!(
            data_encoding::BASE32_NOPAD.decode_len(input.len())? == bytes.len(),
            KeyParsingError::DecodeInvalidLength
        );
        data_encoding::BASE32_NOPAD.decode_mut(input, &mut bytes)
    };
    match res {
        Ok(len) => {
            ensure!(
                len == PublicKey::LENGTH,
                KeyParsingError::DecodeInvalidLength
            );
        }
        Err(partial) => return Err(partial.error.into()),
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::HEXLOWER;
    use rand::SeedableRng;

    fn generate_random_id() -> EndpointId {
        let mut rng = rand::rng();
        let key = SecretKey::generate(&mut rng);
        let id = key.public();
        id
    }

    #[test]
    /// Basic requirement for any serialization/deserialization
    fn test_endpoint_id_display_and_parse_roundtrip() {
        for _ in 0..100 {
            let id = generate_random_id();
            let s = id.to_string();
            let parsed = EndpointId::from_str(&s).unwrap();
            assert_eq!(id, parsed, "roundtrip failed for {}", s);
        }
    }

    #[test]
    /// URL is a very common denominator, and thus we should make sure that the
    /// standard formatting is URL-Safe
    fn test_endpoint_id_is_url_safe() {
        let id = generate_random_id();
        let s = id.to_string();
        assert!(
            s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "non-URL-safe char in {}",
            s
        );
    }

    #[test]
    /// To be able to scan the short-form length in tables or logs, having it being fixed length
    /// makes sure its easily formatted and when searching for it in logs, easily identified
    fn test_endpoint_id_have_fixed_short_form_length() {
        for _ in 0..100 {
            let id = generate_random_id();
            let short = id.fmt_short().to_string();
            assert_eq!(short.len(), 8, "short form should be exactly 8 chars");
        }
    }

    #[test]
    /// Common addressing schemes (IPv4, IPv6, UUID, MAC addr) are usually visually distinct
    /// and thus easily identified by developers and sysadmins when encountered in config files or APIs
    fn test_enpoint_id_is_visually_distinct() {
        let id = generate_random_id();
        let string = id.to_string();
        let mut split = string.split("-");

        assert_eq!(
            2,
            split.clone().count(),
            "it should be visibly distinct by consisting of exactly two parts separated by an \'-\' char"
        );
        assert_eq!(
            split.next().unwrap().len(),
            8,
            "short form should be exactly 8 chars"
        );
        assert_eq!(
            split.next().unwrap().len(),
            44,
            "the second part form should be exactly 44 chars"
        );
    }

    #[test]
    /// almost any addressing scheme ends up in a DNS call one way or another, to make it easier, we should
    /// make sure that the default serialization is DNS label compatible and can fit in a subdomain
    fn test_endpoint_id_dns_label_compatibility() {
        for _ in 0..100 {
            let id = generate_random_id();
            let s = id.to_string();
            assert!(
                s.len() < 64,
                "Serialized form too long to fit in a subdomain ({} chars): {}",
                s.len(),
                s
            );
        }
    }

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
        let key = SecretKey::generate(&mut rng);
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
        let key = SecretKey::generate(&mut rand::rng());
        let signature = key.sign(b"hello world");
        let bytes = postcard::to_stdvec(&signature).unwrap();
        let signature2: Signature = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(signature, signature2);
    }
}
