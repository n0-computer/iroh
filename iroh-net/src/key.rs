//! Cryptographic key handling for `iroh-net`.

mod encryption;

use std::{
    fmt::{Debug, Display},
    hash::Hash,
    str::FromStr,
    sync::Mutex,
    time::Duration,
};

pub use ed25519_dalek::{Signature, PUBLIC_KEY_LENGTH};
use ed25519_dalek::{SignatureError, SigningKey, VerifyingKey};
use once_cell::sync::OnceCell;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use ssh_key::LineEnding;
use ttl_cache::TtlCache;

pub use self::encryption::SharedSecret;
use self::encryption::{public_ed_box, secret_ed_box};

#[derive(Debug)]
struct CryptoKeys {
    verifying_key: VerifyingKey,
    crypto_box: crypto_box::PublicKey,
}

impl CryptoKeys {
    fn new(verifying_key: VerifyingKey) -> Self {
        let crypto_box = public_ed_box(&verifying_key);
        Self {
            verifying_key,
            crypto_box,
        }
    }
}

const KEY_CACHE_TTL: Duration = Duration::from_secs(60);

lazy_static::lazy_static! {
    static ref KEY_CACHE: Mutex<TtlCache<[u8; 32], CryptoKeys>> = Mutex::new(TtlCache::new(100));
}

/// A public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

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
        self.public().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let public = VerifyingKey::deserialize(deserializer)?;
        Ok(public.into())
    }
}

impl PublicKey {
    /// Get this public key as a byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Get or create the crypto keys, and project something out of them.
    fn with_crypto_keys<T>(
        &self,
        f: impl Fn(&CryptoKeys) -> T,
    ) -> std::result::Result<T, SignatureError> {
        let mut state = KEY_CACHE.lock().unwrap();
        Ok(match state.get(&self.0) {
            Some(item) => {
                // cache hit
                f(item)
            }
            None => {
                // cache miss, but we know that they key is valid
                let vk = VerifyingKey::from_bytes(&self.0)?;
                let item = CryptoKeys::new(vk);
                let res = f(&item);
                state.insert(self.0, item, KEY_CACHE_TTL);
                res
            }
        })
    }

    fn public(&self) -> VerifyingKey {
        self.with_crypto_keys(|item| item.verifying_key)
            .expect("key has been checked")
    }

    fn public_crypto_box(&self) -> crypto_box::PublicKey {
        self.with_crypto_keys(|item| item.crypto_box.clone())
            .expect("key has been checked")
    }

    /// Construct a `PublicKey` from a slice of bytes.
    ///
    /// # Warning
    ///
    /// This will return a [`SignatureError`] if the bytes passed into this method do not represent
    /// a valid `ed25519_dalek` curve point. Will never fail for bytes return from [`Self::as_bytes`].
    /// See [`VerifyingKey::from_bytes`] for details.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, SignatureError> {
        let public = VerifyingKey::from_bytes(bytes)?;
        Ok(public.into())
    }

    /// Verify a signature on a message with this secret key's public key.
    ///
    /// # Return
    ///
    /// Returns `Ok(())` if the signature is valid, and `Err` otherwise.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.public().verify_strict(message, signature)
    }

    /// Convert to a base32 string limited to the first 10 bytes for a friendly string
    /// representation of the key.
    pub fn fmt_short(&self) -> String {
        let mut text = data_encoding::BASE32_NOPAD.encode(&self.as_bytes()[..10]);
        text.make_ascii_lowercase();
        text
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = SignatureError;

    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let public = VerifyingKey::try_from(bytes)?;
        Ok(public.into())
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
        let crypto_box = public_ed_box(&verifying_key);
        let item = CryptoKeys {
            verifying_key,
            crypto_box,
        };
        let key = *verifying_key.as_bytes();
        let mut table = KEY_CACHE.lock().unwrap();
        table.insert(key, item, KEY_CACHE_TTL);
        PublicKey(key)
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut text = data_encoding::BASE32_NOPAD.encode(&self.as_bytes()[..10]);
        text.make_ascii_lowercase();
        write!(f, "PublicKey({text})")
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut text = data_encoding::BASE32_NOPAD.encode(self.as_bytes());
        text.make_ascii_lowercase();
        write!(f, "{text}")
    }
}

/// Error when deserialising a [`PublicKey`] or a [`SecretKey`].
#[derive(thiserror::Error, Debug)]
pub enum KeyParsingError {
    /// Error when decoding the base32.
    #[error("decoding: {0}")]
    Base32(#[from] data_encoding::DecodeError),
    /// Error when decoding the public key.
    #[error("key: {0}")]
    Key(#[from] ed25519_dalek::SignatureError),
}

/// Deserialises the [`PublicKey`] from it's base32 encoding.
///
/// [`Display`] is capable of serialising this format.
impl FromStr for PublicKey {
    type Err = KeyParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = data_encoding::BASE32_NOPAD.decode(s.to_ascii_uppercase().as_bytes())?;
        let key = PublicKey::try_from(&bytes[..])?;
        Ok(key)
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
        let mut text = data_encoding::BASE32_NOPAD.encode(&self.to_bytes());
        text.make_ascii_lowercase();
        write!(f, "SecretKey({text})")
    }
}

impl Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut text = data_encoding::BASE32_NOPAD.encode(&self.to_bytes());
        text.make_ascii_lowercase();
        write!(f, "{text}")
    }
}

impl FromStr for SecretKey {
    type Err = KeyParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = data_encoding::BASE32_NOPAD.decode(s.to_ascii_uppercase().as_bytes())?;
        let key = SecretKey::try_from(&bytes[..])?;
        Ok(key)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_key_openssh_roundtrip() {
        let kp = SecretKey::generate();
        let ser = kp.to_openssh().unwrap();
        let de = SecretKey::try_from_openssh(&ser).unwrap();
        assert_eq!(kp.to_bytes(), de.to_bytes());
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
