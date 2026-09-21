//! Versioned IDs, explicit algorithm registration, and pluggable local signers.

use std::{
    collections::BTreeSet,
    fmt,
    io::{Read, Write},
    path::Path,
    str::FromStr,
    sync::Arc,
};

use data_encoding::HEXLOWER;
use iroh_base::{PublicKey, SecretKey};
use rustls::{SignatureScheme, pki_types::SubjectPublicKeyInfoDer, sign::SigningKey};
use sha2::{Digest, Sha384};

use super::Error;

const DOMAIN: &[u8] = b"iroh identity prototype v1\0";
const PREFIX: &str = "iroh-pid1-";
const MAX_KEY: usize = 8192;
const MAX_PRIVATE: usize = 16384;
const PRIVATE_MAGIC: &[u8] = b"IRID\x01";

/// Secret credential bytes which are redacted in debug output and zeroed on drop.
pub struct SecretBytes(zeroize::Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Borrow the sensitive encoding for application-controlled persistence.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(REDACTED)")
    }
}

/// Legacy key or a version-one SHA-384 commitment. Values are prototype-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PeerId {
    /// An existing Ed25519 endpoint ID, with unchanged key semantics.
    Legacy(PublicKey),
    /// SHA-384 commitment using the experimental version-one format.
    V1([u8; 48]),
}

impl PeerId {
    /// New-envelope encoding. Legacy serialization itself is left untouched.
    pub fn to_bytes(self) -> Vec<u8> {
        match self {
            Self::Legacy(key) => [vec![0], key.as_bytes().to_vec()].concat(),
            Self::V1(digest) => [vec![1, 1], digest.to_vec()].concat(),
        }
    }

    /// Decode a complete new envelope; trailing bytes and unknown tags fail.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        match bytes {
            [0, key @ ..] if key.len() == 32 => Ok(Self::Legacy(
                PublicKey::try_from(key).map_err(|_| Error::Encoding)?,
            )),
            [1, 1, digest @ ..] if digest.len() == 48 => {
                Ok(Self::V1(digest.try_into().map_err(|_| Error::Encoding)?))
            }
            _ => Err(Error::Encoding),
        }
    }
}

impl From<PublicKey> for PeerId {
    fn from(key: PublicKey) -> Self {
        Self::Legacy(key)
    }
}

impl TryFrom<PeerId> for PublicKey {
    type Error = Error;

    fn try_from(id: PeerId) -> Result<Self, Error> {
        match id {
            PeerId::Legacy(key) => Ok(key),
            PeerId::V1(_) => Err(Error::Encoding),
        }
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Legacy(key) => key.fmt(f),
            Self::V1(_) => write!(f, "{PREFIX}{}", HEXLOWER.encode(&self.to_bytes())),
        }
    }
}

impl FromStr for PeerId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Error> {
        if let Some(encoded) = value.strip_prefix(PREFIX) {
            // Bound allocation and reject alternate text spellings of new IDs.
            if encoded.len() != 100 {
                return Err(Error::Encoding);
            }
            let bytes = HEXLOWER
                .decode(encoded.as_bytes())
                .map_err(|_| Error::Encoding)?;
            match Self::from_bytes(&bytes)? {
                id @ Self::V1(_) => Ok(id),
                _ => Err(Error::Encoding),
            }
        } else {
            value.parse().map(Self::Legacy).map_err(|_| Error::Encoding)
        }
    }
}

/// A TLS-capable algorithm adapter. Implementations are trusted configuration.
/// IDs and their canonical encodings must agree between peers.
pub trait IdentityAlgorithm: fmt::Debug + Send + Sync {
    /// Portable suite number; experimental assignments must agree between peers.
    fn suite_id(&self) -> u16;
    /// TLS signature scheme used by this adapter.
    fn tls_scheme(&self) -> SignatureScheme;
    /// Validate a canonical SPKI and return the canonical raw public key.
    fn public_key<'a>(&self, spki: &'a [u8]) -> Result<&'a [u8], Error>;
    /// Verify the exact TLS signature input, without additional hashing/context.
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error>;
}

/// Prototype built-in suites. Numbers are local experimental assignments.
#[derive(Clone, Copy, Debug)]
pub enum BuiltinAlgorithm {
    /// The existing strict Ed25519 identity signature scheme (suite 1).
    Ed25519,
    /// ML-DSA-65 signatures (experimental suite 2).
    MlDsa65,
}

impl IdentityAlgorithm for BuiltinAlgorithm {
    /// Portable suite number; experimental assignments must agree between peers.
    fn suite_id(&self) -> u16 {
        match self {
            Self::Ed25519 => 1,
            Self::MlDsa65 => 2,
        }
    }

    /// TLS signature scheme used by this adapter.
    fn tls_scheme(&self) -> SignatureScheme {
        match self {
            Self::Ed25519 => SignatureScheme::ED25519,
            Self::MlDsa65 => SignatureScheme::ML_DSA_65,
        }
    }

    fn public_key<'a>(&self, spki: &'a [u8]) -> Result<&'a [u8], Error> {
        let (alg, len) = match self {
            Self::Ed25519 => (rustls::pki_types::alg_id::ED25519, 32),
            Self::MlDsa65 => (rustls::pki_types::alg_id::ML_DSA_65, 1952),
        };
        if spki.len() > MAX_KEY || spki.len() < len {
            return Err(Error::PublicIdentity);
        }
        let key = &spki[spki.len() - len..];
        // Re-encoding enforces exact DER, algorithm parameters, and key length.
        if rustls::sign::public_key_to_spki(&alg, key).as_ref() != spki {
            return Err(Error::PublicIdentity);
        }
        if matches!(self, Self::Ed25519) {
            PublicKey::try_from(key).map_err(|_| Error::PublicIdentity)?;
        }
        Ok(key)
    }

    fn verify(&self, key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
        if matches!(self, Self::Ed25519) {
            return PublicKey::try_from(key)
                .map_err(|_| Error::PublicIdentity)?
                .verify(
                    message,
                    &iroh_base::Signature::try_from(signature)
                        .map_err(|_| Error::PublicIdentity)?,
                )
                .map_err(|_| Error::Tls(rustls::Error::DecryptError));
        }
        let algorithm: &dyn aws_lc_rs::signature::VerificationAlgorithm = match self {
            Self::Ed25519 => &aws_lc_rs::signature::ED25519,
            Self::MlDsa65 => &aws_lc_rs::signature::ML_DSA_65,
        };
        let expected_len = match self {
            Self::Ed25519 => 64,
            Self::MlDsa65 => 3309,
        };
        if signature.len() != expected_len {
            return Err(Error::Tls(rustls::Error::DecryptError));
        }
        aws_lc_rs::signature::UnparsedPublicKey::new(algorithm, key)
            .verify(message, signature)
            .map_err(|_| Error::Tls(rustls::Error::DecryptError))
    }
}

/// Registered algorithm capabilities and a remote-peer suite allowlist.
///
/// Local credentials must use a registered adapter, but need not use a suite in
/// the remote allowlist. Choosing a local credential does not permit that suite
/// for remote peers. No fallback is performed.
#[derive(Clone, Debug)]
pub struct Registry {
    algorithms: Vec<Arc<dyn IdentityAlgorithm>>,
    allowed_remote: Vec<u16>,
    allowed_peers: Option<BTreeSet<PeerId>>,
}

/// Explicit remote signature and identity acceptance policy.
///
/// Local signing credentials are independent of this policy. Without an identity
/// allowlist, any peer using an allowed suite may authenticate; applications must
/// then authorize its identity before processing privileged requests.
#[derive(Clone, Debug)]
pub struct RemotePolicy {
    suites: Vec<u16>,
    peers: Option<BTreeSet<PeerId>>,
}

impl RemotePolicy {
    /// Permit only these remote signature suites. Empty means deny all peers.
    pub fn new(suites: impl IntoIterator<Item = u16>) -> Self {
        Self {
            suites: suites.into_iter().collect(),
            peers: None,
        }
    }

    /// Additionally require the authenticated identity to appear in this list.
    pub fn allow_peers(mut self, peers: impl IntoIterator<Item = PeerId>) -> Self {
        self.peers = Some(peers.into_iter().collect());
        self
    }
}

impl Registry {
    /// Register trusted adapters and a separate allowlist for remote authentication.
    /// Local credentials can use any registered adapter.
    pub fn new(
        algorithms: Vec<Arc<dyn IdentityAlgorithm>>,
        allowed: Vec<u16>,
    ) -> Result<Self, Error> {
        for (i, alg) in algorithms.iter().enumerate() {
            if alg.suite_id() == 0 {
                return Err(Error::Suite);
            }
            if algorithms[..i].iter().any(|other| {
                other.suite_id() == alg.suite_id() || other.tls_scheme() == alg.tls_scheme()
            }) {
                return Err(Error::DuplicateSuite);
            }
            // Suite 1 / ED25519 is reserved for legacy identity semantics.
            if (alg.suite_id() == 1) != (alg.tls_scheme() == SignatureScheme::ED25519) {
                return Err(Error::Suite);
            }
        }
        if allowed.is_empty()
            || allowed
                .iter()
                .any(|id| !algorithms.iter().any(|a| a.suite_id() == *id))
        {
            return Err(Error::Suite);
        }
        Ok(Self {
            algorithms,
            allowed_remote: allowed,
            allowed_peers: None,
        })
    }

    /// Register Ed25519 (1) and ML-DSA-65 (2), allowing the supplied suites for peers.
    pub fn builtins(allowed: Vec<u16>) -> Result<Self, Error> {
        Self::new(
            vec![
                Arc::new(BuiltinAlgorithm::Ed25519),
                Arc::new(BuiltinAlgorithm::MlDsa65),
            ],
            allowed,
        )
    }

    /// Replace remote acceptance policy, retaining all registered local capabilities.
    pub fn with_remote_policy(mut self, policy: RemotePolicy) -> Result<Self, Error> {
        if policy
            .suites
            .iter()
            .any(|id| !self.algorithms.iter().any(|a| a.suite_id() == *id))
        {
            return Err(Error::Suite);
        }
        self.allowed_remote = policy.suites;
        self.allowed_peers = policy.peers;
        Ok(self)
    }

    /// TLS signature schemes permitted for remote authentication.
    pub fn schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms
            .iter()
            .filter(|a| self.allowed_remote.contains(&a.suite_id()))
            .map(|a| a.tls_scheme())
            .collect()
    }

    /// Validate a canonical public SPKI against remote policy and derive its identity.
    /// This does not verify possession of the private key.
    pub fn identify(&self, spki: &[u8]) -> Result<PeerId, Error> {
        let id = identify_key(self.remote_algorithm(spki)?, spki)?;
        if self
            .allowed_peers
            .as_ref()
            .is_some_and(|peers| !peers.contains(&id))
        {
            return Err(Error::Unauthorized);
        }
        Ok(id)
    }

    // Local validation must retain adapter, encoding and identity checks without
    // treating our own credential as a remote peer subject to the allowlist.
    /// Validate a local key against registered capabilities, independently of remote policy.
    pub fn identify_local(&self, spki: &[u8]) -> Result<PeerId, Error> {
        identify_key(self.registered_algorithm(spki)?, spki)
    }

    fn remote_algorithm(&self, spki: &[u8]) -> Result<&dyn IdentityAlgorithm, Error> {
        let algorithm = self.registered_algorithm(spki)?;
        if !self.allowed_remote.contains(&algorithm.suite_id()) {
            return Err(Error::Suite);
        }
        Ok(algorithm)
    }

    fn registered_algorithm(&self, spki: &[u8]) -> Result<&dyn IdentityAlgorithm, Error> {
        if spki.len() > MAX_KEY {
            return Err(Error::PublicIdentity);
        }
        let mut matches = self
            .algorithms
            .iter()
            .filter(|a| a.public_key(spki).is_ok());
        let algorithm = matches.next().ok_or(Error::PublicIdentity)?;
        if matches.next().is_some() {
            return Err(Error::PublicIdentity);
        }
        Ok(algorithm.as_ref())
    }

    /// Verify a TLS signature and enforce remote suite and identity policy.
    pub fn verify(
        &self,
        spki: &[u8],
        message: &[u8],
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<(), Error> {
        if signature.signature().len() > 16384 {
            return Err(Error::PublicIdentity);
        }
        let algorithm = self.remote_algorithm(spki)?;
        if algorithm.tls_scheme() != signature.scheme {
            return Err(Error::Suite);
        }
        self.identify(spki)?;
        algorithm.verify(algorithm.public_key(spki)?, message, signature.signature())
    }

    /// Verify a protocol-specific signature and return the authenticated identity.
    /// The caller must construct an unambiguous, context-bound signing input.
    pub fn verify_proof(
        &self,
        spki: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<PeerId, Error> {
        if signature.len() > 16384 {
            return Err(Error::PublicIdentity);
        }
        let id = self.identify(spki)?;
        let algorithm = self.remote_algorithm(spki)?;
        algorithm.verify(algorithm.public_key(spki)?, message, signature)?;
        Ok(id)
    }
}

fn identify_key(alg: &dyn IdentityAlgorithm, spki: &[u8]) -> Result<PeerId, Error> {
    let key = alg.public_key(spki)?;
    if alg.suite_id() == 1 {
        // Independently enforce legacy semantics, including the Ed25519 OID.
        BuiltinAlgorithm::Ed25519.public_key(spki)?;
        return Ok(PeerId::Legacy(
            PublicKey::try_from(key).map_err(|_| Error::PublicIdentity)?,
        ));
    }
    Ok(commitment(alg.suite_id(), key))
}

fn commitment(suite: u16, key: &[u8]) -> PeerId {
    let mut hash = Sha384::new();
    hash.update(DOMAIN);
    hash.update([1]);
    hash.update(suite.to_be_bytes());
    hash.update((key.len() as u32).to_be_bytes());
    hash.update(key);
    PeerId::V1(hash.finalize().into())
}

/// A non-exporting signer interface, using rustls' existing signing abstraction.
#[derive(Clone)]
pub struct LocalIdentity {
    key: Arc<dyn SigningKey>,
    spki: SubjectPublicKeyInfoDer<'static>,
    id: PeerId,
    suite: u16,
    scheme: SignatureScheme,
    private: Option<Arc<zeroize::Zeroizing<Vec<u8>>>>,
}

impl fmt::Debug for LocalIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalIdentity")
            .field("id", &self.id)
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

impl LocalIdentity {
    /// Construct an identity from a signer that need not export its private key.
    ///
    /// The key must match a registered adapter. The registry's remote-peer
    /// allowlist does not constrain the local signing credential.
    pub fn new(key: Arc<dyn SigningKey>, registry: &Registry) -> Result<Self, Error> {
        let spki = key.public_key().ok_or(Error::Signer)?.into_owned();
        let algorithm = registry.registered_algorithm(spki.as_ref())?;
        let id = identify_key(algorithm, spki.as_ref())?;
        if key.choose_scheme(&[algorithm.tls_scheme()]).is_none() {
            return Err(Error::Signer);
        }
        Ok(Self {
            key,
            spki,
            id,
            suite: algorithm.suite_id(),
            scheme: algorithm.tls_scheme(),
            private: None,
        })
    }

    /// Return the identity derived from the signing key.
    pub fn id(&self) -> PeerId {
        self.id
    }

    /// The canonical public identity material presented by this credential.
    pub fn public_key(&self) -> SubjectPublicKeyInfoDer<'_> {
        SubjectPublicKeyInfoDer::from(self.spki.as_ref())
    }

    /// Construct a raw-public-key TLS credential without exporting secret bytes.
    pub fn certified_key(&self) -> Arc<rustls::sign::CertifiedKey> {
        Arc::new(rustls::sign::CertifiedKey::new(
            vec![rustls::pki_types::CertificateDer::from(self.spki.to_vec())],
            self.key.clone(),
        ))
    }

    /// Sign an exact protocol signing input. Context separation is the caller's responsibility.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self
            .key
            .choose_scheme(&[self.scheme])
            .ok_or(Error::Signer)?
            .sign(message)?)
    }

    /// Encode a generated/imported credential. Custom non-exporting signers return an error.
    pub fn to_bytes(&self) -> Result<SecretBytes, Error> {
        let private = self.private.as_ref().ok_or(Error::NonExportable)?;
        let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(11 + private.len()));
        bytes.extend_from_slice(PRIVATE_MAGIC);
        bytes.extend_from_slice(&self.suite.to_be_bytes());
        bytes.extend_from_slice(&(private.len() as u32).to_be_bytes());
        bytes.extend_from_slice(private);
        Ok(SecretBytes(bytes))
    }

    /// Import an exact, bounded version-one private credential encoding.
    pub fn from_bytes(bytes: &[u8], registry: &Registry) -> Result<Self, Error> {
        if bytes.len() < 11 || bytes.len() > MAX_PRIVATE || &bytes[..5] != PRIVATE_MAGIC {
            return Err(Error::Encoding);
        }
        let suite = u16::from_be_bytes(bytes[5..7].try_into().map_err(|_| Error::Encoding)?);
        let len =
            u32::from_be_bytes(bytes[7..11].try_into().map_err(|_| Error::Encoding)?) as usize;
        if len != bytes.len() - 11 {
            return Err(Error::Encoding);
        }
        let key = &bytes[11..];
        match suite {
            1 if key.len() == 32 => Self::ed25519(
                SecretKey::try_from(key).map_err(|_| Error::Encoding)?,
                registry,
            ),
            2 => Self::from_ml_dsa65_pkcs8(key, registry),
            _ => Err(Error::Suite),
        }
    }

    fn from_ml_dsa65_pkcs8(bytes: &[u8], registry: &Registry) -> Result<Self, Error> {
        let der = rustls::pki_types::PrivatePkcs8KeyDer::from(bytes.to_vec());
        let key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&der.into())?;
        let mut identity = Self::new(key, registry)?;
        if identity.suite != 2 {
            return Err(Error::Suite);
        }
        BuiltinAlgorithm::MlDsa65.public_key(identity.spki.as_ref())?;
        identity.private = Some(Arc::new(zeroize::Zeroizing::new(bytes.to_vec())));
        Ok(identity)
    }

    /// Create a new key file, refusing to overwrite existing files. Unix permissions are 0600.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        let bytes = self.to_bytes()?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(bytes.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    /// Load a bounded private credential file. Unix group/other permissions must be absent.
    pub fn load(path: impl AsRef<Path>, registry: &Registry) -> Result<Self, Error> {
        let file = std::fs::File::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if file.metadata()?.permissions().mode() & 0o077 != 0 {
                return Err(Error::InsecureKeyFile);
            }
        }
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        file.take((MAX_PRIVATE + 1) as u64)
            .read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes, registry)
    }

    /// Adapt an existing iroh secret key without changing its endpoint ID.
    pub fn ed25519(key: SecretKey, registry: &Registry) -> Result<Self, Error> {
        let private = zeroize::Zeroizing::new(key.to_bytes().to_vec());
        let mut identity = Self::new(Arc::new(EdSigner(key)), registry)?;
        identity.private = Some(Arc::new(private));
        Ok(identity)
    }

    /// Generate a fresh ML-DSA-65 identity using the system randomness source.
    pub fn generate_ml_dsa65(registry: &Registry) -> Result<Self, Error> {
        let pair =
            aws_lc_rs::signature::PqdsaKeyPair::generate(&aws_lc_rs::signature::ML_DSA_65_SIGNING)
                .map_err(|_| Error::KeyGeneration)?;
        let document = pair.to_pkcs8v1().map_err(|_| Error::KeyGeneration)?;
        Self::from_ml_dsa65_pkcs8(document.as_ref(), registry)
    }
}

#[derive(Clone, Debug)]
struct EdSigner(SecretKey);

impl SigningKey for EdSigner {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        offered
            .contains(&SignatureScheme::ED25519)
            .then(|| Box::new(self.clone()) as Box<dyn rustls::sign::Signer>)
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(rustls::sign::public_key_to_spki(
            &rustls::pki_types::alg_id::ED25519,
            self.0.public().as_bytes(),
        ))
    }
}

impl rustls::sign::Signer for EdSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}
