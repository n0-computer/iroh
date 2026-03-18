//! Pkarr signed packet encoding.
//!
//! Implements the [pkarr] signed DNS packet format: `<32 pubkey><64 sig><8 timestamp><DNS packet>`.
//!
//! [pkarr]: https://pkarr.org

use std::{
    fmt::{self, Debug, Display, Formatter},
    sync::LazyLock,
};

use iroh_base::{PublicKey, SecretKey, Signature};
use simple_dns::{CLASS, Name, Packet, ResourceRecord, rdata::RData};

/// z-base-32 encoding as used by pkarr.
static Z_BASE_32: LazyLock<data_encoding::Encoding> = LazyLock::new(|| {
    let mut spec = data_encoding::Specification::new();
    spec.symbols.push_str("ybndrfg8ejkmcpqxot1uwisza345h769");
    spec.encoding().expect("valid z-base-32 spec")
});

/// Maximum size of the encoded DNS packet within a signed packet.
const MAX_DNS_PACKET_SIZE: usize = 1000;

/// Total header size: 32 (pubkey) + 64 (signature) + 8 (timestamp).
const HEADER_SIZE: usize = 104;

/// Maximum total size of a serialized signed packet.
pub const MAX_SIGNED_PACKET_SIZE: usize = HEADER_SIZE + MAX_DNS_PACKET_SIZE;

/// Encode bytes as z-base-32.
pub(crate) fn z32_encode(bytes: &[u8]) -> String {
    Z_BASE_32.encode(bytes)
}

/// Decode a z-base-32 string to bytes.
pub(crate) fn z32_decode(s: &str) -> Result<Vec<u8>, data_encoding::DecodeError> {
    Z_BASE_32.decode(s.as_bytes())
}

/// Encode a public key as z-base-32 (the pkarr addressing format).
pub(crate) fn public_key_to_z32(key: &PublicKey) -> String {
    z32_encode(key.as_bytes())
}

/// Parse a public key from a z-base-32 string.
pub(crate) fn public_key_from_z32(s: &str) -> Result<PublicKey, Z32PublicKeyError> {
    let bytes = z32_decode(s)?;
    Ok(PublicKey::try_from(bytes.as_slice())?)
}

/// Error parsing a public key from z-base-32.
#[derive(Debug)]
pub enum Z32PublicKeyError {
    /// Invalid z-base-32 encoding.
    Decode(data_encoding::DecodeError),
    /// Valid z-base-32 but not a valid public key.
    Key(iroh_base::KeyParsingError),
}

impl fmt::Display for Z32PublicKeyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "invalid z-base-32: {e}"),
            Self::Key(e) => write!(f, "invalid public key: {e}"),
        }
    }
}

impl std::error::Error for Z32PublicKeyError {}

impl From<data_encoding::DecodeError> for Z32PublicKeyError {
    fn from(e: data_encoding::DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl From<iroh_base::KeyParsingError> for Z32PublicKeyError {
    fn from(e: iroh_base::KeyParsingError) -> Self {
        Self::Key(e)
    }
}

/// A signed DNS packet in the pkarr format.
///
/// Wire format: `<32 bytes pubkey><64 bytes signature><8 bytes BE timestamp><DNS wire format>`
///
/// The DNS packet must be at most 1000 bytes. Total max size is 1104 bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedPacket {
    bytes: Vec<u8>,
}

impl SignedPacket {
    /// Maximum total byte size of a signed packet.
    pub const MAX_BYTES: usize = MAX_SIGNED_PACKET_SIZE;

    /// Create a signed packet containing TXT records under a single name.
    ///
    /// This is the common case: multiple TXT values under the same DNS name (e.g. `"_iroh"`).
    pub fn from_txt_strings(
        secret_key: &SecretKey,
        name: &str,
        values: impl IntoIterator<Item = impl AsRef<str>>,
        ttl: u32,
    ) -> Result<SignedPacket, SignedPacketBuildError> {
        let public_key = secret_key.public();
        let origin = public_key_to_z32(&public_key);
        let normalized = normalize_name(&origin, name.to_string());
        let dns_name = Name::new_unchecked(&normalized).into_owned();
        let mut packet = Packet::new_reply(0);

        for value in values {
            let mut txt = simple_dns::rdata::TXT::new();
            txt.add_string(value.as_ref())
                .map_err(|e| SignedPacketBuildError::DnsError(e.to_string()))?;
            packet.answers.push(ResourceRecord::new(
                dns_name.clone(),
                CLASS::IN,
                ttl,
                RData::TXT(txt.into_owned()),
            ));
        }

        let encoded_packet = packet
            .build_bytes_vec_compressed()
            .map_err(|e| SignedPacketBuildError::DnsError(e.to_string()))?;

        if encoded_packet.len() > MAX_DNS_PACKET_SIZE {
            return Err(SignedPacketBuildError::PacketTooLarge(encoded_packet.len()));
        }

        let timestamp = timestamp_now();
        let signature = secret_key.sign(&signable(timestamp, &encoded_packet));

        let mut bytes = Vec::with_capacity(HEADER_SIZE + encoded_packet.len());
        bytes.extend_from_slice(public_key.as_bytes());
        bytes.extend_from_slice(&signature.to_bytes());
        bytes.extend_from_slice(&timestamp.to_be_bytes());
        bytes.extend_from_slice(&encoded_packet);

        Ok(SignedPacket { bytes })
    }

    /// Parse and verify a signed packet from its wire representation.
    pub fn from_bytes(bytes: &[u8]) -> Result<SignedPacket, SignedPacketVerifyError> {
        if bytes.len() < HEADER_SIZE {
            return Err(SignedPacketVerifyError::TooShort(bytes.len()));
        }
        if bytes.len() > MAX_SIGNED_PACKET_SIZE {
            return Err(SignedPacketVerifyError::TooLarge(bytes.len()));
        }

        let public_key = PublicKey::try_from(&bytes[..32])
            .map_err(|e| SignedPacketVerifyError::InvalidKey(e.to_string()))?;
        let signature =
            Signature::from_bytes(bytes[32..96].try_into().expect("64 bytes for signature"));
        let timestamp =
            u64::from_be_bytes(bytes[96..104].try_into().expect("8 bytes for timestamp"));
        let encoded_packet = &bytes[104..];

        public_key
            .verify(&signable(timestamp, encoded_packet), &signature)
            .map_err(|e| SignedPacketVerifyError::SignatureError(e.to_string()))?;

        Packet::parse(encoded_packet)
            .map_err(|e| SignedPacketVerifyError::DnsError(e.to_string()))?;

        Ok(SignedPacket {
            bytes: bytes.to_vec(),
        })
    }

    /// Create from a public key and relay payload (signature + timestamp + dns).
    pub fn from_relay_payload(
        public_key: &PublicKey,
        payload: &[u8],
    ) -> Result<SignedPacket, SignedPacketVerifyError> {
        let mut bytes = Vec::with_capacity(32 + payload.len());
        bytes.extend_from_slice(public_key.as_bytes());
        bytes.extend_from_slice(payload);
        Self::from_bytes(&bytes)
    }

    /// Parse a signed packet without verifying the signature.
    ///
    /// Still validates minimum length and DNS parsing.
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Result<SignedPacket, SignedPacketVerifyError> {
        if bytes.len() < HEADER_SIZE {
            return Err(SignedPacketVerifyError::TooShort(bytes.len()));
        }
        if bytes.len() > MAX_SIGNED_PACKET_SIZE {
            return Err(SignedPacketVerifyError::TooLarge(bytes.len()));
        }
        Packet::parse(&bytes[104..])
            .map_err(|e| SignedPacketVerifyError::DnsError(e.to_string()))?;
        Ok(SignedPacket {
            bytes: bytes.to_vec(),
        })
    }

    /// Return the full serialized bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the relay payload (everything after the public key).
    pub fn to_relay_payload(&self) -> Vec<u8> {
        self.bytes[32..].to_vec()
    }

    /// Return the public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::try_from(&self.bytes[..32]).expect("valid public key in SignedPacket")
    }

    /// Return the signature.
    pub fn signature(&self) -> Signature {
        Signature::from_bytes(
            self.bytes[32..96]
                .try_into()
                .expect("64 bytes for signature"),
        )
    }

    /// Return the timestamp in microseconds since UNIX epoch.
    pub fn timestamp(&self) -> u64 {
        u64::from_be_bytes(
            self.bytes[96..104]
                .try_into()
                .expect("8 bytes for timestamp"),
        )
    }

    /// Return the encoded DNS packet bytes.
    pub fn encoded_packet(&self) -> &[u8] {
        &self.bytes[104..]
    }

    /// Iterate over TXT records under a specific DNS name.
    ///
    /// The `name` is normalized relative to the signer's z-base-32 public key.
    /// Returns the TXT string values.
    pub fn txt_records(&self, name: &str) -> Vec<String> {
        let origin = public_key_to_z32(&self.public_key());
        let normalized = normalize_name(&origin, name.to_string());
        let Ok(packet) = Packet::parse(self.encoded_packet()) else {
            return Vec::new();
        };
        let Ok(zone) = Name::new(&origin) else {
            return Vec::new();
        };
        packet
            .answers
            .iter()
            .filter_map(|rr| match &rr.rdata {
                RData::TXT(txt) => {
                    // Check if the name matches, either directly or via zone-relative comparison
                    let rr_name = rr.name.to_string();
                    if rr_name == normalized {
                        String::try_from(txt.clone()).ok()
                    } else if let Some(relative) = rr.name.without(&zone) {
                        if relative.to_string() == name {
                            String::try_from(txt.clone()).ok()
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .collect()
    }

    /// Iterate over all TXT records, yielding `(name_relative_to_origin, value)` pairs.
    ///
    /// The name is the part before the z-base-32 public key zone.
    pub fn all_txt_records(&self) -> Vec<(String, String)> {
        let origin = public_key_to_z32(&self.public_key());
        let Ok(packet) = Packet::parse(self.encoded_packet()) else {
            return Vec::new();
        };
        let Ok(zone) = Name::new(&origin) else {
            return Vec::new();
        };
        packet
            .answers
            .iter()
            .filter_map(|rr| match &rr.rdata {
                RData::TXT(txt) => {
                    let relative_name = rr
                        .name
                        .without(&zone)
                        .map(|n| n.to_string())
                        .unwrap_or_default();
                    let value = String::try_from(txt.clone()).ok()?;
                    Some((relative_name, value))
                }
                _ => None,
            })
            .collect()
    }

    /// Return whether this packet is more recent than another.
    pub fn more_recent_than(&self, other: &SignedPacket) -> bool {
        if self.timestamp() == other.timestamp() {
            self.encoded_packet() > other.encoded_packet()
        } else {
            self.timestamp() > other.timestamp()
        }
    }
}

impl Debug for SignedPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedPacket")
            .field("public_key", &self.public_key())
            .field("timestamp", &self.timestamp())
            .finish()
    }
}

impl Display for SignedPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "SignedPacket ({}):",
            public_key_to_z32(&self.public_key())
        )?;
        writeln!(f, "  timestamp: {}", &self.timestamp())?;
        for (name, value) in self.all_txt_records() {
            writeln!(f, "  {name} TXT \"{value}\"")?;
        }
        Ok(())
    }
}

/// Construct the signable bytes per BEP_0044.
fn signable(timestamp: u64, v: &[u8]) -> Vec<u8> {
    let mut signable = format!("3:seqi{}e1:v{}:", timestamp, v.len()).into_bytes();
    signable.extend(v);
    signable
}

/// Normalize a DNS name relative to the pkarr origin (z-base-32 public key).
fn normalize_name(origin: &str, name: String) -> String {
    let name = if name.ends_with('.') {
        name[..name.len() - 1].to_string()
    } else {
        name
    };

    let parts: Vec<&str> = name.split('.').collect();
    let last = *parts.last().unwrap_or(&"");

    if last == origin {
        return name;
    }

    if last == "@" || last.is_empty() {
        return origin.to_string();
    }

    format!("{name}.{origin}")
}

fn timestamp_now() -> u64 {
    use n0_future::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time before UNIX epoch")
        .as_micros() as u64
}

/// Error building a signed packet.
#[derive(Debug)]
#[allow(missing_docs)]
pub enum SignedPacketBuildError {
    PacketTooLarge(usize),
    DnsError(String),
}

impl fmt::Display for SignedPacketBuildError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooLarge(n) => {
                write!(
                    f,
                    "DNS packet too large: {n} bytes (max {MAX_DNS_PACKET_SIZE})"
                )
            }
            Self::DnsError(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SignedPacketBuildError {}

/// Error verifying a signed packet.
#[derive(Debug)]
#[allow(missing_docs)]
pub enum SignedPacketVerifyError {
    TooShort(usize),
    TooLarge(usize),
    SignatureError(String),
    DnsError(String),
    InvalidKey(String),
}

impl fmt::Display for SignedPacketVerifyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => {
                write!(f, "Signed packet too short: {n} bytes (min {HEADER_SIZE})")
            }
            Self::TooLarge(n) => write!(
                f,
                "Signed packet too large: {n} bytes (max {MAX_SIGNED_PACKET_SIZE})"
            ),
            Self::SignatureError(e) => write!(f, "Invalid signature: {e}"),
            Self::DnsError(e) => write!(f, "{e}"),
            Self::InvalidKey(e) => write!(f, "Invalid public key: {e}"),
        }
    }
}

impl std::error::Error for SignedPacketVerifyError {}
