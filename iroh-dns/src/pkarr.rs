//! Pkarr signed packet encoding.
//!
//! Implements the [pkarr] signed DNS packet format: `<32 pubkey><64 sig><8 timestamp><DNS packet>`.
//!
//! [pkarr]: https://pkarr.org

use std::{
    fmt::{self, Display, Formatter},
    sync::atomic::{AtomicU64, Ordering},
};

use iroh_base::{PublicKey, SecretKey, Signature};
use n0_error::{e, stack_error};
use simple_dns::{CLASS, Name, Packet, ResourceRecord, rdata::RData};

use crate::EndpointIdExt;

/// Maximum size of the encoded DNS packet within a signed packet.
const MAX_DNS_PACKET_SIZE: usize = 1000;

/// Total header size: 32 (pubkey) + 64 (signature) + 8 (timestamp).
const HEADER_SIZE: usize = 104;

/// Maximum total size of a serialized signed packet.
pub const MAX_SIGNED_PACKET_SIZE: usize = HEADER_SIZE + MAX_DNS_PACKET_SIZE;

/// A signed DNS packet in the pkarr format.
///
/// Wire format: `<32 bytes pubkey><64 bytes signature><8 bytes BE timestamp><DNS wire format>`
///
/// The DNS packet must be at most 1000 bytes. Total max size is 1104 bytes.
#[derive(Clone, PartialEq, Eq, derive_more::Debug)]
#[debug("SignedPacket {{ public_key: {}, timestamp: {:?} }}", self.public_key(), self.timestamp())]
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
        let origin = public_key.to_z32();
        let normalized = normalize_name(&origin, name.to_string());
        let dns_name = Name::new_unchecked(&normalized).into_owned();
        let mut packet = Packet::new_reply(0);

        for value in values {
            let mut txt = simple_dns::rdata::TXT::new();
            txt.add_string(value.as_ref())
                .map_err(|e| e!(SignedPacketBuildError::DnsError, e))?;
            packet.answers.push(ResourceRecord::new(
                dns_name.clone(),
                CLASS::IN,
                ttl,
                RData::TXT(txt.into_owned()),
            ));
        }

        let encoded_packet = packet
            .build_bytes_vec_compressed()
            .map_err(|e| e!(SignedPacketBuildError::DnsError, e))?;

        if encoded_packet.len() > MAX_DNS_PACKET_SIZE {
            return Err(e!(SignedPacketBuildError::PacketTooLarge {
                len: encoded_packet.len()
            }));
        }

        let timestamp = Timestamp::now();
        let signature = secret_key.sign(&signable(timestamp.as_micros(), &encoded_packet));

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
            return Err(e!(SignedPacketVerifyError::TooShort { len: bytes.len() }));
        }
        if bytes.len() > MAX_SIGNED_PACKET_SIZE {
            return Err(e!(SignedPacketVerifyError::TooLarge { len: bytes.len() }));
        }

        let public_key = PublicKey::try_from(&bytes[..32])
            .map_err(|e| e!(SignedPacketVerifyError::InvalidKey, e))?;
        let signature =
            Signature::from_bytes(bytes[32..96].try_into().expect("64 bytes for signature"));
        let timestamp =
            u64::from_be_bytes(bytes[96..104].try_into().expect("8 bytes for timestamp"));
        let encoded_packet = &bytes[104..];

        public_key
            .verify(&signable(timestamp, encoded_packet), &signature)
            .map_err(|e| e!(SignedPacketVerifyError::SignatureError, e))?;

        Packet::parse(encoded_packet).map_err(|e| e!(SignedPacketVerifyError::DnsError, e))?;

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
            return Err(e!(SignedPacketVerifyError::TooShort { len: bytes.len() }));
        }
        if bytes.len() > MAX_SIGNED_PACKET_SIZE {
            return Err(e!(SignedPacketVerifyError::TooLarge { len: bytes.len() }));
        }
        Packet::parse(&bytes[104..]).map_err(|e| e!(SignedPacketVerifyError::DnsError, e))?;
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

    /// Return the timestamp.
    pub fn timestamp(&self) -> Timestamp {
        Timestamp::from_be_bytes(
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
        let origin = self.public_key().to_z32();
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
        let origin = self.public_key().to_z32();
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

    /// Reconstruct a signed packet from its raw parts without verifying the signature.
    ///
    /// This is useful for reconstructing a packet from storage or DHT mutable items
    /// where the components are stored separately.
    pub fn from_parts_unchecked(
        public_key: &[u8],
        signature: &[u8],
        timestamp: Timestamp,
        encoded_packet: &[u8],
    ) -> Result<Self, SignedPacketVerifyError> {
        let mut bytes = Vec::with_capacity(HEADER_SIZE + encoded_packet.len());
        bytes.extend_from_slice(public_key);
        bytes.extend_from_slice(signature);
        bytes.extend_from_slice(&timestamp.to_be_bytes());
        bytes.extend_from_slice(encoded_packet);
        Self::from_bytes_unchecked(&bytes)
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

impl Display for SignedPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "SignedPacket ({}):", self.public_key().to_z32())?;
        writeln!(f, "  timestamp: {}µs", self.timestamp().as_micros())?;
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

/// A pkarr timestamp in microseconds since the UNIX epoch.
///
/// Used as the `seq` field in BEP_0044 DHT mutable items. Per the spec, a new
/// publish must have a strictly higher timestamp than the previous one, or DHT
/// nodes will reject the update.
///
/// [`Timestamp::now`] is guaranteed to be strictly monotonic: it will never
/// return the same value twice and will never go backward, even if the system
/// clock is corrected by NTP. This is achieved by tracking the last returned
/// value and ensuring each call returns at least `last + 1`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, derive_more::Debug)]
#[debug("Timestamp({}µs)", _0)]
pub struct Timestamp(u64);

/// Tracks the last timestamp returned by [`Timestamp::now`] to ensure monotonicity.
static LAST_TIMESTAMP: AtomicU64 = AtomicU64::new(0);

impl Timestamp {
    /// Returns a strictly monotonic timestamp.
    ///
    /// Guaranteed to return a value greater than any previous call, even if the
    /// system clock jumps backward (e.g. due to NTP correction).
    pub fn now() -> Self {
        use n0_future::time::SystemTime;
        let micros = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_micros() as u64;
        // Ensure strictly monotonic: if the clock went backward or two calls
        // land in the same microsecond, we increment from the last value.
        let mut last = LAST_TIMESTAMP.load(Ordering::Relaxed);
        loop {
            let next = micros.max(last + 1);
            match LAST_TIMESTAMP.compare_exchange_weak(
                last,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Self(next),
                Err(actual) => last = actual,
            }
        }
    }

    /// Creates a timestamp from a raw microseconds value.
    pub fn from_micros(micros: u64) -> Self {
        Self(micros)
    }

    /// Returns the raw microseconds value.
    pub fn as_micros(self) -> u64 {
        self.0
    }

    /// Returns the big-endian byte representation.
    pub fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Parses from big-endian bytes.
    pub fn from_be_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }
}

/// Error building a signed packet.
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum SignedPacketBuildError {
    #[error("DNS packet too large: {len} bytes (max {MAX_DNS_PACKET_SIZE})")]
    PacketTooLarge { len: usize },
    #[error("DNS encoding error")]
    DnsError {
        #[error(std_err)]
        source: simple_dns::SimpleDnsError,
    },
}

/// Error verifying a signed packet.
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum SignedPacketVerifyError {
    #[error("Signed packet too short: {len} bytes (min {HEADER_SIZE})")]
    TooShort { len: usize },
    #[error("Signed packet too large: {len} bytes (max {MAX_SIGNED_PACKET_SIZE})")]
    TooLarge { len: usize },
    #[error("Invalid signature")]
    SignatureError {
        #[error(std_err)]
        source: iroh_base::SignatureError,
    },
    #[error("DNS decoding error")]
    DnsError {
        #[error(std_err)]
        source: simple_dns::SimpleDnsError,
    },
    #[error("Invalid public key")]
    InvalidKey { source: iroh_base::KeyParsingError },
}
