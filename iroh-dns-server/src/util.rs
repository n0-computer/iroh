use core::fmt;
use std::{collections::BTreeMap, str::FromStr};

use domain::base::{Message, iana::Rtype};
use n0_error::{AnyError, StdResultExt, e, stack_error};
use pkarr::SignedPacket;

#[derive(
    derive_more::From, derive_more::Into, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Copy,
)]
pub struct PublicKeyBytes([u8; 32]);

#[stack_error(derive, add_meta, from_sources)]
pub enum InvalidPublicKeyBytes {
    #[error(transparent)]
    Encoding {
        #[error(std_err)]
        source: z32::Z32Error,
    },
    #[error("invalid length, must be 32 bytes")]
    InvalidLength,
}

impl PublicKeyBytes {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_z32(s: &str) -> Result<Self, InvalidPublicKeyBytes> {
        let bytes = z32::decode(s.as_bytes())?;
        let bytes = TryInto::<[u8; 32]>::try_into(&bytes[..])
            .map_err(|_| e!(InvalidPublicKeyBytes::InvalidLength))?;
        Ok(Self(bytes))
    }

    pub fn to_z32(self) -> String {
        z32::encode(&self.0)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_signed_packet(packet: &SignedPacket) -> Self {
        Self(packet.public_key().to_bytes())
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

impl From<pkarr::PublicKey> for PublicKeyBytes {
    fn from(value: pkarr::PublicKey) -> Self {
        Self(value.to_bytes())
    }
}

impl TryFrom<PublicKeyBytes> for pkarr::PublicKey {
    type Error = AnyError;
    fn try_from(value: PublicKeyBytes) -> Result<Self, Self::Error> {
        pkarr::PublicKey::try_from(&value.0).anyerr()
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

/// A key for looking up records in a zone: (name_without_zone, record_type).
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct ZoneRecordKey {
    /// The DNS name relative to the zone (without the z32 public key label).
    /// Empty string means the zone apex.
    pub name: String,
    /// The DNS record type.
    pub rtype: Rtype,
}

/// A single DNS record stored in a zone.
#[derive(Debug, Clone)]
pub struct ZoneRecord {
    /// TTL in seconds.
    pub ttl: u32,
    /// The record data as a display string (e.g. for TXT: `"relay=https://example.com/"`)
    pub data: String,
}

/// A collection of DNS records for a pkarr zone, keyed by (name, record_type).
#[derive(Debug, Clone)]
pub struct PkarrZone {
    pub records: BTreeMap<ZoneRecordKey, Vec<ZoneRecord>>,
}

impl PkarrZone {
    /// Look up records by name and type.
    pub fn lookup(&self, name: &str, rtype: Rtype) -> Option<&[ZoneRecord]> {
        let key = ZoneRecordKey {
            name: name.to_string(),
            rtype,
        };
        self.records.get(&key).map(|v| v.as_slice())
    }
}

/// Parse a signed packet into zone records, stripping the z32 public key label.
/// Returns the z32 label and the zone records.
pub fn signed_packet_to_zone(signed_packet: &SignedPacket) -> Result<PkarrZone, std::io::Error> {
    let pubkey_z32 = signed_packet.public_key().to_z32();
    let encoded = signed_packet.encoded_packet();
    let message = Message::from_octets(encoded.to_vec()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid DNS message in signed packet",
        )
    })?;

    let answer = message
        .answer()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    let mut records: BTreeMap<ZoneRecordKey, Vec<ZoneRecord>> = BTreeMap::new();

    for record in answer {
        let record = match record {
            Ok(r) => r,
            Err(_) => continue,
        };
        let rtype = record.rtype();

        // Skip SOA and NS records
        if rtype == Rtype::SOA || rtype == Rtype::NS {
            continue;
        }

        let owner = record.owner().to_string();
        let name_without_zone = strip_zone_suffix(&owner, &pubkey_z32);
        let ttl = record.ttl().as_secs() as u32;

        let data = if rtype == Rtype::TXT {
            // For TXT records, extract raw content without zone-file quoting.
            // AllRecordData::to_string() wraps TXT data in quotes (zone-file format),
            // so we extract raw bytes from character strings instead.
            match record.to_record::<domain::rdata::Txt<&[u8]>>() {
                Ok(Some(txt_record)) => {
                    let mut bytes = Vec::new();
                    for cs in txt_record.data().iter() {
                        bytes.extend_from_slice(cs.as_ref());
                    }
                    match String::from_utf8(bytes) {
                        Ok(s) => s,
                        Err(_) => continue,
                    }
                }
                _ => continue,
            }
        } else {
            match record.to_any_record::<domain::rdata::AllRecordData<&[u8], domain::base::name::ParsedName<&[u8]>>>() {
                Ok(any) => any.data().to_string(),
                Err(_) => continue,
            }
        };

        let key = ZoneRecordKey {
            name: name_without_zone,
            rtype,
        };
        records
            .entry(key)
            .or_default()
            .push(ZoneRecord { ttl, data });
    }

    Ok(PkarrZone { records })
}

/// Strip the z32 zone suffix from a DNS name.
/// e.g., "_iroh.abc123." -> "_iroh", "abc123." -> "" (root)
fn strip_zone_suffix(full_name: &str, zone_label: &str) -> String {
    let full_name = full_name.trim_end_matches('.');
    let zone_label = zone_label.trim_end_matches('.');

    if full_name == zone_label {
        return String::new();
    }

    // Try to strip ".zone_label" suffix
    let suffix = format!(".{zone_label}");
    if let Some(prefix) = full_name.strip_suffix(&suffix) {
        return prefix.to_string();
    }

    // Fallback: return the full name
    full_name.to_string()
}
