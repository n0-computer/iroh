use core::fmt;
use std::{
    collections::{btree_map, BTreeMap},
    str::FromStr,
    sync::Arc,
};

use anyhow::{anyhow, Result};
use hickory_proto::{
    op::Message,
    rr::{
        domain::{IntoLabel, Label},
        Name, Record, RecordSet, RecordType, RrKey,
    },
    serialize::binary::BinDecodable,
};
use pkarr::SignedPacket;

#[derive(
    derive_more::From, derive_more::Into, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Copy,
)]
pub struct PublicKeyBytes([u8; 32]);

impl PublicKeyBytes {
    pub fn from_z32(s: &str) -> Result<Self> {
        let bytes = z32::decode(s.as_bytes())?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("invalid length"))?;
        Ok(Self(bytes))
    }

    pub fn to_z32(&self) -> String {
        z32::encode(&self.0)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
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
    type Error = anyhow::Error;
    fn try_from(value: PublicKeyBytes) -> Result<Self, Self::Error> {
        pkarr::PublicKey::try_from(value.0).map_err(anyhow::Error::from)
    }
}

impl FromStr for PublicKeyBytes {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_z32(s)
    }
}

impl AsRef<[u8; 32]> for PublicKeyBytes {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

pub fn signed_packet_to_hickory_message(signed_packet: &SignedPacket) -> Result<Message> {
    let encoded = signed_packet.encoded_packet();
    let message = Message::from_bytes(&encoded)?;
    Ok(message)
}

pub fn signed_packet_to_hickory_records_without_origin(
    signed_packet: &SignedPacket,
    filter: impl Fn(&Record) -> bool,
) -> Result<(Label, BTreeMap<RrKey, Arc<RecordSet>>)> {
    let common_zone = Label::from_utf8(&signed_packet.public_key().to_z32())?;
    let mut message = signed_packet_to_hickory_message(signed_packet)?;
    let answers = message.take_answers();
    let mut output: BTreeMap<RrKey, Arc<RecordSet>> = BTreeMap::new();
    for mut record in answers.into_iter() {
        // disallow SOA and NS records
        if matches!(record.record_type(), RecordType::SOA | RecordType::NS) {
            continue;
        }
        // expect the z32 encoded pubkey as root name
        let name = record.name();
        if name.num_labels() < 1 {
            continue;
        }
        let zone = name.iter().last().unwrap().into_label()?;
        if zone != common_zone {
            continue;
        }
        if !filter(&record) {
            continue;
        }

        let name_without_zone =
            Name::from_labels(name.iter().take(name.num_labels() as usize - 1))?;
        record.set_name(name_without_zone);

        let rrkey = RrKey::new(record.name().into(), record.record_type());
        match output.entry(rrkey) {
            btree_map::Entry::Vacant(e) => {
                let set: RecordSet = record.into();
                e.insert(Arc::new(set));
            }
            btree_map::Entry::Occupied(mut e) => {
                let set = e.get_mut();
                let serial = set.serial();
                // safe because we just created the arc and are sync iterating
                Arc::get_mut(set).unwrap().insert(record, serial);
            }
        }
    }
    Ok((common_zone, output))
}

pub fn record_set_append_origin(
    input: &RecordSet,
    origin: &Name,
    serial: u32,
) -> Result<RecordSet> {
    let new_name = input.name().clone().append_name(origin)?;
    let mut output = RecordSet::new(&new_name, input.record_type(), serial);
    // TODO: less clones
    for record in input.records_without_rrsigs() {
        let mut record = record.clone();
        record.set_name(new_name.clone());
        output.insert(record, serial);
    }
    Ok(output)
}
