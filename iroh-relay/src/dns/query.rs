//! DNS packet construction and response parsing using `simple_dns`.

use std::net::{Ipv4Addr, Ipv6Addr};

use n0_error::e;
use simple_dns::{
    CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, RCODE, TYPE,
    rdata::{A, AAAA, RData},
};

use super::{DnsError, TxtRecordData};

/// Build a DNS query packet for the given host and query type.
///
/// Returns `(query_id, wire_bytes)`.
pub(super) fn build_query(host: &str, qtype: TYPE) -> Result<(u16, Vec<u8>), DnsError> {
    let id: u16 = rand::random();
    let mut packet = Packet::new_query(id);
    packet.set_flags(PacketFlag::RECURSION_DESIRED);

    let name = Name::new(host)?;
    let question = Question::new(name, QTYPE::TYPE(qtype), QCLASS::CLASS(CLASS::IN), false);
    packet.questions.push(question);

    let bytes = packet.build_bytes_vec()?;
    Ok((id, bytes))
}

/// Check response packet for errors (RCODE, ID mismatch).
fn check_response(packet: &Packet, expected_id: u16) -> Result<(), DnsError> {
    if packet.id() != expected_id {
        return Err(e!(DnsError::InvalidResponse));
    }
    match packet.rcode() {
        RCODE::NoError => Ok(()),
        rcode => Err(e!(DnsError::ServerError {
            rcode: format!("{rcode:?}"),
        })),
    }
}

/// Parse A (IPv4) records from a DNS response.
pub(super) fn parse_a_response(
    data: &[u8],
    expected_id: u16,
) -> Result<(Vec<Ipv4Addr>, u32), DnsError> {
    let packet = Packet::parse(data)?;
    check_response(&packet, expected_id)?;

    let mut addrs = Vec::new();
    let mut min_ttl = u32::MAX;
    for rr in &packet.answers {
        if let RData::A(A { address }) = &rr.rdata {
            addrs.push(Ipv4Addr::from(*address));
            min_ttl = min_ttl.min(rr.ttl);
        }
    }
    if min_ttl == u32::MAX {
        min_ttl = 0;
    }
    Ok((addrs, min_ttl))
}

/// Parse AAAA (IPv6) records from a DNS response.
pub(super) fn parse_aaaa_response(
    data: &[u8],
    expected_id: u16,
) -> Result<(Vec<Ipv6Addr>, u32), DnsError> {
    let packet = Packet::parse(data)?;
    check_response(&packet, expected_id)?;

    let mut addrs = Vec::new();
    let mut min_ttl = u32::MAX;
    for rr in &packet.answers {
        if let RData::AAAA(AAAA { address }) = &rr.rdata {
            addrs.push(Ipv6Addr::from(*address));
            min_ttl = min_ttl.min(rr.ttl);
        }
    }
    if min_ttl == u32::MAX {
        min_ttl = 0;
    }
    Ok((addrs, min_ttl))
}

/// Parse TXT records from a DNS response.
pub(super) fn parse_txt_response(
    data: &[u8],
    expected_id: u16,
) -> Result<(Vec<TxtRecordData>, u32), DnsError> {
    let packet = Packet::parse(data)?;
    check_response(&packet, expected_id)?;

    let mut records = Vec::new();
    let mut min_ttl = u32::MAX;
    for rr in &packet.answers {
        if let RData::TXT(txt) = &rr.rdata {
            let record = extract_txt_record_data(txt);
            records.push(record);
            min_ttl = min_ttl.min(rr.ttl);
        }
    }
    if min_ttl == u32::MAX {
        min_ttl = 0;
    }
    Ok((records, min_ttl))
}

/// Extract character strings from a TXT record into `TxtRecordData`.
///
/// For iroh's use case, TXT records contain `key=value` strings
/// where each DNS character string is one attribute.
fn extract_txt_record_data(txt: &simple_dns::rdata::TXT<'_>) -> TxtRecordData {
    let attrs = txt.attributes();
    if !attrs.is_empty() {
        let strings: Vec<String> = attrs
            .into_iter()
            .map(|(k, v)| match v {
                Some(val) => format!("{k}={val}"),
                None => k.to_owned(),
            })
            .collect();
        TxtRecordData::from(strings)
    } else {
        match String::try_from(txt.clone()) {
            Ok(s) if !s.is_empty() => TxtRecordData::from(vec![s]),
            _ => TxtRecordData::from(Vec::<String>::new()),
        }
    }
}

/// Returns true if the response has the TC (truncation) flag set.
pub(super) fn is_truncated(data: &[u8]) -> bool {
    if let Ok(packet) = Packet::parse(data) {
        packet.has_flags(PacketFlag::TRUNCATION)
    } else {
        false
    }
}
