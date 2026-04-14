//! DNS packet construction and response parsing using `simple_dns`.

use std::net::{Ipv4Addr, Ipv6Addr};

use n0_error::e;
use simple_dns::{
    CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, RCODE, TYPE,
    rdata::{A, AAAA, RData},
};

use super::{DnsError, TxtRecordData};

/// EDNS(0) advertised UDP payload size.
///
/// 1232 bytes is the current recommended safe value per RFC 6891 and the
/// DNS flag day 2020 recommendations. This avoids IP fragmentation on
/// common path MTUs while allowing responses much larger than the
/// original 512-byte RFC 1035 limit.
const EDNS_UDP_PAYLOAD_SIZE: u16 = 1232;

/// Build a DNS query packet for the given host and query type.
///
/// The query includes an EDNS(0) OPT record advertising support for
/// responses up to [`EDNS_UDP_PAYLOAD_SIZE`] bytes over UDP.
///
/// Returns `(query_id, wire_bytes)`.
pub(super) fn build_query(host: &str, qtype: TYPE) -> Result<(u16, Vec<u8>), DnsError> {
    let id: u16 = rand::random();
    let mut packet = Packet::new_query(id);
    packet.set_flags(PacketFlag::RECURSION_DESIRED);

    let name = Name::new(host)?;
    let question = Question::new(name, QTYPE::TYPE(qtype), QCLASS::CLASS(CLASS::IN), false);
    packet.questions.push(question);

    // Add EDNS(0) OPT record to advertise larger UDP payload support.
    *packet.opt_mut() = Some(simple_dns::rdata::OPT {
        udp_packet_size: EDNS_UDP_PAYLOAD_SIZE,
        version: 0,
        opt_codes: vec![],
    });

    let bytes = packet.build_bytes_vec()?;
    Ok((id, bytes))
}

/// Maximum CNAME chain depth to prevent infinite loops.
pub(super) const MAX_CNAME_DEPTH: usize = 8;

/// Resolve the CNAME chain in the answer section starting from `start_name`.
///
/// Returns the final canonical name after following all CNAMEs, or the
/// original name if no CNAME records are present.
fn resolve_cname_chain<'a>(packet: &'a Packet<'a>, start_name: &Name<'a>) -> Name<'a> {
    let mut current = start_name.clone();
    for _ in 0..MAX_CNAME_DEPTH {
        let Some(next) = packet.answers.iter().find_map(|rr| {
            (rr.name == current)
                .then(|| match &rr.rdata {
                    RData::CNAME(cname) => Some(cname.0.clone()),
                    _ => None,
                })
                .flatten()
        }) else {
            break;
        };
        current = next;
    }
    current
}

/// Returns the CNAME target for a query name, if the response contains a CNAME
/// but no final records of the requested type for that name.
///
/// This is used for recursive CNAME following: when the server returns only a
/// CNAME without the final record, the caller issues a new query for the target.
pub(super) fn cname_target(packet: &Packet<'_>, qname: &str) -> Option<String> {
    let name = Name::new(qname).ok()?;
    let canonical = resolve_cname_chain(packet, &name);
    (canonical != name).then(|| canonical.to_string())
}

/// Check response packet for errors (RCODE, ID mismatch).
fn check_response(packet: &Packet, expected_id: u16) -> Result<(), DnsError> {
    if packet.id() != expected_id {
        return Err(e!(DnsError::InvalidResponse));
    }
    match packet.rcode() {
        RCODE::NoError => Ok(()),
        RCODE::NameError => Err(e!(DnsError::NxDomain)),
        rcode => Err(e!(DnsError::ServerError {
            rcode: format!("{rcode:?}"),
        })),
    }
}

/// Check whether a resource record's name matches the queried name or its
/// CNAME-resolved canonical name. If no question section is present
/// (shouldn't happen in practice), accept all records.
fn name_matches(
    rr_name: &Name<'_>,
    qname: Option<&Name<'_>>,
    canonical: Option<&Name<'_>>,
) -> bool {
    match qname {
        Some(q) => rr_name == q || canonical.is_some_and(|c| rr_name == c),
        None => true, // No question section -- accept all matching record types.
    }
}

/// Parse A (IPv4) records from a DNS response, following CNAME chains.
///
/// If the response contains CNAME records pointing from the queried name to a
/// canonical name, records for both the original and canonical names are collected.
pub(super) fn parse_a_response(
    data: &[u8],
    expected_id: u16,
) -> Result<(Vec<Ipv4Addr>, u32), DnsError> {
    let packet = Packet::parse(data)?;
    check_response(&packet, expected_id)?;

    let qname = packet.questions.first().map(|q| q.qname.clone());
    let canonical = qname.as_ref().map(|q| resolve_cname_chain(&packet, q));

    let mut addrs = Vec::new();
    let mut min_ttl = u32::MAX;
    for rr in &packet.answers {
        if let RData::A(A { address }) = &rr.rdata
            && name_matches(&rr.name, qname.as_ref(), canonical.as_ref())
        {
            addrs.push(Ipv4Addr::from(*address));
            min_ttl = min_ttl.min(rr.ttl);
        }
    }
    if min_ttl == u32::MAX {
        min_ttl = 0;
    }
    Ok((addrs, min_ttl))
}

/// Parse AAAA (IPv6) records from a DNS response, following CNAME chains.
pub(super) fn parse_aaaa_response(
    data: &[u8],
    expected_id: u16,
) -> Result<(Vec<Ipv6Addr>, u32), DnsError> {
    let packet = Packet::parse(data)?;
    check_response(&packet, expected_id)?;

    let qname = packet.questions.first().map(|q| q.qname.clone());
    let canonical = qname.as_ref().map(|q| resolve_cname_chain(&packet, q));

    let mut addrs = Vec::new();
    let mut min_ttl = u32::MAX;
    for rr in &packet.answers {
        if let RData::AAAA(AAAA { address }) = &rr.rdata
            && name_matches(&rr.name, qname.as_ref(), canonical.as_ref())
        {
            addrs.push(Ipv6Addr::from(*address));
            min_ttl = min_ttl.min(rr.ttl);
        }
    }
    if min_ttl == u32::MAX {
        min_ttl = 0;
    }
    Ok((addrs, min_ttl))
}

/// Parse TXT records from a DNS response, following CNAME chains.
pub(super) fn parse_txt_response(
    data: &[u8],
    expected_id: u16,
) -> Result<(Vec<TxtRecordData>, u32), DnsError> {
    let packet = Packet::parse(data)?;
    check_response(&packet, expected_id)?;

    let qname = packet.questions.first().map(|q| q.qname.clone());
    let canonical = qname.as_ref().map(|q| resolve_cname_chain(&packet, q));

    let mut records = Vec::new();
    let mut min_ttl = u32::MAX;
    for rr in &packet.answers {
        if let RData::TXT(txt) = &rr.rdata
            && name_matches(&rr.name, qname.as_ref(), canonical.as_ref())
        {
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

/// Extract the raw content of a TXT record into `TxtRecordData`.
///
/// Converts the TXT record's character strings into raw bytes. In iroh's
/// DNS encoding, each TXT record typically contains a single character
/// string (one `key=value` attribute), and each attribute is published as
/// a separate TXT ResourceRecord.
///
/// We use `String::try_from` which concatenates all character strings in
/// the record into one byte sequence. This preserves the raw content
/// without the destructive key=value parsing that `TXT::attributes()` does
/// (which uses a HashMap and would lose ordering and deduplicate keys).
fn extract_txt_record_data(txt: &simple_dns::rdata::TXT<'_>) -> TxtRecordData {
    match String::try_from(txt.clone()) {
        Ok(s) if !s.is_empty() => TxtRecordData::from(vec![s.into_bytes().into_boxed_slice()]),
        _ => TxtRecordData::from(Vec::<Box<[u8]>>::new()),
    }
}

/// Returns true if the response has the TC (truncation) flag set.
pub(super) fn is_truncated(data: &[u8]) -> bool {
    Packet::parse(data).is_ok_and(|p| p.has_flags(PacketFlag::TRUNCATION))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use simple_dns::{
        CLASS, Name, Packet, PacketFlag, QCLASS, QTYPE, Question, ResourceRecord,
        rdata::{A, CNAME, RData},
    };

    use super::*;

    /// Build a query packet for `host` with type A, return (id, bytes).
    fn make_query(host: &str) -> (u16, Vec<u8>) {
        build_query(host, TYPE::A).unwrap()
    }

    /// Build a response with A records for `name`.
    fn a_response(id: u16, name: &str, addrs: &[Ipv4Addr]) -> Vec<u8> {
        let mut packet = Packet::new_reply(id);
        packet.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        // Echo the question back (needed for CNAME resolution in parse functions).
        packet.questions.push(Question::new(
            Name::new_unchecked(name),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        for addr in addrs {
            packet.answers.push(ResourceRecord::new(
                Name::new_unchecked(name),
                CLASS::IN,
                300,
                RData::A(A {
                    address: u32::from(*addr),
                }),
            ));
        }
        packet.build_bytes_vec().unwrap()
    }

    /// Build a response containing a CNAME from `alias` -> `canonical`, plus
    /// A records under the canonical name (the common "both in one response" case).
    fn cname_with_a_response(id: u16, alias: &str, canonical: &str, addrs: &[Ipv4Addr]) -> Vec<u8> {
        let mut packet = Packet::new_reply(id);
        packet.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        packet.questions.push(Question::new(
            Name::new_unchecked(alias),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        // CNAME record
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked(alias),
            CLASS::IN,
            300,
            RData::CNAME(CNAME(Name::new_unchecked(canonical))),
        ));
        // A records for the canonical name
        for addr in addrs {
            packet.answers.push(ResourceRecord::new(
                Name::new_unchecked(canonical),
                CLASS::IN,
                300,
                RData::A(A {
                    address: u32::from(*addr),
                }),
            ));
        }
        packet.build_bytes_vec().unwrap()
    }

    /// Build a response containing only a CNAME (no final A record).
    fn cname_only_response(id: u16, alias: &str, canonical: &str) -> Vec<u8> {
        let mut packet = Packet::new_reply(id);
        packet.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        packet.questions.push(Question::new(
            Name::new_unchecked(alias),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked(alias),
            CLASS::IN,
            300,
            RData::CNAME(CNAME(Name::new_unchecked(canonical))),
        ));
        packet.build_bytes_vec().unwrap()
    }

    #[test]
    fn build_query_includes_edns_opt() {
        let (_, bytes) = build_query("example.com", TYPE::A).unwrap();
        let packet = Packet::parse(&bytes).unwrap();
        let opt = packet.opt().expect("query should include OPT record");
        assert_eq!(opt.udp_packet_size, 1232);
        assert_eq!(opt.version, 0);
    }

    #[test]
    fn parse_a_no_cname() {
        let (id, _) = make_query("example.com");
        let resp = a_response(id, "example.com", &[Ipv4Addr::new(1, 2, 3, 4)]);
        let (addrs, ttl) = parse_a_response(&resp, id).unwrap();
        assert_eq!(addrs, [Ipv4Addr::new(1, 2, 3, 4)]);
        assert_eq!(ttl, 300);
    }

    #[test]
    fn parse_a_with_cname_in_response() {
        let (id, _) = make_query("alias.example.com");
        let resp = cname_with_a_response(
            id,
            "alias.example.com",
            "real.example.com",
            &[Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)],
        );
        let (addrs, _) = parse_a_response(&resp, id).unwrap();
        assert_eq!(
            addrs,
            [Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]
        );
    }

    #[test]
    fn parse_a_with_chained_cname() {
        // alias -> middle -> real, A records on real
        let (id, _) = make_query("alias.example.com");
        let mut packet = Packet::new_reply(id);
        packet.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        packet.questions.push(Question::new(
            Name::new_unchecked("alias.example.com"),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked("alias.example.com"),
            CLASS::IN,
            300,
            RData::CNAME(CNAME(Name::new_unchecked("middle.example.com"))),
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked("middle.example.com"),
            CLASS::IN,
            300,
            RData::CNAME(CNAME(Name::new_unchecked("real.example.com"))),
        ));
        packet.answers.push(ResourceRecord::new(
            Name::new_unchecked("real.example.com"),
            CLASS::IN,
            300,
            RData::A(A {
                address: u32::from(Ipv4Addr::new(5, 6, 7, 8)),
            }),
        ));
        let resp = packet.build_bytes_vec().unwrap();
        let (addrs, _) = parse_a_response(&resp, id).unwrap();
        assert_eq!(addrs, [Ipv4Addr::new(5, 6, 7, 8)]);
    }

    #[test]
    fn cname_target_extracts_target_for_recursive_follow() {
        let id = 1234;
        let resp = cname_only_response(id, "alias.example.com", "real.example.com");
        let packet = Packet::parse(&resp).unwrap();
        let target = cname_target(&packet, "alias.example.com");
        assert_eq!(target.as_deref(), Some("real.example.com"));
    }

    #[test]
    fn cname_target_returns_none_when_no_cname() {
        let id = 1234;
        let resp = a_response(id, "example.com", &[Ipv4Addr::new(1, 2, 3, 4)]);
        let packet = Packet::parse(&resp).unwrap();
        let target = cname_target(&packet, "example.com");
        assert_eq!(target, None);
    }
}
