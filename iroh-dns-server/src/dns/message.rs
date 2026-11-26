//! Wire format handling for DNS queries and responses.
//!
//! Incoming queries are parsed by a small hand-written parser that only extracts what an
//! authoritative server needs: the header, the single question and the EDNS(0) OPT record.
//! It never allocates proportionally to the header counts and never follows compression
//! pointers, so its cost is bounded by the length of the input.
//!
//! Responses are encoded with [`simple_dns`]. The OPT record is appended by hand, because
//! `simple_dns` 0.12 places the extended RCODE and version in the wrong bits of the OPT TTL.

use std::fmt;

use n0_error::{Result, anyerr, ensure_any};
use simple_dns::{
    CLASS, Label, Name, OPCODE, PacketFlag, QCLASS, QTYPE, RCODE, ResourceRecord, TYPE,
    rdata::RData,
};

/// Maximum length of a domain name in wire format, including the root label.
const MAX_NAME_WIRE_LEN: usize = 255;
/// Maximum length of a single label.
const MAX_LABEL_LEN: usize = 63;
/// Length of the fixed DNS header.
const HEADER_LEN: usize = 12;
/// Wire length of a resource record with root name and empty rdata.
const MIN_RR_LEN: usize = 11;

/// Maximum UDP payload we advertise and send with EDNS(0).
///
/// This is the value recommended by DNS flag day 2020 to avoid IP fragmentation.
pub(crate) const EDNS_UDP_PAYLOAD: u16 = 1232;
/// Maximum UDP payload without EDNS(0), from RFC 1035.
pub(crate) const PLAIN_UDP_PAYLOAD: u16 = 512;

pub(crate) const QTYPE_ANY: u16 = 255;
pub(crate) const QTYPE_AXFR: u16 = 252;
pub(crate) const QTYPE_IXFR: u16 = 251;
const TYPE_OPT: u16 = 41;
pub(crate) const QCLASS_IN: u16 = 1;
pub(crate) const QCLASS_ANY: u16 = 255;

const FLAG_QR: u16 = 0x8000;
const FLAG_RD: u16 = 0x0100;
const FLAG_CD: u16 = 0x0010;
const OPCODE_SHIFT: u16 = 11;
const OPCODE_MASK: u16 = 0xF;
const OPCODE_QUERY: u16 = 0;
/// The opcode bits within the high byte of the header flags.
const OPCODE_BITS_HI: u8 = 0x78;

/// A domain name as raw wire labels, most specific label first.
///
/// The root name has no labels. Labels may contain arbitrary bytes.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DnsName {
    labels: Vec<Vec<u8>>,
}

impl DnsName {
    /// Parses a name in presentation format, without support for escapes.
    ///
    /// A trailing dot is optional, and the name is always treated as absolute.
    pub(crate) fn parse(s: &str) -> Result<Self> {
        let trimmed = s.strip_suffix('.').unwrap_or(s);
        if trimmed.is_empty() {
            return Ok(Self::default());
        }
        let labels = trimmed
            .split('.')
            .map(|label| label.as_bytes().to_vec())
            .collect();
        Self::from_labels(labels)
    }

    /// Creates a name from labels, checking label and name length limits.
    pub(crate) fn from_labels(labels: Vec<Vec<u8>>) -> Result<Self> {
        let mut wire_len = 1;
        for label in &labels {
            ensure_any!(!label.is_empty(), "empty label in DNS name");
            ensure_any!(label.len() <= MAX_LABEL_LEN, "DNS label too long");
            wire_len += 1 + label.len();
        }
        ensure_any!(wire_len <= MAX_NAME_WIRE_LEN, "DNS name too long");
        Ok(Self { labels })
    }

    /// Converts a [`simple_dns::Name`] into a [`DnsName`].
    pub(crate) fn from_simple(name: &Name<'_>) -> Self {
        Self {
            labels: name.as_bytes().map(<[u8]>::to_vec).collect(),
        }
    }

    /// Returns the labels, most specific first.
    pub(crate) fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    /// Returns a copy with all ASCII letters lowercased.
    pub(crate) fn to_ascii_lowercase(&self) -> Self {
        Self {
            labels: self
                .labels
                .iter()
                .map(|label| label.to_ascii_lowercase())
                .collect(),
        }
    }

    /// Returns the labels in front of `suffix` if `suffix` is equal to or a parent of `self`.
    ///
    /// Comparison is exact; lowercase both names for case-insensitive matching.
    pub(crate) fn strip_suffix(&self, suffix: &DnsName) -> Option<&[Vec<u8>]> {
        let split = self.labels.len().checked_sub(suffix.labels.len())?;
        let (prefix, tail) = self.labels.split_at(split);
        (tail == suffix.labels.as_slice()).then_some(prefix)
    }

    /// Converts into an owned [`simple_dns::Name`].
    pub(crate) fn to_simple(&self) -> Name<'static> {
        let labels: Vec<Label<'static>> = self
            .labels
            .iter()
            .map(|label| Label::new_unchecked(label.clone()))
            .collect();
        Name::new_with_labels(&labels)
    }
}

impl fmt::Display for DnsName {
    /// Formats the name in presentation format with a trailing dot.
    ///
    /// Dots, backslashes and non-printable bytes inside labels are escaped as in RFC 1035.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            return f.write_str(".");
        }
        for label in &self.labels {
            for &b in label {
                match b {
                    b'.' | b'\\' => write!(f, "\\{}", b as char)?,
                    0x21..=0x7e => write!(f, "{}", b as char)?,
                    _ => write!(f, "\\{b:03}")?,
                }
            }
            f.write_str(".")?;
        }
        Ok(())
    }
}

impl fmt::Debug for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DnsName({self})")
    }
}

/// The question of a DNS query.
#[derive(Debug, Clone)]
pub(crate) struct Question {
    /// The queried name, with the case the client sent.
    pub(crate) name: DnsName,
    pub(crate) qtype: u16,
    pub(crate) qclass: u16,
}

/// EDNS(0) parameters of a query.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Edns {
    /// The UDP payload size the client can receive.
    pub(crate) udp_payload: u16,
    /// The EDNS version the client used.
    pub(crate) version: u8,
}

/// A parsed DNS query.
#[derive(Debug, Clone)]
pub(crate) struct Query {
    pub(crate) id: u16,
    flags: u16,
    pub(crate) question: Question,
    pub(crate) edns: Option<Edns>,
}

impl Query {
    /// Creates a standard query for `name` and `qtype`, with recursion desired.
    pub(crate) fn new(name: DnsName, qtype: u16, checking_disabled: bool) -> Self {
        let mut flags = FLAG_RD;
        if checking_disabled {
            flags |= FLAG_CD;
        }
        Self {
            id: 0,
            flags,
            question: Question {
                name,
                qtype,
                qclass: QCLASS_IN,
            },
            edns: None,
        }
    }

    /// Returns a response skeleton for this query with the given response code.
    pub(crate) fn response(&self, rcode: RCODE) -> Response {
        Response {
            id: self.id,
            query_flags: self.flags,
            authoritative: false,
            truncated: false,
            rcode,
            question: Some(self.question.clone()),
            answers: Vec::new(),
            authority: Vec::new(),
            edns: self.edns.is_some(),
        }
    }
}

/// The result of parsing an incoming DNS message.
#[derive(Debug)]
pub(crate) enum Request {
    /// A well-formed standard query.
    Query(Query),
    /// A message that deserves an error response without a question section.
    Reject(Response),
    /// A message that must not be answered, such as a response or a runt packet.
    Ignore,
}

/// Parses an incoming DNS message.
///
/// This never panics and runs in time linear in the length of `buf`.
pub(crate) fn parse_request(buf: &[u8]) -> Request {
    if buf.len() < HEADER_LEN {
        return Request::Ignore;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & FLAG_QR != 0 {
        return Request::Ignore;
    }
    let reject = |rcode| Request::Reject(Response::error(id, flags, rcode));
    let is_query = (flags >> OPCODE_SHIFT) & OPCODE_MASK == OPCODE_QUERY;
    let parsed = parse_body(buf);
    match (is_query, parsed) {
        (true, Some((question, Some(edns)))) => Request::Query(Query {
            id,
            flags,
            question,
            edns,
        }),
        (true, _) => reject(RCODE::FormatError),
        // Echo the question and EDNS of other opcodes when they parse, so that the client
        // sees NOTIMP for the opcode rather than a lack of EDNS support.
        (false, Some((question, Some(edns)))) => Request::Reject(
            Query {
                id,
                flags,
                question,
                edns,
            }
            .response(RCODE::NotImplemented),
        ),
        (false, _) => reject(RCODE::NotImplemented),
    }
}

/// Parses the question and the EDNS(0) record of a message.
///
/// Returns `None` unless there is exactly one well-formed question, and `Some((question,
/// None))` if the records after it are malformed.
fn parse_body(buf: &[u8]) -> Option<(Question, Option<Option<Edns>>)> {
    let count = |i: usize| u16::from_be_bytes([buf[4 + 2 * i], buf[5 + 2 * i]]) as usize;
    let (qdcount, ancount, nscount, arcount) = (count(0), count(1), count(2), count(3));
    if qdcount != 1 {
        return None;
    }
    let mut reader = Reader {
        buf,
        pos: HEADER_LEN,
    };
    let question = reader.question()?;
    let edns = reader.edns(ancount, nscount, arcount).ok();
    Some((question, edns))
}

/// A cursor over an incoming message.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.bytes(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes = self.bytes(4)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn bytes(&mut self, len: usize) -> Option<&[u8]> {
        let end = self.pos.checked_add(len)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    /// Reads the question.
    ///
    /// Compression pointers are rejected: a valid pointer must point backwards, and nothing
    /// in front of the first question can hold a name.
    fn question(&mut self) -> Option<Question> {
        let mut labels = Vec::new();
        let mut wire_len = 1;
        loop {
            let len = self.u8()? as usize;
            if len == 0 {
                break;
            }
            if len > MAX_LABEL_LEN {
                return None;
            }
            wire_len += 1 + len;
            if wire_len > MAX_NAME_WIRE_LEN {
                return None;
            }
            labels.push(self.bytes(len)?.to_vec());
        }
        let qtype = self.u16()?;
        let qclass = self.u16()?;
        Some(Question {
            name: DnsName { labels },
            qtype,
            qclass,
        })
    }

    /// Skips a possibly compressed name without following pointers.
    fn skip_name(&mut self) -> Option<()> {
        loop {
            let len = self.u8()?;
            match len {
                0 => return Some(()),
                l if l & 0xC0 == 0xC0 => {
                    self.u8()?;
                    return Some(());
                }
                l if l as usize > MAX_LABEL_LEN => return None,
                l => {
                    self.bytes(l as usize)?;
                }
            }
        }
    }

    /// Skips the answer and authority sections and extracts the OPT record.
    ///
    /// Fails on truncated records or more than one OPT record.
    fn edns(&mut self, ancount: usize, nscount: usize, arcount: usize) -> Result<Option<Edns>> {
        // Every record takes at least `MIN_RR_LEN` bytes, so the counts can be checked
        // against the remaining length before looping.
        let remaining = self.buf.len() - self.pos;
        ensure_any!(
            (ancount + nscount + arcount) * MIN_RR_LEN <= remaining,
            "record counts exceed message length"
        );
        let mut edns = None;
        for i in 0..ancount + nscount + arcount {
            self.skip_name().ok_or_else(|| anyerr!("truncated name"))?;
            let rtype = self.u16().ok_or_else(|| anyerr!("truncated record"))?;
            let class = self.u16().ok_or_else(|| anyerr!("truncated record"))?;
            let ttl = self.u32().ok_or_else(|| anyerr!("truncated record"))?;
            let rdlen = self.u16().ok_or_else(|| anyerr!("truncated record"))?;
            self.bytes(rdlen as usize)
                .ok_or_else(|| anyerr!("truncated rdata"))?;
            if i >= ancount + nscount && rtype == TYPE_OPT {
                ensure_any!(edns.is_none(), "multiple OPT records");
                edns = Some(Edns {
                    udp_payload: class,
                    version: (ttl >> 16) as u8,
                });
            }
        }
        Ok(edns)
    }
}

/// A DNS response under construction.
#[derive(Debug, Clone)]
pub(crate) struct Response {
    id: u16,
    query_flags: u16,
    pub(crate) authoritative: bool,
    pub(crate) truncated: bool,
    pub(crate) rcode: RCODE,
    pub(crate) question: Option<Question>,
    pub(crate) answers: Vec<ResourceRecord<'static>>,
    pub(crate) authority: Vec<ResourceRecord<'static>>,
    /// Whether to include an OPT record.
    pub(crate) edns: bool,
}

impl Response {
    /// Creates an error response without a question section.
    fn error(id: u16, query_flags: u16, rcode: RCODE) -> Self {
        Self {
            id,
            query_flags,
            authoritative: false,
            truncated: false,
            rcode,
            question: None,
            answers: Vec::new(),
            authority: Vec::new(),
            edns: false,
        }
    }

    /// Returns whether the query had the RD flag set.
    pub(crate) fn recursion_desired(&self) -> bool {
        self.query_flags & FLAG_RD != 0
    }

    /// Returns whether the query had the CD flag set.
    pub(crate) fn checking_disabled(&self) -> bool {
        self.query_flags & FLAG_CD != 0
    }

    /// Encodes the response, truncating it to fit into `max_len` bytes.
    ///
    /// A response that does not fit is sent with the TC flag and without records, so that
    /// the client retries over TCP.
    pub(crate) fn encode(&self, max_len: usize) -> Vec<u8> {
        match self.try_encode(true) {
            Ok(bytes) if bytes.len() <= max_len => bytes,
            Ok(_) => self
                .try_encode(false)
                .unwrap_or_else(|_| self.encode_header_only(RCODE::ServerFailure)),
            Err(_) => self.encode_header_only(RCODE::ServerFailure),
        }
    }

    fn try_encode(&self, with_records: bool) -> Result<Vec<u8>> {
        let mut packet = simple_dns::Packet::new_reply(self.id);
        *packet.opcode_mut() = OPCODE::StandardQuery;
        // Extended RCODEs are written to the OPT record below.
        *packet.rcode_mut() = RCODE::from(self.rcode as u16 & 0xF);
        let mut flags = PacketFlag::RESPONSE;
        if self.authoritative {
            flags |= PacketFlag::AUTHORITATIVE_ANSWER;
        }
        if self.truncated || !with_records {
            flags |= PacketFlag::TRUNCATION;
        }
        if self.recursion_desired() {
            flags |= PacketFlag::RECURSION_DESIRED;
        }
        if self.checking_disabled() {
            flags |= PacketFlag::CHECKING_DISABLED;
        }
        packet.set_flags(flags);
        if let Some(question) = &self.question
            && let Ok(qclass) = QCLASS::try_from(question.qclass)
        {
            let qtype = QTYPE::try_from(question.qtype)
                .unwrap_or(QTYPE::TYPE(TYPE::Unknown(question.qtype)));
            packet.questions.push(simple_dns::Question::new(
                question.name.to_simple(),
                qtype,
                qclass,
                false,
            ));
        }
        if with_records {
            packet.answers.extend(self.answers.iter().cloned());
            packet.name_servers.extend(self.authority.iter().cloned());
        }
        let mut bytes = packet
            .build_bytes_vec_compressed()
            .map_err(|err| anyerr!("failed to encode DNS response: {err}"))?;
        // Echo the request opcode. `simple_dns` cannot represent all 16 values.
        bytes[2] = (bytes[2] & !OPCODE_BITS_HI) | self.opcode_bits_hi();
        if self.edns {
            append_opt(&mut bytes, self.rcode);
        }
        Ok(bytes)
    }

    /// Returns the request opcode, positioned within the high byte of the flags.
    fn opcode_bits_hi(&self) -> u8 {
        ((self.query_flags >> 8) as u8) & OPCODE_BITS_HI
    }

    /// Encodes a bare header with the given RCODE.
    fn encode_header_only(&self, rcode: RCODE) -> Vec<u8> {
        let opcode = self.query_flags & (OPCODE_MASK << OPCODE_SHIFT);
        let mut flags = FLAG_QR | opcode | (self.query_flags & (FLAG_RD | FLAG_CD));
        flags |= rcode as u16 & 0xF;
        let mut bytes = Vec::with_capacity(HEADER_LEN);
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&flags.to_be_bytes());
        bytes.extend_from_slice(&[0; 8]);
        bytes
    }
}

/// Appends an EDNS(0) OPT record to an encoded message and bumps ARCOUNT.
fn append_opt(bytes: &mut Vec<u8>, rcode: RCODE) {
    let arcount = u16::from_be_bytes([bytes[10], bytes[11]]).saturating_add(1);
    bytes[10..12].copy_from_slice(&arcount.to_be_bytes());
    let extended_rcode = ((rcode as u16) >> 4) as u32;
    // TTL layout: extended RCODE (8 bits), version (8 bits), DO flag and Z (16 bits).
    let ttl = extended_rcode << 24;
    bytes.push(0); // root name
    bytes.extend_from_slice(&TYPE_OPT.to_be_bytes());
    bytes.extend_from_slice(&EDNS_UDP_PAYLOAD.to_be_bytes());
    bytes.extend_from_slice(&ttl.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes()); // rdlen
}

/// Encodes a query in wire format, used to feed JSON DoH requests through the same path.
pub(crate) fn encode_query(query: &Query) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_LEN + MAX_NAME_WIRE_LEN + 4);
    bytes.extend_from_slice(&query.id.to_be_bytes());
    bytes.extend_from_slice(&query.flags.to_be_bytes());
    bytes.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in query.question.name.labels() {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label);
    }
    bytes.push(0);
    bytes.extend_from_slice(&query.question.qtype.to_be_bytes());
    bytes.extend_from_slice(&query.question.qclass.to_be_bytes());
    bytes
}

/// Returns the wire-format rdata of a record.
pub(crate) fn rdata_wire(rdata: &RData<'static>) -> Vec<u8> {
    let mut packet = simple_dns::Packet::new_reply(0);
    packet.answers.push(ResourceRecord::new(
        Name::new_with_labels(&[]),
        CLASS::IN,
        0,
        rdata.clone(),
    ));
    match packet.build_bytes_vec() {
        // header, root name, type, class, ttl, rdlen
        Ok(bytes) => bytes
            .get(HEADER_LEN + 1 + 10..)
            .unwrap_or_default()
            .to_vec(),
        Err(_) => Vec::new(),
    }
}

/// Returns the numeric type code of a record.
pub(crate) fn record_type(record: &ResourceRecord<'_>) -> u16 {
    record.rdata.type_code().into()
}

#[cfg(test)]
mod tests {
    use simple_dns::Packet;

    use super::*;

    fn query_bytes(name: &str, qtype: u16) -> Vec<u8> {
        encode_query(&Query::new(DnsName::parse(name).unwrap(), qtype, false))
    }

    #[test]
    fn parse_simple_query() {
        let bytes = query_bytes("Foo.Example.", 16);
        let Request::Query(query) = parse_request(&bytes) else {
            panic!("expected query");
        };
        assert_eq!(query.question.name.to_string(), "Foo.Example.");
        assert_eq!(query.question.qtype, 16);
        assert_eq!(query.question.qclass, QCLASS_IN);
        assert!(query.edns.is_none());
    }

    #[test]
    fn parse_query_with_unknown_type() {
        // TLSA is not known to simple-dns, but must not be a format error.
        let bytes = query_bytes("example.", 52);
        assert!(matches!(parse_request(&bytes), Request::Query(q) if q.question.qtype == 52));
    }

    #[test]
    fn parse_edns() {
        let mut bytes = query_bytes("example.", 1);
        bytes[11] = 1; // arcount
        bytes.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 1, 0, 0, 0, 0]);
        let Request::Query(query) = parse_request(&bytes) else {
            panic!("expected query");
        };
        let edns = query.edns.unwrap();
        assert_eq!(edns.udp_payload, 4096);
        assert_eq!(edns.version, 1);
    }

    #[test]
    fn reject_malformed() {
        assert!(matches!(parse_request(&[0; 11]), Request::Ignore));

        // response bit set
        let mut bytes = query_bytes("example.", 1);
        bytes[2] |= 0x80;
        assert!(matches!(parse_request(&bytes), Request::Ignore));

        // two questions
        let mut bytes = query_bytes("example.", 1);
        bytes[5] = 2;
        assert!(
            matches!(parse_request(&bytes), Request::Reject(r) if r.rcode == RCODE::FormatError)
        );

        // opcode NOTIFY
        let mut bytes = query_bytes("example.", 1);
        bytes[2] |= 4 << 3;
        assert!(
            matches!(parse_request(&bytes), Request::Reject(r) if r.rcode == RCODE::NotImplemented)
        );

        // compression pointer in question
        let mut bytes = query_bytes(".", 1);
        bytes.truncate(HEADER_LEN);
        bytes.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        assert!(
            matches!(parse_request(&bytes), Request::Reject(r) if r.rcode == RCODE::FormatError)
        );

        // huge additional count with no data
        let mut bytes = query_bytes("example.", 1);
        bytes[10] = 0xFF;
        bytes[11] = 0xFF;
        assert!(
            matches!(parse_request(&bytes), Request::Reject(r) if r.rcode == RCODE::FormatError)
        );

        // truncated question
        let bytes = query_bytes("example.", 1);
        assert!(matches!(
            parse_request(&bytes[..bytes.len() - 1]),
            Request::Reject(r) if r.rcode == RCODE::FormatError
        ));
    }

    #[test]
    fn parse_never_panics_on_prefixes() {
        let mut bytes = query_bytes("a.b.example.", 16);
        bytes[11] = 1;
        bytes.extend_from_slice(&[0xC0, 0x0C, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 2, 1, 2]);
        for len in 0..bytes.len() {
            let _ = parse_request(&bytes[..len]);
        }
        assert!(matches!(parse_request(&bytes), Request::Query(_)));
    }

    #[test]
    fn encode_roundtrip() {
        let bytes = query_bytes("example.", 1);
        let Request::Query(query) = parse_request(&bytes) else {
            panic!("expected query");
        };
        let mut response = query.response(RCODE::NoError);
        response.authoritative = true;
        response.answers.push(ResourceRecord::new(
            query.question.name.to_simple(),
            CLASS::IN,
            30,
            RData::A(std::net::Ipv4Addr::LOCALHOST.into()),
        ));
        let encoded = response.encode(512);
        let packet = Packet::parse(&encoded).unwrap();
        assert!(packet.has_flags(PacketFlag::RESPONSE | PacketFlag::AUTHORITATIVE_ANSWER));
        assert!(packet.has_flags(PacketFlag::RECURSION_DESIRED));
        assert_eq!(packet.answers.len(), 1);
        assert_eq!(packet.questions.len(), 1);
    }

    #[test]
    fn encode_truncates() {
        let bytes = query_bytes("example.", 16);
        let Request::Query(query) = parse_request(&bytes) else {
            panic!("expected query");
        };
        let mut response = query.response(RCODE::NoError);
        let long = "x".repeat(200);
        for _ in 0..4 {
            let txt = simple_dns::rdata::TXT::new()
                .with_string(&long)
                .unwrap()
                .into_owned();
            response.answers.push(ResourceRecord::new(
                query.question.name.to_simple(),
                CLASS::IN,
                30,
                RData::TXT(txt),
            ));
        }
        let encoded = response.encode(512);
        assert!(encoded.len() <= 512);
        let packet = Packet::parse(&encoded).unwrap();
        assert!(packet.has_flags(PacketFlag::TRUNCATION));
        assert!(packet.answers.is_empty());
        let full = response.encode(4096);
        assert_eq!(Packet::parse(&full).unwrap().answers.len(), 4);
    }

    #[test]
    fn opt_extended_rcode() {
        let mut bytes = query_bytes("example.", 1);
        bytes[11] = 1;
        bytes.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 1, 0, 0, 0, 0]);
        let Request::Query(query) = parse_request(&bytes) else {
            panic!("expected query");
        };
        let encoded = query.response(RCODE::BADVERS).encode(512);
        // header rcode holds the low 4 bits of 16
        assert_eq!(encoded[3] & 0xF, 0);
        // OPT TTL's first byte holds the high 8 bits
        let opt = &encoded[encoded.len() - 11..];
        assert_eq!(&opt[..3], &[0, 0, 41]);
        assert_eq!(opt[5], 1);
    }

    #[test]
    fn notimp_echoes_opcode_question_and_edns() {
        let mut bytes = query_bytes("example.", 6);
        bytes[2] |= 4 << 3; // NOTIFY
        bytes[11] = 1;
        bytes.extend_from_slice(&[0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0]);
        let Request::Reject(response) = parse_request(&bytes) else {
            panic!("expected reject");
        };
        let encoded = response.encode(512);
        assert_eq!(encoded[2] & OPCODE_BITS_HI, 4 << 3);
        assert_eq!(encoded[3] & 0xF, RCODE::NotImplemented as u8);
        assert_eq!(&encoded[4..6], &[0, 1], "question echoed");
        assert_eq!(&encoded[10..12], &[0, 1], "OPT included");
    }

    #[test]
    fn name_display_escapes() {
        let name = DnsName::from_labels(vec![b"a.b".to_vec(), vec![0x01], b"c".to_vec()]).unwrap();
        assert_eq!(name.to_string(), "a\\.b.\\001.c.");
        assert_eq!(DnsName::default().to_string(), ".");
    }
}
