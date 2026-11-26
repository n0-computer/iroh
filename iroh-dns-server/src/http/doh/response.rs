//! DNS Response

// This module is mostly copied from
// https://github.com/fission-codes/fission-server/blob/394de877fad021260c69fdb1edd7bb4b2f98108c/fission-core/src/dns.rs

use std::{
    fmt::Write,
    net::{Ipv4Addr, Ipv6Addr},
};

use serde::{Deserialize, Serialize};
use simple_dns::{ResourceRecord, rdata::RData};

use crate::dns::message::{DnsName, Question, Response, rdata_wire, record_type};

/// JSON representation of a DNS response
/// See: <https://developers.google.com/speed/public-dns/docs/doh/json>
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct DnsResponse {
    /// Standard DNS response code
    #[serde(rename = "Status")]
    pub status: u32,
    /// Whether the response was truncated
    #[serde(rename = "TC")]
    pub tc: bool,
    /// Whether recursion was desired
    #[serde(rename = "RD")]
    pub rd: bool,
    /// Whether recursion was available
    #[serde(rename = "RA")]
    pub ra: bool,
    /// Whether the response was validated with DNSSEC
    #[serde(rename = "AD")]
    pub ad: bool,
    /// Whether the client asked to disable DNSSEC validation
    #[serde(rename = "CD")]
    pub cd: bool,
    /// The questions that this request answers
    #[serde(rename = "Question")]
    pub question: Vec<DohQuestionJson>,
    /// The answers to the request
    #[serde(rename = "Answer")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub answer: Vec<DohRecordJson>,
    /// An optional comment
    #[serde(rename = "Comment")]
    pub comment: Option<String>,
    /// IP Address / scope prefix-length of the client
    /// See: <https://tools.ietf.org/html/rfc7871>
    pub edns_client_subnet: Option<String>,
}

impl DnsResponse {
    /// Create a new JSON response from a DNS response
    pub(crate) fn from_response(response: &Response) -> Self {
        DnsResponse {
            status: response.rcode as u32,
            tc: response.truncated,
            rd: response.recursion_desired(),
            ra: false,
            ad: false,
            cd: response.checking_disabled(),
            question: response
                .question
                .iter()
                .map(DohQuestionJson::from_question)
                .collect(),
            answer: response
                .answers
                .iter()
                .map(DohRecordJson::from_record)
                .collect(),
            comment: None,
            edns_client_subnet: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
/// JSON representation of a DNS question
pub(crate) struct DohQuestionJson {
    /// FQDN with trailing dot
    pub(crate) name: String,
    /// Standard DNS RR type
    #[serde(rename = "type")]
    pub(crate) question_type: u16,
}

impl DohQuestionJson {
    /// Create a new JSON question from a DNS question
    pub(crate) fn from_question(question: &Question) -> Self {
        Self {
            name: question.name.to_string(),
            question_type: question.qtype,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
/// JSON representation of a DNS record
pub(crate) struct DohRecordJson {
    /// FQDN with trailing dot
    pub(crate) name: String,
    /// Standard DNS RR type
    #[serde(rename = "type")]
    pub(crate) record_type: u16,
    /// Time-to-live, in seconds
    #[serde(rename = "TTL")]
    pub(crate) ttl: u32,
    /// Record data
    pub(crate) data: String,
}

impl DohRecordJson {
    /// Create a new JSON record from a DNS record
    pub(crate) fn from_record(record: &ResourceRecord<'static>) -> Self {
        Self {
            name: DnsName::from_simple(&record.name).to_string(),
            record_type: record_type(record),
            ttl: record.ttl,
            data: rdata_to_string(&record.rdata),
        }
    }
}

/// Formats rdata in presentation format.
///
/// TXT strings are concatenated without quotes, which is what clients of this server
/// expect. Types without a dedicated format use the generic encoding of RFC 3597.
fn rdata_to_string(rdata: &RData<'static>) -> String {
    let name = |name| DnsName::from_simple(name).to_string();
    match rdata {
        RData::A(a) => Ipv4Addr::from(a.address).to_string(),
        RData::AAAA(aaaa) => Ipv6Addr::from(aaaa.address).to_string(),
        RData::NS(ns) => name(&ns.0),
        RData::CNAME(cname) => name(&cname.0),
        RData::PTR(ptr) => name(&ptr.0),
        RData::MX(mx) => format!("{} {}", mx.preference, name(&mx.exchange)),
        RData::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            name(&srv.target)
        ),
        RData::SOA(soa) => format!(
            "{} {} {} {} {} {} {}",
            name(&soa.mname),
            name(&soa.rname),
            soa.serial,
            soa.refresh,
            soa.retry,
            soa.expire,
            soa.minimum
        ),
        RData::TXT(_) => {
            let wire = rdata_wire(rdata);
            let mut out = Vec::with_capacity(wire.len());
            let mut rest = wire.as_slice();
            while let Some((&len, tail)) = rest.split_first() {
                let len = (len as usize).min(tail.len());
                out.extend_from_slice(&tail[..len]);
                rest = &tail[len..];
            }
            String::from_utf8_lossy(&out).into_owned()
        }
        _ => {
            let wire = rdata_wire(rdata);
            let mut out = format!("\\# {}", wire.len());
            if !wire.is_empty() {
                out.push(' ');
                for b in &wire {
                    write!(out, "{b:02x}").expect("writing to string");
                }
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use simple_dns::{CLASS, Name, rdata};

    use super::*;

    #[test]
    fn format_rdata() {
        let txt = rdata::TXT::new()
            .with_string("relay=https://relay.example./")
            .unwrap()
            .into_owned();
        assert_eq!(
            rdata_to_string(&RData::TXT(txt)),
            "relay=https://relay.example./"
        );
        assert_eq!(
            rdata_to_string(&RData::A(Ipv4Addr::LOCALHOST.into())),
            "127.0.0.1"
        );
        let target = Name::new_unchecked("example.org").into_owned();
        assert_eq!(
            rdata_to_string(&RData::CNAME(rdata::CNAME(target))),
            "example.org."
        );
        let record = ResourceRecord::new(
            Name::new_unchecked("a.example").into_owned(),
            CLASS::IN,
            5,
            RData::NULL(4242, rdata::NULL::new(&[1, 2, 255]).unwrap().into_owned()),
        );
        let json = DohRecordJson::from_record(&record);
        assert_eq!(json.name, "a.example.");
        assert_eq!(json.record_type, 4242);
        assert_eq!(json.data, "\\# 3 0102ff");
    }
}
