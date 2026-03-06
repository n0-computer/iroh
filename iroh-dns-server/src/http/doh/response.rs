//! DNS Response

// This module is mostly copied from
// https://github.com/fission-codes/fission-server/blob/394de877fad021260c69fdb1edd7bb4b2f98108c/fission-core/src/dns.rs

use domain::base::{Message, iana::Rtype};
use n0_error::{Result, ensure_any};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
/// JSON representation of a DNS response
/// See: <https://developers.google.com/speed/public-dns/docs/doh/json>
pub struct DnsResponse {
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
    /// Create a new JSON response from raw DNS message bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let message = Message::from_octets(bytes.to_vec())
            .map_err(|_| n0_error::anyerr!("invalid DNS message"))?;

        let header = message.header();

        ensure_any!(header.qr(), "Expected message to be a response");

        let status = header.rcode().to_int() as u32;

        let question: Vec<_> = message
            .question()
            .filter_map(|q| q.ok())
            .map(|q| DohQuestionJson {
                // domain crate's Display omits the trailing dot; DNS JSON format requires it
                name: format!("{}.", q.qname()),
                question_type: q.qtype().to_int(),
            })
            .collect();

        let answer_section = message
            .answer()
            .map_err(|e| n0_error::anyerr!("invalid answer section: {e}"))?;

        let mut answer = Vec::new();
        for record in answer_section {
            if let Ok(record) = record {
                let rtype = record.rtype();
                let owner = format!("{}.", record.owner());
                let ttl = record.ttl().as_secs() as u32;

                let data =
                    if rtype == Rtype::TXT {
                        // For TXT records, extract raw content without zone-file quoting
                        if let Ok(Some(txt_record)) =
                            record.to_record::<domain::rdata::Txt<&[u8]>>()
                        {
                            let mut bytes = Vec::new();
                            for cs in txt_record.data().iter() {
                                bytes.extend_from_slice(cs.as_ref());
                            }
                            String::from_utf8_lossy(&bytes).into_owned()
                        } else {
                            continue;
                        }
                    } else if let Ok(any_record) =
                        record.to_any_record::<domain::rdata::AllRecordData<
                            &[u8],
                            domain::base::name::ParsedName<&[u8]>,
                        >>()
                    {
                        any_record.data().to_string()
                    } else {
                        continue;
                    };

                answer.push(DohRecordJson {
                    name: owner,
                    record_type: rtype.to_int(),
                    ttl,
                    data,
                });
            }
        }

        Ok(DnsResponse {
            status,
            tc: header.tc(),
            rd: header.rd(),
            ra: header.ra(),
            ad: header.ad(),
            cd: header.cd(),
            question,
            answer,
            comment: None,
            edns_client_subnet: None,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
/// JSON representation of a DNS question
pub struct DohQuestionJson {
    /// FQDN with trailing dot
    pub name: String,
    /// Standard DNS RR type
    #[serde(rename = "type")]
    pub question_type: u16,
}

#[derive(Debug, Serialize, Deserialize)]
/// JSON representation of a DNS record
pub struct DohRecordJson {
    /// FQDN with trailing dot
    pub name: String,
    /// Standard DNS RR type
    #[serde(rename = "type")]
    pub record_type: u16,
    /// Time-to-live, in seconds
    #[serde(rename = "TTL")]
    pub ttl: u32,
    /// Record data
    pub data: String,
}
