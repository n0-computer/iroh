//! DNS Response

// This module is mostly copied from
// https://github.com/fission-codes/fission-server/blob/394de877fad021260c69fdb1edd7bb4b2f98108c/fission-core/src/dns.rs

use anyhow::{anyhow, ensure, Result};
use hickory_proto as proto;
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
    /// Create a new JSON response from a DNS message
    pub fn from_message(message: proto::op::Message) -> Result<Self> {
        ensure!(
            message.message_type() == proto::op::MessageType::Response,
            "Expected message type to be response"
        );

        ensure!(
            message.query_count() == message.queries().len() as u16,
            "Query count mismatch"
        );

        ensure!(
            message.answer_count() == message.answers().len() as u16,
            "Answer count mismatch"
        );

        let status: u32 =
            <u16 as From<proto::op::ResponseCode>>::from(message.response_code()) as u32;

        let question: Vec<_> = message
            .queries()
            .iter()
            .map(DohQuestionJson::from_query)
            .collect();

        let answer: Vec<_> = message
            .answers()
            .iter()
            .map(DohRecordJson::from_record)
            .collect::<Result<_>>()?;

        Ok(DnsResponse {
            status,
            tc: message.truncated(),
            rd: message.recursion_desired(),
            ra: message.recursion_available(),
            ad: message.authentic_data(),
            cd: message.checking_disabled(),
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

impl DohQuestionJson {
    /// Create a new JSON question from a DNS query
    pub fn from_query(query: &proto::op::Query) -> Self {
        Self {
            name: query.name().to_string(),
            question_type: query.query_type().into(),
        }
    }
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

impl DohRecordJson {
    /// Create a new JSON record from a DNS record
    pub fn from_record(record: &proto::rr::Record) -> Result<Self> {
        let data = record
            .data()
            .ok_or_else(|| anyhow!("Missing record data"))?;

        Ok(Self {
            name: record.name().to_string(),
            record_type: record.record_type().into(),
            ttl: record.ttl(),
            data: data.to_string(),
        })
    }
}
