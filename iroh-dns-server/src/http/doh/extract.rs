//! Extractors for DNS-over-HTTPS requests

// This module is mostly copied from
// https://github.com/fission-codes/fission-server/blob/394de877fad021260c69fdb1edd7bb4b2f98108c/fission-server/src/extract/doh.rs

use std::{
    fmt::{self, Display, Formatter},
    future::Future,
};

use axum::{
    body::Body,
    extract::{FromRequest, FromRequestParts, Query},
    http::Request,
};
use bytes::Bytes;
use domain::base::{
    Message, MessageBuilder,
    iana::{Opcode, Rtype},
    name::Name,
    question::Question,
};
use http::{HeaderValue, StatusCode, header, request::Parts};
use serde::Deserialize;
use tracing::info;

use crate::http::error::AppError;

/// A DNS packet encoding type
#[derive(Debug)]
pub enum DnsMimeType {
    /// application/dns-message
    Message,
    /// application/dns-json
    Json,
}

impl Display for DnsMimeType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            DnsMimeType::Message => write!(f, "application/dns-message"),
            DnsMimeType::Json => write!(f, "application/dns-json"),
        }
    }
}

impl DnsMimeType {
    /// Turn this mime type to an `Accept` HTTP header value
    pub fn to_header_value(&self) -> HeaderValue {
        HeaderValue::from_static(match self {
            Self::Message => "application/dns-message",
            Self::Json => "application/dns-json",
        })
    }
}

#[derive(Debug, Deserialize)]
struct DnsMessageQuery {
    dns: String,
}

// See: https://developers.google.com/speed/public-dns/docs/doh/json#supported_parameters
#[derive(Debug, Deserialize)]
pub struct DnsQuery {
    /// Record name to look up, e.g. example.com
    pub name: String,
    /// Record type, e.g. A/AAAA/TXT, etc.
    #[serde(rename = "type")]
    pub record_type: Option<String>,
    /// Used to disable DNSSEC validation
    pub cd: Option<bool>,
    /// Desired content type. E.g. "application/dns-message" or "application/dns-json"
    #[allow(dead_code)]
    pub ct: Option<String>,
    /// Whether to return DNSSEC entries such as RRSIG, NSEC or NSEC3
    #[serde(rename = "do")]
    pub dnssec_ok: Option<bool>,
    /// Privacy setting for how your IP address is forwarded to authoritative nameservers
    #[allow(dead_code)]
    pub edns_client_subnet: Option<String>,
    /// Some url-safe random characters to pad your messages for privacy (to avoid being fingerprinted by encrypted message length)
    #[allow(dead_code)]
    pub random_padding: Option<String>,
    /// Whether to provide answers for all records up to the root
    #[serde(rename = "rd")]
    pub recursion_desired: Option<bool>,
}

/// A DNS request encoded in the query string.
/// Contains the raw DNS query bytes and the accepted response MIME type.
#[derive(Debug)]
pub struct DnsRequestQuery(pub(crate) Vec<u8>, pub(crate) DnsMimeType);

/// A DNS request encoded in the body.
/// Contains the raw DNS query bytes.
#[derive(Debug)]
pub struct DnsRequestBody(pub(crate) Vec<u8>);

impl<S> FromRequestParts<S> for DnsRequestQuery
where
    S: Send + Sync,
{
    type Rejection = AppError;

    #[allow(clippy::manual_async_fn)]
    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        async move {
            match parts.headers.get(header::ACCEPT) {
                Some(content_type) if content_type == "application/dns-message" => {
                    handle_dns_message_query(parts, state).await
                }
                Some(content_type) if content_type == "application/dns-json" => {
                    handle_dns_json_query(parts, state).await
                }
                Some(content_type) if content_type == "application/x-javascript" => {
                    handle_dns_json_query(parts, state).await
                }
                None => handle_dns_message_query(parts, state).await,
                _ => Err(AppError::with_status(StatusCode::NOT_ACCEPTABLE)),
            }
        }
    }
}

impl<S> FromRequest<S> for DnsRequestBody
where
    S: Send + Sync,
{
    type Rejection = AppError;

    #[allow(clippy::manual_async_fn)]
    fn from_request(
        req: Request<Body>,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        async move {
            let (parts, body) = req.into_parts();
            let req = Request::from_parts(parts, body);

            let body = Bytes::from_request(req, state)
                .await
                .map_err(|_| AppError::with_status(StatusCode::INTERNAL_SERVER_ERROR))?;

            // Validate that it's a valid DNS message
            validate_dns_query(&body)?;

            Ok(DnsRequestBody(body.to_vec()))
        }
    }
}

async fn handle_dns_message_query<S>(
    parts: &mut Parts,
    state: &S,
) -> Result<DnsRequestQuery, AppError>
where
    S: Send + Sync,
{
    let Query(params) = Query::<DnsMessageQuery>::from_request_parts(parts, state).await?;

    let buf = base64_url::decode(params.dns.as_bytes())
        .map_err(|err| AppError::new(StatusCode::BAD_REQUEST, Some(err)))?;

    validate_dns_query(&buf)?;

    Ok(DnsRequestQuery(buf, DnsMimeType::Message))
}

async fn handle_dns_json_query<S>(parts: &mut Parts, state: &S) -> Result<DnsRequestQuery, AppError>
where
    S: Send + Sync,
{
    let Query(dns_query) = Query::<DnsQuery>::from_request_parts(parts, state).await?;

    let query_bytes = encode_query_as_bytes(dns_query)?;

    Ok(DnsRequestQuery(query_bytes, DnsMimeType::Json))
}

/// Build DNS query wire-format bytes from a JSON query.
pub(crate) fn encode_query_as_bytes(question: DnsQuery) -> Result<Vec<u8>, AppError> {
    let query_type = if let Some(record_type) = question.record_type {
        // Try parsing as a number first, then as a string
        if let Ok(num) = record_type.parse::<u16>() {
            Rtype::from_int(num)
        } else {
            parse_rtype_name(&record_type.to_uppercase()).ok_or_else(|| {
                AppError::new(
                    StatusCode::BAD_REQUEST,
                    Some(format!("Unknown record type: {record_type}")),
                )
            })?
        }
    } else {
        Rtype::A
    };

    let name: Name<Vec<u8>> =
        question
            .name
            .parse()
            .map_err(|err: domain::base::name::FromStrError| {
                AppError::new(StatusCode::BAD_REQUEST, Some(err.to_string()))
            })?;

    let mut builder = MessageBuilder::new_vec();
    builder.header_mut().set_opcode(Opcode::QUERY);
    builder
        .header_mut()
        .set_rd(question.recursion_desired.unwrap_or(true));
    builder.header_mut().set_cd(question.cd.unwrap_or(false));
    builder
        .header_mut()
        .set_ad(question.dnssec_ok.unwrap_or(false));

    let mut question_builder = builder.question();
    question_builder.header_mut().set_opcode(Opcode::QUERY);
    question_builder
        .header_mut()
        .set_rd(question.recursion_desired.unwrap_or(true));
    question_builder
        .header_mut()
        .set_cd(question.cd.unwrap_or(false));
    question_builder
        .header_mut()
        .set_ad(question.dnssec_ok.unwrap_or(false));

    question_builder
        .push(Question::new_in(name, query_type))
        .map_err(|e| AppError::new(StatusCode::BAD_REQUEST, Some(e.to_string())))?;

    let message = question_builder.into_message();
    Ok(message.into_octets())
}

/// Validate that bytes contain a valid DNS query message.
fn validate_dns_query(bytes: &[u8]) -> Result<(), AppError> {
    let message = Message::from_octets(bytes.to_vec())
        .map_err(|_| AppError::new(StatusCode::BAD_REQUEST, Some("Invalid DNS message")))?;

    info!("received DNS query message: {:?}", message.header());

    if message.header().qr() {
        return Err(AppError::new(
            StatusCode::BAD_REQUEST,
            Some("Invalid message type: expected query"),
        ));
    }

    Ok(())
}

/// Parse a record type name string (e.g. "A", "AAAA", "TXT") to Rtype.
fn parse_rtype_name(name: &str) -> Option<Rtype> {
    match name {
        "A" => Some(Rtype::A),
        "AAAA" => Some(Rtype::AAAA),
        "TXT" => Some(Rtype::TXT),
        "MX" => Some(Rtype::MX),
        "NS" => Some(Rtype::NS),
        "SOA" => Some(Rtype::SOA),
        "CNAME" => Some(Rtype::CNAME),
        "SRV" => Some(Rtype::SRV),
        "PTR" => Some(Rtype::PTR),
        "CAA" => Some(Rtype::CAA),
        _ => None,
    }
}
