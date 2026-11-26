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
use http::{HeaderValue, StatusCode, header, request::Parts};
use serde::Deserialize;

use crate::{
    dns::message::{self, DnsName},
    http::error::AppError,
};

/// A DNS packet encoding type
#[derive(Debug)]
pub(super) enum DnsMimeType {
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
    pub(super) fn to_header_value(&self) -> HeaderValue {
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
struct DnsQuery {
    /// Record name to look up, e.g. example.com
    name: String,
    /// Record type, e.g. A/AAAA/TXT, etc.
    #[serde(rename = "type")]
    record_type: Option<String>,
    /// Used to disable DNSSEC validation
    cd: Option<bool>,
    /// Desired content type. E.g. "application/dns-message" or "application/dns-json"
    #[allow(dead_code)]
    ct: Option<String>,
    /// Whether to return DNSSEC entries such as RRSIG, NSEC or NSEC3
    #[serde(rename = "do")]
    #[allow(dead_code)]
    dnssec_ok: Option<bool>,
    /// Privacy setting for how your IP address is forwarded to authoritative nameservers
    #[allow(dead_code)]
    edns_client_subnet: Option<String>,
    /// Some url-safe random characters to pad your messages for privacy (to avoid being fingerprinted by encrypted message length)
    #[allow(dead_code)]
    random_padding: Option<String>,
    /// Whether to provide answers for all records up to the root
    #[serde(rename = "rd")]
    #[allow(dead_code)]
    recursion_desired: Option<bool>,
}

/// A wire-format DNS request encoded in the query string
#[derive(Debug)]
pub(crate) struct DnsRequestQuery(pub(super) Bytes, pub(super) DnsMimeType);

/// A wire-format DNS request encoded in the body
#[derive(Debug)]
pub(crate) struct DnsRequestBody(pub(crate) Bytes);

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
            let body = Bytes::from_request(req, state)
                .await
                .map_err(|_| AppError::with_status(StatusCode::INTERNAL_SERVER_ERROR))?;

            Ok(DnsRequestBody(body))
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

    Ok(DnsRequestQuery(buf.into(), DnsMimeType::Message))
}

async fn handle_dns_json_query<S>(parts: &mut Parts, state: &S) -> Result<DnsRequestQuery, AppError>
where
    S: Send + Sync,
{
    let Query(dns_query) = Query::<DnsQuery>::from_request_parts(parts, state).await?;

    let request = encode_query_as_request(dns_query)?;

    Ok(DnsRequestQuery(request, DnsMimeType::Json))
}

/// Encodes a JSON API query as a wire-format DNS query.
fn encode_query_as_request(question: DnsQuery) -> Result<Bytes, AppError> {
    let query_type = match question.record_type {
        Some(record_type) => parse_record_type(&record_type).ok_or_else(|| {
            AppError::new(
                StatusCode::BAD_REQUEST,
                Some(format!("unknown record type: {record_type}")),
            )
        })?,
        None => 1, // A
    };

    let name = DnsName::parse(&question.name)
        .map_err(|err| AppError::new(StatusCode::BAD_REQUEST, Some(err)))?;

    let query = message::Query::new(name, query_type, question.cd.unwrap_or(false));
    Ok(message::encode_query(&query).into())
}

/// Parses a record type given by number or mnemonic.
fn parse_record_type(s: &str) -> Option<u16> {
    if let Ok(code) = s.parse::<u16>() {
        return Some(code);
    }
    let upper = s.to_ascii_uppercase();
    if let Some(code) = upper.strip_prefix("TYPE") {
        return code.parse().ok();
    }
    Some(match upper.as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "HINFO" => 13,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "LOC" => 29,
        "SRV" => 33,
        "NAPTR" => 35,
        "CERT" => 37,
        "DNAME" => 39,
        "DS" => 43,
        "SSHFP" => 44,
        "RRSIG" => 46,
        "NSEC" => 47,
        "DNSKEY" => 48,
        "TLSA" => 52,
        "SVCB" => 64,
        "HTTPS" => 65,
        "ANY" => 255,
        "CAA" => 257,
        _ => return None,
    })
}
