//! Extractors for DNS-over-HTTPS requests

// This module is mostly copied from
// https://github.com/fission-codes/fission-server/blob/394de877fad021260c69fdb1edd7bb4b2f98108c/fission-server/src/extract/doh.rs

use std::{
    fmt::{self, Display, Formatter},
    future::Future,
    net::SocketAddr,
    str::FromStr,
};

use axum::{
    body::Body,
    extract::{ConnectInfo, FromRequest, FromRequestParts, Query},
    http::Request,
};
use bytes::Bytes;
use hickory_server::{
    net::xfer::Protocol,
    proto::{
        self,
        serialize::binary::{BinEncodable, BinEncoder},
    },
    server::Request as DNSRequest,
};
use http::{HeaderValue, StatusCode, header, request::Parts};
use serde::Deserialize;
use tracing::info;

use crate::http::error::AppError;

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
    dnssec_ok: Option<bool>,
    /// Privacy setting for how your IP address is forwarded to authoritative nameservers
    #[allow(dead_code)]
    edns_client_subnet: Option<String>,
    /// Some url-safe random characters to pad your messages for privacy (to avoid being fingerprinted by encrypted message length)
    #[allow(dead_code)]
    random_padding: Option<String>,
    /// Whether to provide answers for all records up to the root
    #[serde(rename = "rd")]
    recursion_desired: Option<bool>,
}

/// A DNS request encoded in the query string
#[derive(Debug)]
pub(crate) struct DnsRequestQuery(pub(super) DNSRequest, pub(super) DnsMimeType);

/// A DNS request encoded in the body
#[derive(Debug)]
pub(crate) struct DnsRequestBody(pub(crate) DNSRequest);

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
            let ConnectInfo(src_addr) = ConnectInfo::from_request_parts(parts, state).await?;

            match parts.headers.get(header::ACCEPT) {
                Some(content_type) if content_type == "application/dns-message" => {
                    handle_dns_message_query(parts, state, src_addr).await
                }
                Some(content_type) if content_type == "application/dns-json" => {
                    handle_dns_json_query(parts, state, src_addr).await
                }
                Some(content_type) if content_type == "application/x-javascript" => {
                    handle_dns_json_query(parts, state, src_addr).await
                }
                None => handle_dns_message_query(parts, state, src_addr).await,
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
            let (mut parts, body) = req.into_parts();

            let ConnectInfo(src_addr) = ConnectInfo::from_request_parts(&mut parts, state).await?;

            let req = Request::from_parts(parts, body);

            let body = Bytes::from_request(req, state)
                .await
                .map_err(|_| AppError::with_status(StatusCode::INTERNAL_SERVER_ERROR))?;

            let request = decode_request(&body, src_addr)?;

            Ok(DnsRequestBody(request))
        }
    }
}

async fn handle_dns_message_query<S>(
    parts: &mut Parts,
    state: &S,
    src_addr: SocketAddr,
) -> Result<DnsRequestQuery, AppError>
where
    S: Send + Sync,
{
    let Query(params) = Query::<DnsMessageQuery>::from_request_parts(parts, state).await?;

    let buf = base64_url::decode(params.dns.as_bytes())
        .map_err(|err| AppError::new(StatusCode::BAD_REQUEST, Some(err)))?;

    let request = decode_request(&buf, src_addr)?;

    Ok(DnsRequestQuery(request, DnsMimeType::Message))
}

async fn handle_dns_json_query<S>(
    parts: &mut Parts,
    state: &S,
    src_addr: SocketAddr,
) -> Result<DnsRequestQuery, AppError>
where
    S: Send + Sync,
{
    let Query(dns_query) = Query::<DnsQuery>::from_request_parts(parts, state).await?;

    let request = encode_query_as_request(dns_query, src_addr)?;

    Ok(DnsRequestQuery(request, DnsMimeType::Json))
}

/// Exposed to make it usable internally...
fn encode_query_as_request(
    question: DnsQuery,
    src_addr: SocketAddr,
) -> Result<DNSRequest, AppError> {
    let query_type = if let Some(record_type) = question.record_type {
        record_type
            .parse::<u16>()
            .map(proto::rr::RecordType::from)
            .or_else(|_| FromStr::from_str(&record_type.to_uppercase()))
            .map_err(|err| AppError::new(StatusCode::BAD_REQUEST, Some(err)))?
    } else {
        proto::rr::RecordType::A
    };

    let name = proto::rr::Name::from_utf8(question.name)
        .map_err(|err| AppError::new(StatusCode::BAD_REQUEST, Some(err)))?;

    let query = proto::op::Query::query(name, query_type);

    let mut message = proto::op::Message::query();
    message.metadata.checking_disabled = question.cd.unwrap_or(false);
    message.metadata.recursion_desired = question.recursion_desired.unwrap_or(true);
    message.metadata.recursion_available = true;
    message.metadata.authentic_data = question.dnssec_ok.unwrap_or(false);
    message.add_query(query);

    // This is kind of a hack, but the only way I can find to
    // create a MessageRequest is by decoding a buffer of bytes,
    // so we encode the message into a buffer and then decode it
    let mut buf = Vec::with_capacity(4096);
    let mut encoder = BinEncoder::new(&mut buf);

    message
        .emit(&mut encoder)
        .map_err(|err| AppError::new(StatusCode::BAD_REQUEST, Some(err)))?;

    let request = decode_request(&buf, src_addr)?;

    Ok(request)
}

fn decode_request(bytes: &[u8], src_addr: SocketAddr) -> Result<DNSRequest, AppError> {
    match DNSRequest::from_bytes(bytes.to_vec(), src_addr, Protocol::Https) {
        Ok(request) => {
            info!("received message {:?}", *request);
            if request.metadata.message_type != proto::op::MessageType::Query {
                return Err(AppError::new(
                    StatusCode::BAD_REQUEST,
                    Some("Invalid message type: expected query"),
                ));
            }
            Ok(request)
        }
        Err(err) => Err(AppError::new(
            StatusCode::BAD_REQUEST,
            Some(format!("Invalid DNS message: {err}")),
        )),
    }
}
