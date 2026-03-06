//! DNS over HTTPS

// This module is mostly copied from
// https://github.com/fission-codes/fission-server/blob/main/fission-server/src/routes/doh.rs

use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use domain::base::Message;
use http::{
    HeaderValue, StatusCode,
    header::{CACHE_CONTROL, CONTENT_TYPE},
};
use n0_error::StdResultExt;

use super::error::AppResult;
use crate::{dns::DnsProtocol, state::AppState};

mod extract;
mod response;

use self::extract::{DnsMimeType, DnsRequestBody, DnsRequestQuery};
#[cfg(test)]
pub(crate) use self::response::DnsResponse;

/// GET handler for resolving DoH queries
pub async fn get(
    State(state): State<AppState>,
    DnsRequestQuery(query_bytes, accept_type): DnsRequestQuery,
) -> AppResult<Response> {
    let response_bytes = state
        .dns_handler
        .answer(&query_bytes, DnsProtocol::Https)
        .await?;

    // Parse the response to extract TTL for cache headers
    let min_ttl = if let Ok(message) = Message::from_octets(response_bytes.to_vec()) {
        if let Ok(answer) = message.answer() {
            answer
                .into_iter()
                .filter_map(|r| r.ok())
                .map(|r| r.ttl().as_secs() as u32)
                .min()
        } else {
            None
        }
    } else {
        None
    };

    let mut response = match accept_type {
        DnsMimeType::Message => (StatusCode::OK, response_bytes).into_response(),
        DnsMimeType::Json => {
            let dns_response = self::response::DnsResponse::from_bytes(&response_bytes)?;
            (StatusCode::OK, Json(dns_response)).into_response()
        }
    };

    response
        .headers_mut()
        .insert(CONTENT_TYPE, accept_type.to_header_value());

    if let Some(min_ttl) = min_ttl {
        let maxage = HeaderValue::from_str(&format!("s-maxage={min_ttl}")).anyerr()?;
        response.headers_mut().insert(CACHE_CONTROL, maxage);
    }

    Ok(response)
}

/// POST handler for resolvng DoH queries
pub async fn post(
    State(state): State<AppState>,
    DnsRequestBody(query_bytes): DnsRequestBody,
) -> Response {
    let response = match state
        .dns_handler
        .answer(&query_bytes, DnsProtocol::Https)
        .await
    {
        Ok(response) => response,
        Err(err) => return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };

    (
        StatusCode::OK,
        [(CONTENT_TYPE, DnsMimeType::Message.to_string())],
        response,
    )
        .into_response()
}

// TODO: Port tests from
// https://github.com/fission-codes/fission-server/blob/main/fission-server/src/routes/doh.rs
