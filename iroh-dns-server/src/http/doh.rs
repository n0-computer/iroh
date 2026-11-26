//! DNS over HTTPS

// This module is mostly copied from
// https://github.com/fission-codes/fission-server/blob/main/fission-server/src/routes/doh.rs

use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use http::{
    HeaderValue, StatusCode,
    header::{CACHE_CONTROL, CONTENT_TYPE},
};
use n0_error::StdResultExt;

use self::{
    extract::{DnsMimeType, DnsRequestBody, DnsRequestQuery},
    response::DnsResponse,
};
use super::error::{AppError, AppResult};
use crate::{dns::Protocol, state::AppState};

mod extract;
pub(crate) mod response;

/// GET handler for resolving DoH queries
pub(super) async fn get(
    State(state): State<AppState>,
    DnsRequestQuery(request, accept_type): DnsRequestQuery,
) -> AppResult<Response> {
    let (message, max_len) = state
        .dns_handler
        .answer(&request, Protocol::Https)
        .await
        .ok_or_else(invalid_message)?;

    let min_ttl = message.answers.iter().map(|rec| rec.ttl).min();

    let mut response = match accept_type {
        DnsMimeType::Message => (StatusCode::OK, message.encode(max_len)).into_response(),
        DnsMimeType::Json => {
            let response = DnsResponse::from_response(&message);
            (StatusCode::OK, Json(response)).into_response()
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
pub(super) async fn post(
    State(state): State<AppState>,
    DnsRequestBody(request): DnsRequestBody,
) -> Response {
    let Some(response) = state
        .dns_handler
        .answer_bytes(&request, Protocol::Https)
        .await
    else {
        return invalid_message().into_response();
    };

    (
        StatusCode::OK,
        [(CONTENT_TYPE, DnsMimeType::Message.to_string())],
        response,
    )
        .into_response()
}

fn invalid_message() -> AppError {
    AppError::new(
        StatusCode::BAD_REQUEST,
        Some("Invalid DNS message: expected query"),
    )
}

// TODO: Port tests from
// https://github.com/fission-codes/fission-server/blob/main/fission-server/src/routes/doh.rs
