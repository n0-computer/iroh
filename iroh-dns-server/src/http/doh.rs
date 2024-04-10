//! DNS over HTTPS

// This module is mostly copied from
// https://github.com/fission-codes/fission-server/blob/main/fission-server/src/routes/doh.rs

use anyhow::anyhow;
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use hickory_server::proto::{self, serialize::binary::BinDecodable};
use http::{
    header::{CACHE_CONTROL, CONTENT_TYPE},
    HeaderValue, StatusCode,
};

use crate::state::AppState;

use super::error::AppResult;

mod extract;
mod response;

use self::extract::{DnsMimeType, DnsRequestBody, DnsRequestQuery};

/// GET handler for resolving DoH queries
pub async fn get(
    State(state): State<AppState>,
    DnsRequestQuery(request, accept_type): DnsRequestQuery,
) -> AppResult<Response> {
    let message_bytes = state.dns_handler.answer_request(request).await?;
    let message = proto::op::Message::from_bytes(&message_bytes).map_err(|e| anyhow!(e))?;

    let min_ttl = message.answers().iter().map(|rec| rec.ttl()).min();

    let mut response = match accept_type {
        DnsMimeType::Message => (StatusCode::OK, message_bytes).into_response(),
        DnsMimeType::Json => {
            let response = self::response::DnsResponse::from_message(message)?;
            (StatusCode::OK, Json(response)).into_response()
        }
    };

    response
        .headers_mut()
        .insert(CONTENT_TYPE, accept_type.to_header_value());

    if let Some(min_ttl) = min_ttl {
        let maxage =
            HeaderValue::from_str(&format!("s-maxage={min_ttl}")).map_err(|e| anyhow!(e))?;
        response.headers_mut().insert(CACHE_CONTROL, maxage);
    }

    Ok(response)
}

/// POST handler for resolvng DoH queries
pub async fn post(
    State(state): State<AppState>,
    DnsRequestBody(request): DnsRequestBody,
) -> Response {
    let response = match state.dns_handler.answer_request(request).await {
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
