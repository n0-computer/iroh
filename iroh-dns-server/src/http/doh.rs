//! DNS over HTTPS
//!
//! Mostly copied from
//! https://github.com/fission-codes/fission-server/blob/main/fission-server/src/routes/doh.rs

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

// TODO: These tests were copied from fission-server, check and enable.
// #[cfg(test)]
// mod tests {
//     use crate::{db::schema::accounts, test_utils::test_context::TestContext};
//     use diesel::ExpressionMethods;
//     use diesel_async::RunQueryDsl;
//     use http::{Method, StatusCode};
//     use mime::Mime;
//     use pretty_assertions::assert_eq;
//     use serde_json::json;
//     use std::str::FromStr;
//     use testresult::TestResult;
//
//     #[test_log::test(tokio::test)]
//     async fn test_dns_json_soa() -> TestResult {
//         let ctx = &TestContext::new().await?;
//
//         let (status, body) = ctx
//             .request(
//                 Method::GET,
//                 format!("/dns-query?name={}&type={}", "localhost", "soa"),
//             )
//             .with_accept_mime(Mime::from_str("application/dns-json")?)
//             .into_json_response::<serde_json::Value>()
//             .await?;
//
//         assert_eq!(status, StatusCode::OK);
//         assert_eq!(
//             body,
//             json!(
//                 {
//                   "Status": 0,
//                   "TC": false,
//                   "RD": true,
//                   "RA": false,
//                   "AD": false,
//                   "CD": false,
//                   "Question": [
//                     {
//                       "name": "localhost.",
//                       "type": 6
//                     }
//                   ],
//                   "Answer": [
//                     {
//                       "name": "localhost.",
//                       "type": 6,
//                       "TTL": 1800,
//                       "data": "dns1.fission.systems. hostmaster.fission.codes. 0 10800 3600 604800 3600"
//                     }
//                   ],
//                   "Comment": null,
//                   "edns_client_subnet": null
//                 }
//             ),
//         );
//
//         Ok(())
//     }
//
//     #[test_log::test(tokio::test)]
//     async fn test_dns_json_did_username_ok() -> TestResult {
//         let ctx = &TestContext::new().await?;
//         let conn = &mut ctx.get_db_conn().await?;
//
//         let username = "donnie";
//         let email = "donnie@example.com";
//         let did = "did:28:06:42:12";
//
//         diesel::insert_into(accounts::table)
//             .values((
//                 accounts::username.eq(username),
//                 accounts::email.eq(email),
//                 accounts::did.eq(did),
//             ))
//             .execute(conn)
//             .await?;
//
//         let (status, body) = ctx
//             .request(
//                 Method::GET,
//                 format!(
//                     "/dns-query?name={}&type={}",
//                     format_args!("_did.{}.localhost", username),
//                     "txt"
//                 ),
//             )
//             .with_accept_mime(Mime::from_str("application/dns-json")?)
//             .into_json_response::<serde_json::Value>()
//             .await?;
//
//         assert_eq!(status, StatusCode::OK);
//         assert_eq!(
//             body,
//             json!(
//                 {
//                   "Status": 0,
//                   "TC": false,
//                   "RD": true,
//                   "RA": false,
//                   "AD": false,
//                   "CD": false,
//                   "Question": [
//                     {
//                       "name": "_did.donnie.localhost.",
//                       "type": 16
//                     }
//                   ],
//                   "Answer": [
//                     {
//                       "name": "_did.donnie.localhost.",
//                       "type": 16,
//                       "TTL": 1800,
//                       "data": "did:28:06:42:12"
//                     }
//                   ],
//                   "Comment": null,
//                   "edns_client_subnet": null
//                 }
//             ),
//         );
//
//         Ok(())
//     }
//
//     #[test_log::test(tokio::test)]
//     async fn test_dns_json_did_username_err_not_found() -> TestResult {
//         let ctx = &TestContext::new().await?;
//         let username = "donnie";
//
//         let (status, body) = ctx
//             .request(
//                 Method::GET,
//                 format!(
//                     "/dns-query?name={}&type={}",
//                     format_args!("_did.{}.localhost", username),
//                     "txt"
//                 ),
//             )
//             .with_accept_mime(Mime::from_str("application/dns-json")?)
//             .into_json_response::<serde_json::Value>()
//             .await?;
//
//         assert_eq!(status, StatusCode::OK);
//         assert_eq!(
//             body,
//             json!(
//                 {
//                   "Status": 0,
//                   "TC": false,
//                   "RD": true,
//                   "RA": false,
//                   "AD": false,
//                   "CD": false,
//                   "Question": [
//                     {
//                       "name": "_did.donnie.localhost.",
//                       "type": 16
//                     }
//                   ],
//                   "Comment": null,
//                   "edns_client_subnet": null
//                 }
//             ),
//         );
//
//         Ok(())
//     }
// }
