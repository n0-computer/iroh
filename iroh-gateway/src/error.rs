use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

use axum::{
    body::BoxBody,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use http::{HeaderMap, HeaderValue};
use opentelemetry::trace::TraceId;
use serde_json::json;

use crate::constants::HEADER_X_TRACE_ID;

#[derive(Debug)]
pub struct GatewayError {
    pub status_code: StatusCode,
    pub message: String,
    pub trace_id: TraceId,
    pub method: Option<http::Method>,
}

impl GatewayError {
    pub fn with_method(self, method: http::Method) -> Self {
        Self {
            method: Some(method),
            ..self
        }
    }
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let mut headers = HeaderMap::new();
        if self.trace_id != TraceId::INVALID {
            headers.insert(
                &HEADER_X_TRACE_ID,
                HeaderValue::from_str(&self.trace_id.to_string()).unwrap(),
            );
        }
        match self.method {
            Some(http::Method::HEAD) => {
                let mut rb = Response::builder().status(self.status_code);
                let rh = rb.headers_mut().unwrap();
                rh.extend(headers);
                rb.body(BoxBody::default()).unwrap()
            }
            _ => {
                let body = if self.trace_id != TraceId::INVALID {
                    axum::Json(json!({
                        "code": self.status_code.as_u16(),
                        "success": false,
                        "message": self.message,
                        "trace_id": self.trace_id.to_string(),
                    }))
                } else {
                    axum::Json(json!({
                        "code": self.status_code.as_u16(),
                        "success": false,
                        "message": self.message,
                    }))
                };
                let mut res = body.into_response();
                res.headers_mut().extend(headers);
                let status = res.status_mut();
                *status = self.status_code;
                res
            }
        }
    }
}

impl Display for GatewayError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "gateway_error({}): {})",
            &self.status_code, &self.message
        )
    }
}

impl Error for GatewayError {}
