use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug)]
pub struct GatewayError {
    pub status_code: StatusCode,
    pub message: String,
    pub trace_id: String,
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
        match self.method {
            Some(http::Method::HEAD) => (self.status_code).into_response(),
            _ => {
                let body = axum::Json(json!({
                    "code": self.status_code.as_u16(),
                    "success": false,
                    "message": self.message,
                    "trace_id": self.trace_id,
                }));
                (self.status_code, body).into_response()
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
