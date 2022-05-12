use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use metrics::increment_counter;
use serde_json::json;

use crate::metrics::METRICS_FAIL;

#[derive(Debug)]
pub struct GatewayError {
    pub status_code: StatusCode,
    pub message: String,
    pub trace_id: String,
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        increment_counter!(METRICS_FAIL, "code" => self.status_code.as_u16().to_string());
        let body = axum::Json(json!({
            "code": self.status_code.as_u16(),
            "success": false,
            "message": self.message,
            "trace_id": self.trace_id,
        }));
        (self.status_code, body).into_response()
    }
}
