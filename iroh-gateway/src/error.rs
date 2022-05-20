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
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let body = axum::Json(json!({
            "code": self.status_code.as_u16(),
            "success": false,
            "message": self.message,
            "trace_id": self.trace_id,
        }));
        (self.status_code, body).into_response()
    }
}
