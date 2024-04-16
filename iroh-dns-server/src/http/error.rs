use axum::{
    extract::rejection::{ExtensionRejection, QueryRejection},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppError {
    #[serde(with = "serde_status_code")]
    status: StatusCode,
    detail: Option<String>,
}

impl Default for AppError {
    fn default() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            detail: None,
        }
    }
}

impl AppError {
    pub fn with_status(status: StatusCode) -> AppError {
        Self {
            status,
            detail: None,
        }
    }

    /// Create a new [`AppError`].
    pub fn new(status_code: StatusCode, message: Option<impl ToString>) -> AppError {
        Self {
            status: status_code,
            // title: Self::canonical_reason_to_string(&status_code),
            detail: message.map(|m| m.to_string()),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let json = Json(self.clone());
        (self.status, json).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(value: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            detail: Some(value.to_string()),
        }
    }
}

impl From<QueryRejection> for AppError {
    fn from(value: QueryRejection) -> Self {
        Self::new(StatusCode::BAD_REQUEST, Some(value))
    }
}

impl From<ExtensionRejection> for AppError {
    fn from(value: ExtensionRejection) -> Self {
        Self::new(StatusCode::BAD_REQUEST, Some(value))
    }
}

/// Serialize/Deserializer for status codes.
///
/// This is needed because status code according to JSON API spec must
/// be the status code as a STRING.
///
/// We could have used http_serde, but it encodes the status code as a NUMBER.
pub mod serde_status_code {
    use http::StatusCode;
    use serde::{de::Unexpected, Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize [StatusCode]s.
    pub fn serialize<S: Serializer>(status: &StatusCode, ser: S) -> Result<S::Ok, S::Error> {
        String::serialize(&status.as_u16().to_string(), ser)
    }

    /// Deserialize [StatusCode]s.
    pub fn deserialize<'de, D>(de: D) -> Result<StatusCode, D::Error>
    where
        D: Deserializer<'de>,
    {
        let str = String::deserialize(de)?;
        StatusCode::from_bytes(str.as_bytes()).map_err(|_| {
            serde::de::Error::invalid_value(
                Unexpected::Str(str.as_str()),
                &"A valid http status code",
            )
        })
    }
}
