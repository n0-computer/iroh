use axum::body::HttpBody;
use axum::{
    body,
    body::BoxBody,
    http::{header::*, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use bytes::Bytes;
use iroh_metrics::get_current_trace_id;
use opentelemetry::trace::TraceId;
use std::error::Error;

use crate::constants::*;

pub const ERR_UNSUPPORTED_FORMAT: &str = "unsuported format";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseFormat {
    Raw,
    Car,
    Fs(String),
}

impl std::convert::TryFrom<&str> for ResponseFormat {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "application/vnd.ipld.raw" | "raw" => Ok(ResponseFormat::Raw),
            "application/vnd.ipld.car" | "car" => Ok(ResponseFormat::Car),
            "fs" | "" => Ok(ResponseFormat::Fs(String::new())),
            rf => {
                if rf.starts_with("application/vnd.ipld.") {
                    Ok(ResponseFormat::Fs(rf.to_string()))
                } else {
                    Err(format!("{}: {}", ERR_UNSUPPORTED_FORMAT, rf))
                }
            }
        }
    }
}

impl ResponseFormat {
    pub fn write_headers(&self, headers: &mut HeaderMap) {
        match self {
            ResponseFormat::Raw => {
                headers.insert(CONTENT_TYPE, CONTENT_TYPE_IPLD_RAW.clone());
                headers.insert(&HEADER_X_CONTENT_TYPE_OPTIONS, VALUE_XCTO_NOSNIFF.clone());
            }
            ResponseFormat::Car => {
                headers.insert(CONTENT_TYPE, CONTENT_TYPE_IPLD_CAR.clone());
                headers.insert(&HEADER_X_CONTENT_TYPE_OPTIONS, VALUE_XCTO_NOSNIFF.clone());
                headers.insert(ACCEPT_RANGES, VALUE_NONE.clone());
            }
            ResponseFormat::Fs(_) => {
                // Don't send application/octet-stream in that case, let the
                // client decide instead.
            }
        }
    }

    pub fn get_extenstion(&self) -> String {
        match self {
            ResponseFormat::Raw => "bin".to_string(),
            ResponseFormat::Car => "car".to_string(),
            ResponseFormat::Fs(s) => {
                if s.is_empty() {
                    String::new()
                } else {
                    s.split('.').last().unwrap().to_string()
                }
            }
        }
    }

    pub fn try_from_headers(headers: &HeaderMap) -> Result<Self, String> {
        if headers.contains_key("Accept") {
            if let Some(h_values) = headers.get("Accept") {
                let h_values = h_values.to_str().unwrap().split(',');
                for h_value in h_values {
                    let h_value = h_value.trim();
                    if h_value.starts_with("application/vnd.ipld.") {
                        return ResponseFormat::try_from(h_value);
                    }
                }
            }
        }
        Ok(ResponseFormat::Fs(String::new()))
    }
}

#[tracing::instrument()]
pub fn get_response_format(
    request_headers: &HeaderMap,
    query_format: &Option<String>,
) -> Result<ResponseFormat, String> {
    if let Some(format) = query_format {
        if !format.is_empty() {
            if let Ok(format) = ResponseFormat::try_from(format.as_str()) {
                return Ok(format);
            }
        }
    }

    ResponseFormat::try_from_headers(request_headers)
        .or_else(|_| Ok(ResponseFormat::Fs(String::new())))
}

#[derive(Debug)]
pub struct GatewayResponse {
    pub status_code: StatusCode,
    pub body: BoxBody,
    pub headers: HeaderMap,
    pub trace_id: TraceId,
}

impl IntoResponse for GatewayResponse {
    fn into_response(mut self) -> Response {
        if self.status_code == StatusCode::SEE_OTHER {
            if let Some(ref path) = self.headers.remove(LOCATION) {
                if let Ok(path) = path.to_str() {
                    return Redirect::to(path).into_response();
                }
            }
        }
        let mut rb = Response::builder().status(self.status_code);
        if self.trace_id != TraceId::INVALID {
            self.headers.insert(
                &HEADER_X_TRACE_ID,
                HeaderValue::from_str(&self.trace_id.to_string()).unwrap(),
            );
        }
        let rh = rb.headers_mut().unwrap();
        rh.extend(self.headers);
        rb.body(self.body).unwrap()
    }
}

impl GatewayResponse {
    #[tracing::instrument(skip(body))]
    pub fn new<B>(status_code: StatusCode, body: B, headers: HeaderMap) -> GatewayResponse
    where
        B: 'static + HttpBody<Data = Bytes> + Send,
        <B as HttpBody>::Error: Into<Box<dyn Error + Send + Sync + 'static>>,
    {
        GatewayResponse {
            status_code,
            body: body::boxed(body),
            headers,
            trace_id: get_current_trace_id(),
        }
    }

    fn _redirect(to: &str, status_code: StatusCode) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(LOCATION, HeaderValue::from_str(to).unwrap());
        Self::new(status_code, BoxBody::default(), headers)
    }

    pub fn empty(headers: HeaderMap) -> Self {
        Self::new(StatusCode::OK, BoxBody::default(), headers)
    }

    pub fn redirect(to: &str) -> Self {
        Self::_redirect(to, StatusCode::SEE_OTHER)
    }

    pub fn redirect_permanently(to: &str) -> Self {
        Self::_redirect(to, StatusCode::MOVED_PERMANENTLY)
    }

    pub fn not_modified() -> Self {
        Self::new(
            StatusCode::NOT_MODIFIED,
            BoxBody::default(),
            HeaderMap::new(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_format_try_from() {
        let rf = ResponseFormat::try_from("raw");
        assert_eq!(rf, Ok(ResponseFormat::Raw));
        let rf = ResponseFormat::try_from("car");
        assert_eq!(rf, Ok(ResponseFormat::Car));
        let rf = ResponseFormat::try_from("fs");
        assert_eq!(rf, Ok(ResponseFormat::Fs(String::new())));
        let rf = ResponseFormat::try_from("");
        assert_eq!(rf, Ok(ResponseFormat::Fs(String::new())));

        let rf = ResponseFormat::try_from("RaW");
        assert_eq!(rf, Ok(ResponseFormat::Raw));

        let rf = ResponseFormat::try_from("UNKNOWN");
        assert!(rf.is_err());
    }

    #[test]
    fn response_format_write_headers() {
        let rf = ResponseFormat::try_from("raw").unwrap();
        let mut headers = HeaderMap::new();
        rf.write_headers(&mut headers);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers.get(&CONTENT_TYPE).unwrap(), &CONTENT_TYPE_IPLD_RAW);
        assert_eq!(
            headers.get(&HEADER_X_CONTENT_TYPE_OPTIONS).unwrap(),
            &VALUE_XCTO_NOSNIFF
        );

        let rf = ResponseFormat::try_from("car").unwrap();
        let mut headers = HeaderMap::new();
        rf.write_headers(&mut headers);
        assert_eq!(headers.len(), 3);
        assert_eq!(headers.get(&CONTENT_TYPE).unwrap(), &CONTENT_TYPE_IPLD_CAR);
        assert_eq!(
            headers.get(&HEADER_X_CONTENT_TYPE_OPTIONS).unwrap(),
            &VALUE_XCTO_NOSNIFF
        );

        let rf = ResponseFormat::try_from("fs").unwrap();
        let mut headers = HeaderMap::new();
        rf.write_headers(&mut headers);
        assert_eq!(headers.len(), 0);
    }
}
