use std::{collections::HashMap, str::FromStr};

use axum::{
    body::BoxBody,
    http::{header::*, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

use crate::constants::*;

pub const ERR_UNSUPPORTED_FORMAT: &str = "unsuported format";

#[derive(Debug, Clone, PartialEq)]
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
    pub fn write_headers(&self, headers: &mut HashMap<String, String>) {
        match self {
            ResponseFormat::Raw => {
                headers.insert(CONTENT_TYPE.to_string(), CONTENT_TYPE_IPLD_RAW.to_string());
                headers.insert(
                    HEADER_X_CONTENT_TYPE_OPTIONS.to_string(),
                    VALUE_XCTO_NOSNIFF.to_string(),
                );
            }
            ResponseFormat::Car => {
                headers.insert(CONTENT_TYPE.to_string(), CONTENT_TYPE_IPLD_CAR.to_string());
                headers.insert(
                    HEADER_X_CONTENT_TYPE_OPTIONS.to_string(),
                    VALUE_XCTO_NOSNIFF.to_string(),
                );
                headers.insert(ACCEPT_RANGES.to_string(), "none".to_string());
                headers.insert(
                    CACHE_CONTROL.to_string(),
                    "no-cache, no-transform".to_string(),
                );
            }
            ResponseFormat::Fs(_) => {
                headers.insert(
                    CONTENT_TYPE.to_string(),
                    CONTENT_TYPE_OCTET_STREAM.to_string(),
                );
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
            let h_values = headers.get("Accept").unwrap().to_str().unwrap();
            let h_values = h_values.split(',').collect::<Vec<&str>>();
            for h_value in h_values {
                let h_value = h_value.trim();
                if h_value.starts_with("application/vnd.ipld.") {
                    // if valid media type use it, otherwise return error
                    // todo(arqu): add support for better media type detection
                    if h_value != "application/vnd.ipld.raw"
                        && h_value != "application/vnd.ipld.car"
                    {
                        return Err(format!("{}: {}", ERR_UNSUPPORTED_FORMAT, h_value));
                    }
                    return ResponseFormat::try_from(h_value);
                }
            }
        }
        Ok(ResponseFormat::Fs(String::new()))
    }
}

#[derive(Debug)]
pub struct GatewayResponse {
    pub status_code: StatusCode,
    pub body: BoxBody,
    pub headers: HashMap<String, String>,
    pub trace_id: String,
}

impl IntoResponse for GatewayResponse {
    fn into_response(self) -> Response {
        let mut rb = Response::builder().status(self.status_code);
        let headers = rb.headers_mut().unwrap();
        for (key, value) in &self.headers {
            let header_name = HeaderName::from_str(key).unwrap();
            headers.insert(header_name, HeaderValue::from_str(value).unwrap());
        }
        headers.insert(
            HEADER_X_TRACE_ID,
            HeaderValue::from_str(&self.trace_id).unwrap(),
        );
        rb.body(self.body).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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
        let mut headers = HashMap::new();
        rf.write_headers(&mut headers);
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers.get(&CONTENT_TYPE.to_string()).unwrap(),
            &CONTENT_TYPE_IPLD_RAW.to_string()
        );
        assert_eq!(
            headers
                .get(&HEADER_X_CONTENT_TYPE_OPTIONS.to_string())
                .unwrap(),
            &VALUE_XCTO_NOSNIFF.to_string()
        );

        let rf = ResponseFormat::try_from("car").unwrap();
        let mut headers = HashMap::new();
        rf.write_headers(&mut headers);
        assert_eq!(headers.len(), 4);
        assert_eq!(
            headers.get(&CONTENT_TYPE.to_string()).unwrap(),
            &CONTENT_TYPE_IPLD_CAR.to_string()
        );
        assert_eq!(
            headers
                .get(&HEADER_X_CONTENT_TYPE_OPTIONS.to_string())
                .unwrap(),
            &VALUE_XCTO_NOSNIFF.to_string()
        );

        let rf = ResponseFormat::try_from("fs").unwrap();
        let mut headers = HashMap::new();
        rf.write_headers(&mut headers);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&CONTENT_TYPE.to_string()).unwrap(),
            &CONTENT_TYPE_OCTET_STREAM.to_string()
        );
    }
}
