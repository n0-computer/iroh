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
    Html,
    Raw,
    Car,
    Fs,
}

impl std::convert::TryFrom<&str> for ResponseFormat {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "html" => Ok(ResponseFormat::Html),
            "raw" => Ok(ResponseFormat::Raw),
            "car" => Ok(ResponseFormat::Car),
            "fs" | "" => Ok(ResponseFormat::Fs),
            _ => Err(format!("{}: {}", ERR_UNSUPPORTED_FORMAT, s)),
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
            }
            ResponseFormat::Html => {
                headers.insert(CONTENT_TYPE.to_string(), CONTENT_TYPE_HTML.to_string());
            }
            ResponseFormat::Fs => {
                headers.insert(
                    CONTENT_TYPE.to_string(),
                    CONTENT_TYPE_OCTET_STREAM.to_string(),
                );
            }
        }
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
        let rf = ResponseFormat::try_from("html");
        assert_eq!(rf, Ok(ResponseFormat::Html));
        let rf = ResponseFormat::try_from("fs");
        assert_eq!(rf, Ok(ResponseFormat::Fs));
        let rf = ResponseFormat::try_from("");
        assert_eq!(rf, Ok(ResponseFormat::Fs));

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
        assert_eq!(headers.len(), 2);
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

        let rf = ResponseFormat::try_from("html").unwrap();
        let mut headers = HashMap::new();
        rf.write_headers(&mut headers);
        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get(&CONTENT_TYPE.to_string()).unwrap(),
            &CONTENT_TYPE_HTML.to_string()
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
