use axum::http::{header::HeaderName, HeaderValue};

// Headers
pub static HEADER_X_IPFS_PATH: HeaderName = HeaderName::from_static("x-ipfs-path");
pub static HEADER_X_CONTENT_TYPE_OPTIONS: HeaderName =
    HeaderName::from_static("x-content-type-options");
pub static HEADER_X_TRACE_ID: HeaderName = HeaderName::from_static("x-trace-id");
pub static HEADER_X_IPFS_GATEWAY_PREFIX: HeaderName =
    HeaderName::from_static("x-ipfs-gateway-prefix");
pub static HEADER_X_IPFS_ROOTS: HeaderName = HeaderName::from_static("x-ipfs-roots");
pub static HEADER_SERVICE_WORKER: HeaderName = HeaderName::from_static("service-worker");

// Common Header Values
pub static VALUE_XCTO_NOSNIFF: HeaderValue = HeaderValue::from_static("nosniff");
pub static VALUE_NONE: HeaderValue = HeaderValue::from_static("none");
pub static VALUE_NO_CACHE_NO_TRANSFORM: HeaderValue =
    HeaderValue::from_static("no-cache, no-transform");
pub static VAL_IMMUTABLE_MAX_AGE: HeaderValue =
    HeaderValue::from_static("public, max-age=31536000, immutable");

// Dispositions
pub static DISPOSITION_ATTACHMENT: &str = "attachment";
pub static DISPOSITION_INLINE: &str = "inline";

// Content Types
pub static CONTENT_TYPE_IPLD_RAW: HeaderValue =
    HeaderValue::from_static("application/vnd.ipld.raw");
pub static CONTENT_TYPE_IPLD_CAR: HeaderValue =
    HeaderValue::from_static("application/vnd.ipld.car; version=1");
pub static CONTENT_TYPE_OCTET_STREAM: HeaderValue =
    HeaderValue::from_static("application/octet-stream");
