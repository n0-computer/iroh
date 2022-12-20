use axum::http::{header::HeaderName, HeaderValue};

// Headers
pub static HEADER_X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
pub static HEADER_X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
pub static HEADER_X_IPFS_PATH: HeaderName = HeaderName::from_static("x-ipfs-path");
pub static HEADER_X_CONTENT_TYPE_OPTIONS: HeaderName =
    HeaderName::from_static("x-content-type-options");
pub static HEADER_X_TRACE_ID: HeaderName = HeaderName::from_static("x-trace-id");
pub static HEADER_X_IPFS_GATEWAY_PREFIX: HeaderName =
    HeaderName::from_static("x-ipfs-gateway-prefix");
pub static HEADER_X_IPFS_ROOTS: HeaderName = HeaderName::from_static("x-ipfs-roots");
pub static HEADER_SERVICE_WORKER: HeaderName = HeaderName::from_static("service-worker");
pub static HEADER_CACHE_CONTROL: HeaderName = HeaderName::from_static("cache-control");
pub static HEADER_X_CHUNKED_OUTPUT: HeaderName = HeaderName::from_static("x-chunked-output");
pub static HEADER_X_STREAM_OUTPUT: HeaderName = HeaderName::from_static("x-stream-output");
pub static HEADER_X_REQUESTED_WITH: HeaderName = HeaderName::from_static("x-requested-with");

// Common Header Values
pub static VALUE_XCTO_NOSNIFF: HeaderValue = HeaderValue::from_static("nosniff");
pub static VALUE_NONE: HeaderValue = HeaderValue::from_static("none");
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

// Schemes
pub static SCHEME_IPFS: &str = "ipfs";
pub static SCHEME_IPNS: &str = "ipns";

// Max number of links to return in a single recursive request.
// TODO: Make configurable.
pub static RECURSION_LIMIT: usize = 4096;
