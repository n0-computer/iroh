//! Re-export of endpoint info types from [`iroh_dns::endpoint_info`].
pub use iroh_dns::{
    DecodingError, EndpointIdExt,
    attrs::{EncodingError, IROH_TXT_NAME, ParseError},
    endpoint_info::*,
};
