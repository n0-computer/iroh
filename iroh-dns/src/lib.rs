//! DNS-based endpoint discovery for iroh.
//!
//! This crate contains the core types for publishing and resolving iroh endpoint
//! information via DNS, using the [pkarr](https://pkarr.org) signed packet format.

pub mod attrs;
#[cfg(not(wasm_browser))]
pub mod dns;
pub mod pkarr;

use std::sync::LazyLock;

use iroh_base::{EndpointId, KeyParsingError};
use n0_error::{e, stack_error};

/// z-base-32 encoding as used by pkarr.
static Z_BASE_32: LazyLock<data_encoding::Encoding> = LazyLock::new(|| {
    let mut spec = data_encoding::Specification::new();
    spec.symbols.push_str("ybndrfg8ejkmcpqxot1uwisza345h769");
    spec.encoding().expect("valid z-base-32 spec")
});

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum DecodingError {
    #[error("endpoint id was not encoded in valid z32")]
    InvalidEncodingZ32 {
        #[error(std_err)]
        source: data_encoding::DecodeError,
    },
    #[error("length must be 32 bytes, but got {len} byte(s)")]
    InvalidLength { len: usize },
    #[error("endpoint id is not a valid public key")]
    InvalidKey { source: KeyParsingError },
}

/// Extension methods for [`EndpointId`] to encode to and decode from z-base-32,
/// which is the encoding used by [pkarr](https://pkarr.org) domain names.
pub trait EndpointIdExt {
    /// Encodes a [`EndpointId`] in [z-base-32](https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt) encoding.
    fn to_z32(&self) -> String;

    /// Parses a [`EndpointId`] from [z-base-32](https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt) encoding.
    fn from_z32(s: &str) -> Result<EndpointId, DecodingError>;
}

impl EndpointIdExt for EndpointId {
    fn to_z32(&self) -> String {
        Z_BASE_32.encode(self.as_bytes())
    }

    fn from_z32(s: &str) -> Result<EndpointId, DecodingError> {
        let bytes = Z_BASE_32
            .decode(s.as_bytes())
            .map_err(|e| e!(DecodingError::InvalidEncodingZ32, e))?;
        let pk =
            EndpointId::try_from(bytes.as_slice()).map_err(|e| e!(DecodingError::InvalidKey, e))?;
        Ok(pk)
    }
}
