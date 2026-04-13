//! DNS-based endpoint discovery for iroh.
//!
//! This crate contains the core types for publishing and resolving iroh endpoint
//! information via DNS, using the [pkarr](https://pkarr.org) signed packet format.

pub mod attrs;
pub mod endpoint_info;
pub mod pkarr;

use data_encoding::Encoding;
use data_encoding_macro::new_encoding;
use iroh_base::{EndpointId, KeyParsingError};
use n0_error::e;

/// z-base-32 encoding as used by pkarr.
const Z_BASE_32: Encoding = new_encoding! {
    symbols: "ybndrfg8ejkmcpqxot1uwisza345h769",
};

/// Extension methods for [`EndpointId`] to encode to and decode from z-base-32,
/// which is the encoding used by [pkarr](https://pkarr.org) domain names.
pub trait EndpointIdExt {
    /// Encodes a [`EndpointId`] in [z-base-32](https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt) encoding.
    fn to_z32(&self) -> String;

    /// Parses a [`EndpointId`] from [z-base-32](https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt) encoding.
    fn from_z32(s: &str) -> Result<EndpointId, KeyParsingError>;
}

impl EndpointIdExt for EndpointId {
    fn to_z32(&self) -> String {
        Z_BASE_32.encode(self.as_bytes())
    }

    fn from_z32(s: &str) -> Result<EndpointId, KeyParsingError> {
        let bytes = Z_BASE_32
            .decode(s.as_bytes())
            .map_err(|_| e!(KeyParsingError::FailedToDecodeBase32))?;
        EndpointId::try_from(bytes.as_slice())
    }
}
