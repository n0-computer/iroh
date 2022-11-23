
#[cfg(any(feature = "grpc", feature = "mem"))]
#[macro_use]
mod macros;

// Reexport for convenience.
#[cfg(feature = "grpc")]
pub use tonic::transport::NamedService;

#[cfg(any(feature = "grpc", feature = "mem"))]
mod grpc;
#[cfg(any(feature = "grpc", feature = "mem"))]
pub use grpc::*;

#[cfg(any(feature = "qrpc"))]
pub mod qrpc;
#[cfg(any(feature = "qrpc"))]
pub use qrpc::*;

pub use crate::addr::Addr;
