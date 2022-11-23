#[cfg(any(feature = "grpc", feature = "mem"))]
#[macro_use]
mod macros;

// Reexport for convenience.
#[cfg(feature = "grpc")]
pub use tonic::transport::NamedService;

#[cfg(any(feature = "grpc", feature = "mem"))]
pub mod grpc;
#[cfg(any(feature = "grpc", feature = "mem"))]
pub use grpc::*;

// pub mod qrpc;
// pub use qrpc::*;
