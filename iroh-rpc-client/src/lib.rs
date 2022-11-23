#[cfg(any(feature = "grpc", feature = "mem"))]
#[macro_use]
mod macros;

#[cfg(any(feature = "grpc", feature = "mem"))]
mod grpc;

#[cfg(any(feature = "grpc", feature = "mem"))]
pub use grpc::*;

#[cfg(not(any(feature = "grpc", feature = "mem")))]
mod qrpc;

#[cfg(not(any(feature = "grpc", feature = "mem")))]
pub use qrpc::*;
