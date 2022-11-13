#[macro_use]
mod macros;

pub mod error;
pub mod gateway;
pub mod p2p;
pub mod store;

// Reexport for convenience.
#[cfg(feature = "grpc")]
pub use tonic::transport::NamedService;

#[cfg(feature = "testing")]
pub mod test;

mod addr;
pub use crate::addr::Addr;
