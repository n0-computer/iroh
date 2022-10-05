#[macro_use]
mod macros;

pub mod gateway;
pub mod p2p;
pub mod store;

mod connection_pool;

#[macro_use]
extern crate quick_error;

// Reexport for convenience.
#[cfg(feature = "grpc")]
pub use tonic::transport::NamedService;

#[cfg(feature = "testing")]
pub mod test;

mod addr;
pub use crate::addr::Addr;
