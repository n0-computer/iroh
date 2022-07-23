// Based on tonic::include_proto
macro_rules! include_proto {
    ($package: tt) => {
        #[allow(clippy::all)]
        mod proto {
            include!(concat!(env!("OUT_DIR"), concat!("/", $package, ".rs")));
        }
        pub use proto::*;
    };
}

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
