pub mod addr;
pub mod gateway;
pub mod p2p;
pub mod store;

pub use addr::Addr;

pub trait NamedService {
    const NAME: &'static str;
}
