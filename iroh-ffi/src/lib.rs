#![allow(missing_docs)]

mod error;
// pub mod get;
mod node;

pub use self::error::IrohError;
pub use self::node::*;

uniffi::include_scaffolding!("iroh");
