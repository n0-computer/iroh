mod error;
// pub mod get;
mod node;

pub use self::error::IrohError;
pub use self::node::{Doc, IrohNode};

uniffi::include_scaffolding!("iroh");
