// pub mod error;
// pub mod get;
mod node;

fn add(a: u32, b: u32) -> u32 {
    a + b
}

fn hello() -> String {
    "This is a hello from the rust library".to_string()
}

pub use self::node::IrohNode;

uniffi::include_scaffolding!("iroh");
