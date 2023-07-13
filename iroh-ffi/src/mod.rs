mod get;
mod node;

pub use crate::ffi::get::*;
pub use crate::ffi::node::*;

#[cfg(feature = "headers")]
pub fn generate_headers() -> std::io::Result<()> {
    safer_ffi::headers::builder().to_file("iroh.h")?.generate()
}

#[ffi_export]
/// Deallocate an Iroh-allocated string.
pub fn iroh_string_free(string: char_p::Box) {
    drop(string)
}
