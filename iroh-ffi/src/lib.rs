use safer_ffi::prelude::*;

pub mod error;
pub mod get;
pub mod node;

#[ffi_export]
/// Deallocate an Iroh-allocated string.
pub fn iroh_string_free(string: char_p::Box) {
    drop(string);
}

// Generates the headers.
//
// `cargo test build_headers --features c-headers` to build
#[safer_ffi::cfg_headers]
#[test]
fn build_headers() -> std::io::Result<()> {
    safer_ffi::headers::builder()
        .to_file("iroh.h")?
        .generate()?;

    Ok(())
}
