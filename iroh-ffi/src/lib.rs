// pub mod error;
// pub mod get;
// pub mod node;

// #[ffi_export]
// /// Deallocate an Iroh-allocated string.
// pub fn iroh_string_free(string: char_p::Box) {
//     drop(string);
// }

// --

fn add(a: u32, b: u32) -> u32 {
    a + b
}

fn hello() -> String {
    "This is a hello from the rust library".to_string()
}

uniffi::include_scaffolding!("iroh");

// --

// Generates the headers.
//
// `cargo test build_headers --features c-headers` to build
// #[safer_ffi::cfg_headers]
// #[test]
// fn build_headers() -> std::io::Result<()> {
//     safer_ffi::headers::builder()
//         .to_file("iroh.h")?
//         .generate()?;

//     Ok(())
// }
