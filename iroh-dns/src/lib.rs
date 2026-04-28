//! DNS-based endpoint discovery for iroh.
//!
//! This crate contains the core types for publishing and resolving iroh endpoint
//! information via DNS, using the [pkarr](https://pkarr.org) signed packet format.
#![deny(missing_docs, rustdoc::broken_intra_doc_links, unreachable_pub)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

mod attrs;
#[cfg(not(wasm_browser))]
pub mod dns;
pub mod endpoint_info;
pub mod pkarr;
#[cfg(not(wasm_browser))]
mod system_config;

pub use attrs::{EncodingError, IROH_TXT_NAME, ParseError};
#[cfg(target_os = "android")]
pub use system_config::android::install_android_jni_context;
#[cfg(target_os = "android")]
#[doc(hidden)]
pub use system_config::android::install_test_jni_context_stub;

#[cfg(all(test, target_os = "android"))]
#[ctor::ctor]
fn android_test_init() {
    install_test_jni_context_stub();
}
