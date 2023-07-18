use std::path::PathBuf;
use std::{env, fs};

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target_path = out_path.join("../../..");
    let target_triple = env::var("TARGET").unwrap();

    // macOS or iOS
    let libs_priv = if target_triple.contains("apple") || target_triple.contains("darwin") {
        // TODO: verify all these are needed
        "-framework SystemConfiguration -framework Security -framework Foundation"
    } else {
        ""
    };

    let pkg_config = format!(
        include_str!("iroh.pc.in"),
        name = "iroh",
        description = env::var("CARGO_PKG_DESCRIPTION").unwrap(),
        url = env::var("CARGO_PKG_HOMEPAGE").unwrap_or_else(|_| "".to_string()),
        version = env::var("CARGO_PKG_VERSION").unwrap(),
        libs_priv = libs_priv,
        prefix = env::var("PREFIX").unwrap_or_else(|_| "/usr/local".to_string()),
        libdir = env::var("LIBDIR").unwrap_or_else(|_| "/usr/local/lib".to_string()),
        includedir = env::var("INCLUDEDIR").unwrap_or_else(|_| "/usr/local/include".to_string()),
    );

    fs::create_dir_all(target_path.join("pkgconfig")).unwrap();
    fs::write(
        target_path.join("pkgconfig").join("iroh.pc"),
        pkg_config.as_bytes(),
    )
    .unwrap();
}
