use std::io;

use duct::cmd;

fn main() {
    // Git commit
    println!("cargo:rustc-env=GIT_COMMIT={}", get_git_commit());

    // Rustc version
    println!(
        "cargo:rustc-env=RUSTC_VERSION={}",
        get_rustc_version().unwrap()
    );
}

fn get_git_commit() -> String {
    if let Ok(commit) = cmd!("git", "rev-parse", "HEAD").read() {
        commit
    } else {
        "git_unavailable".to_string()
    }
}

fn get_rustc_version() -> io::Result<String> {
    let rustc_var = std::env::var_os("RUSTC")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "RUSTC env var is not set"))?;
    cmd!(rustc_var, "--version").read()
}
