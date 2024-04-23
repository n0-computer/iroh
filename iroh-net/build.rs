// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{fs::read_dir, io::Error, path::Path, process::Command};

fn main() -> Result<(), Error> {
    let mut features = Features::default();

    // allow overriding the detected features with an env variable
    if let Some(list) = option_env("S2N_QUIC_PLATFORM_FEATURES_OVERRIDE") {
        // iterate twice in case there is dependence on another feature that comes later
        for _ in 0..2 {
            for feature in list.split(',') {
                features.insert(feature.trim());
            }
        }
        return Ok(());
    }

    let env = Env::new();

    for feature in read_dir("features")? {
        let path = feature?.path();
        if let Some(name) = path.file_stem() {
            println!("cargo:rerun-if-changed={}", path.display());
            if env.check(&path)? {
                features.insert(name.to_str().expect("valid feature name"));
            }
        }
    }

    let is_miri = std::env::var("CARGO_CFG_MIRI").is_ok();

    match env.target_os.as_str() {
        "linux" => {
            // miri doesn't support the way we detect syscall support so override it
            if is_miri {
                features.insert("socket_msg");
                features.insert("socket_mmsg");
            }

            features.insert("mtu_disc");
            features.insert("gso");
            features.insert("gro");
            features.insert("pktinfo");
            features.insert("tos");
        }
        "macos" => {
            // miri doesn't support the way we detect syscall support so override it
            if is_miri {
                features.insert("socket_msg");
            }

            features.insert("pktinfo");
            features.insert("tos");
        }
        "android" => {
            features.insert("mtu_disc");
            features.insert("pktinfo");
            features.insert("tos");
        }
        _ => {
            // TODO others
        }
    }

    Ok(())
}

#[derive(Debug, Default)]
struct Features {
    features: std::collections::HashSet<String>,
}

impl Features {
    fn insert(&mut self, name: &str) {
        // supporting any kind message implies cmsg support
        if name == "socket_msg" || name == "socket_mmsg" {
            self.insert("cmsg");
        }

        // the following features only make sense if cmsg is supported
        if ["gso", "gro", "pktinfo", "tos"].contains(&name) && !self.supports("cmsg") {
            return;
        }

        let newly_inserted = self.features.insert(name.to_string());
        if newly_inserted {
            println!("cargo:rustc-cfg=s2n_quic_platform_{name}");
        }
    }

    fn supports(&self, name: &str) -> bool {
        self.features.contains(name)
    }
}

struct Env {
    rustc: String,
    out_dir: String,
    target: String,
    target_os: String,
}

impl Env {
    fn new() -> Self {
        // See https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-sets-for-build-scripts
        Self {
            rustc: env("RUSTC"),
            out_dir: env("OUT_DIR"),
            target: env("TARGET"),
            target_os: env("CARGO_CFG_TARGET_OS"),
        }
    }

    // Tries to compile the program and returns if it was successful
    fn check(&self, path: &Path) -> Result<bool, Error> {
        let mut command = Command::new(&self.rustc);

        command
            .arg("--out-dir")
            .arg(&self.out_dir)
            .arg("--target")
            .arg(&self.target)
            .arg("--crate-type")
            .arg("bin")
            .arg("--codegen")
            .arg("opt-level=0")
            .arg(path);

        for (key, _) in std::env::vars() {
            const CARGO_FEATURE: &str = "CARGO_FEATURE_";
            if key.starts_with(CARGO_FEATURE) {
                command.arg("--cfg").arg(format!(
                    "feature=\"{}\"",
                    key.trim_start_matches(CARGO_FEATURE)
                        .to_lowercase()
                        .replace('_', "-")
                ));
            }
        }

        Ok(command.spawn()?.wait()?.success())
    }
}

fn env(name: &str) -> String {
    option_env(name).unwrap_or_else(|| panic!("build script missing {name:?} environment variable"))
}

fn option_env(name: &str) -> Option<String> {
    println!("cargo:rerun-if-env-changed={name}");
    std::env::var(name).ok()
}
