use std::collections::HashSet;
use std::process::{Command, Output};

use anyhow::anyhow;
use camino::Utf8PathBuf;
use once_cell::sync::Lazy;

/// The target directory where to find compiled binaries.
static TARGET_DIR: Lazy<Utf8PathBuf> = Lazy::new(|| target_dir());

#[test]
fn test_stopped() {
    let out = run_iroh(&["status"]);
    let status = IrohStatusOutput::try_from(out.stdout.as_slice()).unwrap();

    assert!(status.services.iter().all(|s| s.status == "Down"));
    assert!(status.services.iter().all(|s| s.count == 1));
    assert!(status.services.iter().all(|s| s.total == 1));
    let mut all_services = HashSet::new();
    all_services.insert(String::from("gateway"));
    all_services.insert(String::from("p2p"));
    all_services.insert(String::from("store"));
    let found_services: HashSet<String> =
        status.services.iter().map(|s| s.service.clone()).collect();
    assert_eq!(found_services, all_services);
}

#[test]
fn test_start_stop() {
    let out = run_iroh(&["status"]);
    let status = IrohStatusOutput::try_from(out.stdout.as_slice()).unwrap();
    assert!(status.services.iter().all(|s| s.status == "Down"));

    let out = run_iroh(&["start"]);
    assert!(out.status.success());

    let out = run_iroh(&["status"]);
    let status = IrohStatusOutput::try_from(out.stdout.as_slice()).unwrap();
    assert!(status.services.iter().all(|s| s.status == "Serving"));

    let out = run_iroh(&["stop"]);
    assert!(out.status.success());

    let out = run_iroh(&["status"]);
    let status = IrohStatusOutput::try_from(out.stdout.as_slice()).unwrap();
    assert!(status.services.iter().all(|s| s.status == "Down"));
}

/// Run `iroh` with given arguments.
fn run_iroh(args: &[&str]) -> Output {
    let path = std::env::var("PATH").unwrap();
    let path = format!("{}:{}", *TARGET_DIR, path);

    Command::new("iroh")
        .args(args)
        .env("PATH", path)
        .output()
        .unwrap()
}

/// Representation of the status output from `iroh`.
///
/// This is essentially a single sequence of statuses.
///
/// You can parse the output using the [`TryFrom::try_from`] method.
#[derive(Debug, Clone)]
struct IrohStatusOutput {
    services: Vec<IrohServiceStatus>,
}

/// Representation of the status of a single iroh service.
///
/// At least to the extend as exposed by the `iroh` command.
#[derive(Debug, Clone)]
struct IrohServiceStatus {
    service: String,
    count: u32,
    total: u32,
    status: String,
}

impl TryFrom<&[u8]> for IrohStatusOutput {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut services = Vec::with_capacity(3);
        let text = std::str::from_utf8(value)?;
        let lines = text
            .split(|c| c == '\r' || c == '\n')
            .filter(|l| !l.is_empty());
        for (i, line) in lines.enumerate() {
            if i == 0 {
                // Skip the header line
                continue;
            }
            let words = line
                .split(|c| c == ' ' || c == '\t')
                .filter(|w| !w.is_empty());
            let mut service: Option<String> = None;
            let mut count: Option<u32> = None;
            let mut total: Option<u32> = None;
            let mut status: Option<String> = None;
            for (pos, word) in words.enumerate() {
                // Stripping escapes at the start messes up line endings, so do it for each
                // word.  Should probably fix that bug but...
                let stripped = strip_ansi_escapes::strip(word)?;
                let word = std::str::from_utf8(&stripped)?;
                match pos {
                    0 => {
                        service.replace(String::from(word));
                    }
                    1 => {
                        let (c, t) = word
                            .split_once('/')
                            .ok_or(anyhow!("failed to parse service count"))?;
                        count.replace(c.parse()?);
                        total.replace(t.parse()?);
                    }
                    2 => {
                        status.replace(String::from(word));
                    }
                    _ => break,
                }
            }
            services.push(IrohServiceStatus {
                service: service.ok_or(anyhow!("service parse error"))?,
                count: count.ok_or(anyhow!("count parse error"))?,
                total: total.ok_or(anyhow!("total parse error"))?,
                status: status.ok_or(anyhow!("status parse error"))?,
            })
        }
        Ok(IrohStatusOutput { services })
    }
}

/// Returns the target directory.
///
/// This is where you can look for compiled binaries etc.  When in a crate that builds the
/// binary its path is available as a `CARGO_BIN_EXE_<name>` environment variable, however
/// each binary is built by its own crate and we want to test many binaries together.
fn target_dir() -> Utf8PathBuf {
    let metadata = cargo_metadata::MetadataCommand::new().exec().unwrap();
    let profile = match cfg!(debug_assertions) {
        true => "debug",
        false => "release",
    };
    metadata.target_directory.join(profile)
}
