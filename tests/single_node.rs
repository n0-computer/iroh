use std::process::Command;

use anyhow::anyhow;
use camino::Utf8PathBuf;
use once_cell::sync::Lazy;

/// The target directory where to find compiled binaries.
static TARGET_DIR: Lazy<Utf8PathBuf> = Lazy::new(|| target_dir());

#[test]
fn test_start_stop() {
    println!("crate: {}", env!("CARGO_CRATE_NAME"));

    let path = std::env::var("PATH").unwrap();
    let path = format!("{}:{}", *TARGET_DIR, path);

    let out = Command::new("iroh")
        .args(["status"])
        .env("PATH", path)
        .output()
        .unwrap();

    let status = IrohStatusOutput::try_from(out.stdout.as_slice()).unwrap();
    dbg!(status);

    panic!("boom");
}

#[derive(Debug, Clone)]
struct IrohStatusOutput {
    services: Vec<IrohServiceStatus>,
}

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
/// This is where you can look for compiled binaries etc.
fn target_dir() -> Utf8PathBuf {
    let metadata = cargo_metadata::MetadataCommand::new().exec().unwrap();
    let profile = match cfg!(debug_assertions) {
        true => "debug",
        false => "release",
    };
    metadata.target_directory.join(profile)
}
