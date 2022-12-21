use std::{
    env,
    io::{stdout, Write},
};

use anyhow::{anyhow, Result};
use flatfs_store::Flatfs;

fn main() -> Result<()> {
    let mut args = env::args();
    let iter = args.nth(1).unwrap().trim().to_lowercase();
    let path = args.next().unwrap().trim().to_string();
    let n: usize = args.next().unwrap().parse()?;

    println!("Opening {path:?}");

    let flatfs = Flatfs::new(&path)?;
    println!("Size on disk: {} bytes", flatfs.disk_usage());

    match iter.as_str() {
        "all" => {
            for r in flatfs.iter().take(n) {
                let (key, value) = r?;
                println!("{key}");
                println!("{value:?}");
            }
        }
        "stats" => {
            for r in flatfs.stats().take(n) {
                let stats = r?;
                println!("{stats:?}");
            }
        }
        "keys" => {
            for r in flatfs.keys().take(n) {
                let key = r?;
                println!("{key}");
            }
        }
        "values" => {
            let mut stdout = stdout();
            for r in flatfs.values().take(n) {
                let value = r?;
                stdout.write_all(&value)?;
            }
        }
        _ => return Err(anyhow!("Unsupported action: {}", iter)),
    }

    Ok(())
}
