use std::env;

use anyhow::Result;
use flatfs_store::Flatfs;

fn main() -> Result<()> {
    let path = env::args().nth(1).unwrap();

    println!("Opening {path:?}");

    let flatfs = Flatfs::new(&path)?;
    println!("Size on disk: {} bytes", flatfs.disk_usage());

    Ok(())
}
