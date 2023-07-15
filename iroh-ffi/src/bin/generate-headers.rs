use anyhow::{anyhow, Result};

#[cfg(feature = "c-headers")]
fn main() -> Result<()> {
    iroh_ffi::generate_headers().map_err(|e| anyhow!(e.to_string()))?;
    Ok(())
}

#[cfg(not(feature = "c-headers"))]
fn main() -> Result<()> {
    Err(anyhow!("Must run with --features c-headers"))
}
