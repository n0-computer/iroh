//! Utility functions and types.
use std::{
    env, fmt,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{anyhow, Result};
use iroh::Hash;

/// name of directory that wraps all iroh files in a given application directory
const IROH_DIR: &str = "iroh";

/// Returns the path to the user's iroh config directory.
///
/// If the `IROH_CONFIG_DIR` environment variable is set it will be used unconditionally.
/// Otherwise the returned value depends on the operating system according to the following
/// table.
///
/// | Platform | Value                                 | Example                          |
/// | -------- | ------------------------------------- | -------------------------------- |
/// | Linux    | `$XDG_CONFIG_HOME` or `$HOME`/.config/iroh | /home/alice/.config/iroh              |
/// | macOS    | `$HOME`/Library/Application Support/iroh   | /Users/Alice/Library/Application Support/iroh |
/// | Windows  | `{FOLDERID_RoamingAppData}`/iroh           | C:\Users\Alice\AppData\Roaming\iroh   |
#[allow(dead_code)]
pub fn iroh_config_root() -> Result<PathBuf> {
    if let Some(val) = env::var_os("IROH_CONFIG_DIR") {
        return Ok(PathBuf::from(val));
    }
    let cfg = dirs_next::config_dir()
        .ok_or_else(|| anyhow!("operating environment provides no directory for configuration"))?;
    Ok(cfg.join(IROH_DIR))
}

/// Path that leads to a file in the iroh config directory.
#[allow(dead_code)]
pub fn iroh_config_path(file_name: &Path) -> Result<PathBuf> {
    let path = iroh_config_root()?.join(file_name);
    Ok(path)
}

/// Returns the path to the user's iroh data directory.
///
/// If the `IROH_DATA_DIR` environment variable is set it will be used unconditionally.
/// Otherwise the returned value depends on the operating system according to the following
/// table.
///
/// | Platform | Value                                         | Example                                  |
/// | -------- | --------------------------------------------- | ---------------------------------------- |
/// | Linux    | `$XDG_DATA_HOME`/iroh or `$HOME`/.local/share/iroh | /home/alice/.local/share/iroh                 |
/// | macOS    | `$HOME`/Library/Application Support/iroh      | /Users/Alice/Library/Application Support/iroh |
/// | Windows  | `{FOLDERID_RoamingAppData}/iroh`              | C:\Users\Alice\AppData\Roaming\iroh           |
pub fn iroh_data_root() -> Result<PathBuf> {
    if let Some(val) = env::var_os("IROH_DATA_DIR") {
        return Ok(PathBuf::from(val));
    }
    let path = dirs_next::data_dir().ok_or_else(|| {
        anyhow!("operating environment provides no directory for application data")
    })?;
    Ok(path.join(IROH_DIR))
}

/// Path that leads to a file in the iroh data directory.
#[allow(dead_code)]
pub fn iroh_data_path(file_name: &Path) -> Result<PathBuf> {
    let path = iroh_data_root()?.join(file_name);
    Ok(path)
}

/// Returns the path to the user's iroh cache directory.
///
/// If the `IROH_CACHE_DIR` environment variable is set it will be used unconditionally.
/// Otherwise the returned value depends on the operating system according to the following
/// table.
///
/// | Platform | Value                                         | Example                                  |
/// | -------- | --------------------------------------------- | ---------------------------------------- |
/// | Linux    | `$XDG_CACHE_HOME`/iroh or `$HOME`/.cache/iroh | /home/.cache/iroh                        |
/// | macOS    | `$HOME`/Library/Caches/iroh                   | /Users/Alice/Library/Caches/iroh         |
/// | Windows  | `{FOLDERID_LocalAppData}/iroh`                | C:\Users\Alice\AppData\Roaming\iroh      |
#[allow(dead_code)]
pub fn iroh_cache_root() -> Result<PathBuf> {
    if let Some(val) = env::var_os("IROH_CACHE_DIR") {
        return Ok(PathBuf::from(val));
    }
    let path = dirs_next::cache_dir().ok_or_else(|| {
        anyhow!("operating environment provides no directory for application data")
    })?;
    Ok(path.join(IROH_DIR))
}

/// Path that leads to a file in the iroh cache directory.
#[allow(dead_code)]
pub fn iroh_cache_path(file_name: &Path) -> Result<PathBuf> {
    let path = iroh_cache_root()?.join(file_name);
    Ok(path)
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blake3Cid(pub Hash);

const CID_PREFIX: [u8; 4] = [
    0x01, // version
    0x55, // raw codec
    0x1e, // hash function, blake3
    0x20, // hash size, 32 bytes
];

impl Blake3Cid {
    pub fn new(hash: Hash) -> Self {
        Blake3Cid(hash)
    }

    pub fn as_hash(&self) -> &Hash {
        &self.0
    }

    pub fn as_bytes(&self) -> [u8; 36] {
        let hash: [u8; 32] = self.0.as_ref().try_into().unwrap();
        let mut res = [0u8; 36];
        res[0..4].copy_from_slice(&CID_PREFIX);
        res[4..36].copy_from_slice(&hash);
        res
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            bytes.len() == 36,
            "invalid cid length, expected 36, got {}",
            bytes.len()
        );
        anyhow::ensure!(bytes[0..4] == CID_PREFIX, "invalid cid prefix");
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[4..36]);
        Ok(Blake3Cid(Hash::from(hash)))
    }
}

impl fmt::Display for Blake3Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // result will be 58 bytes plus prefix
        let mut res = [b'b'; 59];
        // write the encoded bytes
        data_encoding::BASE32_NOPAD.encode_mut(&self.as_bytes(), &mut res[1..]);
        // convert to string, this is guaranteed to succeed
        let t = std::str::from_utf8_mut(res.as_mut()).unwrap();
        // hack since data_encoding doesn't have BASE32LOWER_NOPAD as a const
        t.make_ascii_lowercase();
        // write the str, no allocations
        f.write_str(t)
    }
}

impl FromStr for Blake3Cid {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sb = s.as_bytes();
        if sb.len() == 59 && sb[0] == b'b' {
            // this is a base32 encoded cid, we can decode it directly
            let mut t = [0u8; 58];
            t.copy_from_slice(&sb[1..]);
            // hack since data_encoding doesn't have BASE32LOWER_NOPAD as a const
            std::str::from_utf8_mut(t.as_mut())
                .unwrap()
                .make_ascii_uppercase();
            // decode the bytes
            let mut res = [0u8; 36];
            data_encoding::BASE32_NOPAD
                .decode_mut(&t, &mut res)
                .map_err(|_e| anyhow::anyhow!("invalid base32"))?;
            // convert to cid, this will check the prefix
            Self::from_bytes(&res)
        } else {
            // if we want to support all the weird multibase prefixes, we have no choice
            // but to use the multibase crate
            let (_base, bytes) = multibase::decode(s)?;
            Self::from_bytes(bytes.as_ref())
        }
    }
}
