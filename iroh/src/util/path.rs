//! Configuration paths for iroh.

use std::path::{Path, PathBuf};

/// Paths to files or directories used by Iroh.
#[derive(Debug, Clone, Copy, Eq, PartialEq, strum::AsRefStr, strum::EnumString, strum::Display)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum IrohPaths {
    /// Path to the node's secret key for the [`iroh_net::key::PublicKey`].
    #[strum(serialize = "keypair")]
    SecretKey,
    /// Path to the node's [redb blob store](iroh_bytes::store::redb).
    #[strum(serialize = "blobs")]
    BaoStoreDir,
    /// Path to the [iroh-sync document database](iroh_sync::store::fs::Store)
    #[strum(serialize = "docs.redb")]
    DocsDatabase,
    /// Path to the console state
    #[strum(serialize = "console")]
    Console,
    #[strum(serialize = "peers.postcard")]
    /// Path to store known peer data.
    PeerData,
    #[strum(serialize = "rpc.lock")]
    /// Path to RPC lock file, containing the RPC port if running.
    RpcLock,
}

impl AsRef<Path> for IrohPaths {
    fn as_ref(&self) -> &Path {
        let s: &str = self.as_ref();
        Path::new(s)
    }
}

impl IrohPaths {
    /// Get the path for this [`IrohPaths`] by joining the name to a root directory.
    pub fn with_root(self, root: impl AsRef<Path>) -> PathBuf {
        let path = root.as_ref().join(self);
        path
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use strum::IntoEnumIterator;

    use super::*;

    #[test]
    fn test_iroh_paths_parse_roundtrip() {
        for iroh_path in IrohPaths::iter() {
            println!("{iroh_path}");
            let root = PathBuf::from("/tmp");
            let path = root.join(iroh_path);
            let fname = path.file_name().unwrap().to_str().unwrap();
            let parsed = IrohPaths::from_str(fname).unwrap();
            assert_eq!(iroh_path, parsed);
        }
    }
}
