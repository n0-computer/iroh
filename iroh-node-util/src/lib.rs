//! Utilities for building iroh nodes.
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
#![cfg_attr(iroh_docsrs, feature(doc_cfg))]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "config")))]
#[cfg(feature = "config")]
pub mod config;
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "logging")))]
#[cfg(feature = "logging")]
pub mod logging;
pub mod rpc;

use std::path::PathBuf;

use anyhow::Context;
use iroh_net::key::SecretKey;
use tokio::io::AsyncWriteExt;

/// Loads a [`SecretKey`] from the provided file, or stores a newly generated one
/// at the given location.
pub async fn load_secret_key(key_path: PathBuf) -> anyhow::Result<SecretKey> {
    if key_path.exists() {
        let keystr = tokio::fs::read(key_path).await?;
        let secret_key = SecretKey::try_from_openssh(keystr).context("invalid keyfile")?;
        Ok(secret_key)
    } else {
        let secret_key = SecretKey::generate();
        let ser_key = secret_key.to_openssh()?;

        // Try to canonicalize if possible
        let key_path = key_path.canonicalize().unwrap_or(key_path);
        let key_path_parent = key_path.parent().ok_or_else(|| {
            anyhow::anyhow!("no parent directory found for '{}'", key_path.display())
        })?;
        tokio::fs::create_dir_all(&key_path_parent).await?;

        // write to tempfile
        let (file, temp_file_path) = tempfile::NamedTempFile::new_in(key_path_parent)
            .context("unable to create tempfile")?
            .into_parts();
        let mut file = tokio::fs::File::from_std(file);
        file.write_all(ser_key.as_bytes())
            .await
            .context("unable to write keyfile")?;
        file.flush().await?;
        drop(file);

        // move file
        tokio::fs::rename(temp_file_path, key_path)
            .await
            .context("failed to rename keyfile")?;

        Ok(secret_key)
    }
}
