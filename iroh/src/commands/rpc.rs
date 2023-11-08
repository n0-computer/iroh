use std::path::Path;

use anyhow::{ensure, Context, Result};
use iroh::util::path::IrohPaths;
use tokio::{fs, io::AsyncReadExt};
use tracing::trace;

/// The current status of the RPC endpoint.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RpcStatus {
    /// Stopped.
    Stopped,
    /// Running on this port.
    Running(u16),
}

impl RpcStatus {
    pub async fn load(root: impl AsRef<Path>) -> Result<RpcStatus> {
        let p = IrohPaths::RpcLock.with_root(root);
        trace!("loading RPC lock: {}", p.display());

        if p.exists() {
            // Lock file exists, read the port and check if we can get a connection.
            let mut file = fs::File::open(&p).await.context("open rpc lock file")?;
            let file_len = file
                .metadata()
                .await
                .context("reading rpc lock file metadata")?
                .len();
            if file_len == 2 {
                let mut buffer = [0u8; 2];
                file.read_exact(&mut buffer)
                    .await
                    .context("read rpc lock file")?;
                let running_rpc_port = u16::from_le_bytes(buffer);
                if iroh::client::quic::connect(running_rpc_port, None)
                    .await
                    .is_ok()
                {
                    return Ok(RpcStatus::Running(running_rpc_port));
                }
            }

            // invalid or outdated rpc lock file, delete
            drop(file);
            fs::remove_file(&p)
                .await
                .context("deleting rpc lock file")?;
            Ok(RpcStatus::Stopped)
        } else {
            // No lock file, stopped
            Ok(RpcStatus::Stopped)
        }
    }
}

/// Store the current rpc status.
pub async fn store_rpc(root: impl AsRef<Path>, rpc_port: u16) -> Result<()> {
    let p = IrohPaths::RpcLock.with_root(root);
    trace!("storing RPC lock: {}", p.display());

    ensure!(!p.exists(), "iroh is already running");
    fs::write(&p, &rpc_port.to_le_bytes())
        .await
        .context("writing rpc lock file")?;
    Ok(())
}

/// Cleans up an existing rpc lock
pub async fn clear_rpc(root: impl AsRef<Path>) -> Result<()> {
    let p = IrohPaths::RpcLock.with_root(root);
    trace!("clearing RPC lock: {}", p.display());

    // ignore errors
    tokio::fs::remove_file(&p).await.ok();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rpc_lock_file() {
        let dir = testdir::testdir!();

        let rpc_port = 7778;
        store_rpc(&dir, rpc_port).await.unwrap();
        let status = RpcStatus::load(&dir).await.unwrap();
        assert_eq!(status, RpcStatus::Stopped);
        let p = IrohPaths::RpcLock.with_root(&dir);
        let exists = fs::try_exists(&p).await.unwrap();
        assert!(!exists, "should be deleted as not running");
    }
}
