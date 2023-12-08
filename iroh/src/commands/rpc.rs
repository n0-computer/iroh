use std::path::Path;

use anyhow::{ensure, Context, Result};
use clap::Subcommand;
use iroh::{client::Iroh, rpc_protocol::ProviderService, util::path::IrohPaths};
use quic_rpc::ServiceConnection;
use tokio::{fs, io::AsyncReadExt};
use tracing::trace;

use crate::config::ConsoleEnv;

use super::{
    author::AuthorCommands, blob::BlobCommands, doc::DocCommands, node::NodeCommands,
    tag::TagCommands,
};

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum RpcCommands {
    /// Manage documents
    ///
    /// Documents are mutable, syncable key-value stores.
    /// For more on docs see https://iroh.computer/docs/layers/documents
    Doc {
        #[clap(subcommand)]
        command: DocCommands,
    },

    /// Manage document authors
    ///
    /// Authors are keypairs that identify writers to documents.
    Author {
        #[clap(subcommand)]
        command: AuthorCommands,
    },
    /// Manage blobs
    ///
    /// Blobs are immutable, opaque chunks of arbirary-sized data.
    /// For more on blobs see https://iroh.computer/docs/layers/blobs
    Blob {
        #[clap(subcommand)]
        command: BlobCommands,
    },
    /// Manage a running iroh node
    Node {
        #[clap(subcommand)]
        command: NodeCommands,
    },
    /// Manage tags
    ///
    /// Tags are local, human-readable names for things iroh should keep.
    /// Anything added with explicit commands like `iroh get` or `doc join`
    /// will be tagged & kept until the tag is removed. If no tag is given
    /// while running an explicit command, iroh will automatically generate
    /// a tag.
    ///
    /// Any data iroh fetches without a tag will be periodically deleted.
    Tag {
        #[clap(subcommand)]
        command: TagCommands,
    },
}

impl RpcCommands {
    pub async fn run<C>(self, iroh: &Iroh<C>, env: &ConsoleEnv) -> Result<()>
    where
        C: ServiceConnection<ProviderService>,
    {
        let res = match self {
            Self::Node { command } => command.run(iroh).await,
            Self::Blob { command } => command.run(iroh).await,
            Self::Doc { command } => command.run(iroh, env).await,
            Self::Author { command } => command.run(iroh, env).await,
            Self::Tag { command } => command.run(iroh).await,
        };
        match res {
            Ok(()) => std::process::exit(0),
            Err(err) => {
                tracing::error!("{:?}", err);
                std::process::exit(1)
            }
        }
    }
}

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
                if iroh::client::quic::connect(running_rpc_port).await.is_ok() {
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

    /// Store the current rpc status.
    pub async fn store(root: impl AsRef<Path>, rpc_port: u16) -> Result<()> {
        let p = IrohPaths::RpcLock.with_root(root);
        trace!("storing RPC lock: {}", p.display());

        ensure!(!p.exists(), "iroh is already running");
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)
                .await
                .context("creating parent dir")?;
        }
        fs::write(&p, &rpc_port.to_le_bytes())
            .await
            .context("writing rpc lock file")?;
        Ok(())
    }

    /// Cleans up an existing rpc lock
    pub async fn clear(root: impl AsRef<Path>) -> Result<()> {
        let p = IrohPaths::RpcLock.with_root(root);
        trace!("clearing RPC lock: {}", p.display());

        // ignore errors
        tokio::fs::remove_file(&p).await.ok();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rpc_lock_file() {
        let dir = testdir::testdir!();

        let rpc_port = 7778;
        RpcStatus::store(&dir, rpc_port).await.unwrap();
        let status = RpcStatus::load(&dir).await.unwrap();
        assert_eq!(status, RpcStatus::Stopped);
        let p = IrohPaths::RpcLock.with_root(&dir);
        let exists = fs::try_exists(&p).await.unwrap();
        assert!(!exists, "should be deleted as not running");
    }
}
