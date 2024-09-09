//! Define the subcommands to manage the iroh RPC.

use super::{
    authors::AuthorCommands, blobs::BlobCommands, docs::DocCommands, gossip::GossipCommands,
    net::NetCommands, tags::TagCommands,
};
use crate::config::ConsoleEnv;
use anyhow::Result;
use clap::Subcommand;
use iroh::client::Iroh;

/// Commands to manage the iroh RPC.
#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum RpcCommands {
    /// Manage iroh's documents.
    ///
    /// Documents are mutable, syncable key-value stores.
    /// For more on docs see https://iroh.computer/docs/layers/documents
    ///
    /// For general configuration options see <https://iroh.computer/docs/reference/config>.
    Docs {
        #[clap(subcommand)]
        command: DocCommands,
    },

    /// Manage iroh's document authors.
    ///
    /// Authors are keypairs that identify writers to documents.
    ///
    /// For general configuration options see <https://iroh.computer/docs/reference/config>.
    Authors {
        #[clap(subcommand)]
        command: AuthorCommands,
    },
    /// Manage blobs
    ///
    /// Blobs are immutable, opaque chunks of arbitrary-sized data.
    /// For more on blobs see https://iroh.computer/docs/layers/blobs
    ///
    /// For general configuration options see <https://iroh.computer/docs/reference/config>.
    Blobs {
        #[clap(subcommand)]
        command: BlobCommands,
    },
    /// Manage the iroh network
    Net {
        #[clap(subcommand)]
        command: NetCommands,
    },
    /// Manage gossip
    ///
    /// Gossip is a way to broadcast messages to a group of nodes.
    ///
    /// For general configuration options see <https://iroh.computer/docs/reference/config>.
    Gossip {
        #[clap(subcommand)]
        command: GossipCommands,
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
    ///
    /// For general configuration options see <https://iroh.computer/docs/reference/config>.
    Tags {
        #[clap(subcommand)]
        command: TagCommands,
    },

    /// Get statistics and metrics from the running node.
    Stats,
    /// Get status of the running node.
    Status,
    /// Shutdown the running node.
    Shutdown {
        /// Shutdown mode.
        ///
        /// Hard shutdown will immediately terminate the process, soft shutdown will wait
        /// for all connections to close.
        #[clap(long, default_value_t = false)]
        force: bool,
    },
}

impl RpcCommands {
    /// Run the RPC command given the iroh client and the console environment.
    pub async fn run(self, iroh: &Iroh, env: &ConsoleEnv) -> Result<()> {
        match self {
            Self::Net { command } => command.run(iroh).await,
            Self::Blobs { command } => command.run(iroh).await,
            Self::Docs { command } => command.run(iroh, env).await,
            Self::Authors { command } => command.run(iroh, env).await,
            Self::Tags { command } => command.run(iroh).await,
            Self::Gossip { command } => command.run(iroh).await,
            Self::Stats => {
                let stats = iroh.stats().await?;
                for (name, details) in stats.iter() {
                    println!(
                        "{:23} : {:>6}    ({})",
                        name, details.value, details.description
                    );
                }
                Ok(())
            }
            Self::Shutdown { force } => {
                iroh.shutdown(force).await?;
                Ok(())
            }
            Self::Status => {
                let response = iroh.status().await?;
                println!("Listening addresses: {:#?}", response.listen_addrs);
                println!("Node ID: {}", response.addr.node_id);
                println!("Version: {}", response.version);
                if let Some(addr) = response.rpc_addr {
                    println!("RPC Addr: {}", addr);
                }
                Ok(())
            }
        }
    }
}
