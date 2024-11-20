//! Define the subcommands to manage the iroh RPC.

use anyhow::Result;
use clap::Subcommand;
use iroh::client::Iroh;
use iroh_docs::cli::ConsoleEnv;
use iroh_node_util::cli::node::NodeCommands;

use super::{
    authors::AuthorCommands, blobs::BlobCommands, docs::DocCommands, gossip::GossipCommands,
    net::NetCommands, tags::TagCommands,
};

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

    #[clap(flatten)]
    Node(NodeCommands),
}

impl RpcCommands {
    /// Run the RPC command given the iroh client and the console environment.
    pub async fn run(self, iroh: &Iroh, env: &ConsoleEnv) -> Result<()> {
        let node_id = || async move { iroh.net().node_addr().await };
        match self {
            Self::Net { command } => command.run(&iroh.net()).await,
            Self::Blobs { command } => command.run(&iroh.blobs(), node_id().await?).await,
            Self::Docs { command } => command.run(&iroh.docs(), &iroh.blobs(), env).await,
            Self::Authors { command } => command.run(&iroh.authors(), env).await,
            Self::Tags { command } => command.run(&iroh.tags()).await,
            Self::Gossip { command } => command.run(&iroh.gossip()).await,
            Self::Node(command) => command.run(&iroh.node()).await,
        }
    }
}
