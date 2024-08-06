use anyhow::Result;
use clap::Subcommand;
use iroh::client::Iroh;

use crate::config::ConsoleEnv;

use super::{
    authors::AuthorCommands, blobs::BlobCommands, docs::DocCommands, gossip::GossipCommands,
    node::NodeCommands, tags::TagCommands,
};

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum RpcCommands {
    /// Manage documents
    ///
    /// Documents are mutable, syncable key-value stores.
    /// For more on docs see https://iroh.computer/docs/layers/documents
    ///
    /// For general configuration options see <https://iroh.computer/docs/reference/config>.
    Docs {
        #[clap(subcommand)]
        command: DocCommands,
    },

    /// Manage document authors
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
    /// Manage a running iroh node
    Node {
        #[clap(subcommand)]
        command: NodeCommands,
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
}

impl RpcCommands {
    pub async fn run(self, iroh: &Iroh, env: &ConsoleEnv) -> Result<()> {
        match self {
            Self::Node { command } => command.run(iroh).await,
            Self::Blobs { command } => command.run(iroh).await,
            Self::Docs { command } => command.run(iroh, env).await,
            Self::Authors { command } => command.run(iroh, env).await,
            Self::Tags { command } => command.run(iroh).await,
            Self::Gossip { command } => command.run(iroh).await,
        }
    }
}
