use anyhow::Result;
use clap::Subcommand;
use iroh::{client::Iroh, rpc_protocol::ProviderService};
use quic_rpc::ServiceConnection;

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
    /// Blobs are immutable, opaque chunks of arbitrary-sized data.
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
        match self {
            Self::Node { command } => command.run(iroh).await,
            Self::Blob { command } => command.run(iroh).await,
            Self::Doc { command } => command.run(iroh, env).await,
            Self::Author { command } => command.run(iroh, env).await,
            Self::Tag { command } => command.run(iroh).await,
        }
    }
}
