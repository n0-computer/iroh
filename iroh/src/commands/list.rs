use anyhow::Result;
use clap::Subcommand;
use futures::StreamExt;
use indicatif::HumanBytes;
use iroh::rpc_protocol::{ListBlobsRequest, ListCollectionsRequest, ListIncompleteBlobsRequest};

use super::{make_rpc_client, DEFAULT_RPC_PORT};

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// List the available blobs on the running provider.
    Blobs {
        /// RPC port of the provider
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
    /// List the available blobs on the running provider.
    IncompleteBlobs {
        /// RPC port of the provider
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
    /// List the available collections on the running provider.
    Collections {
        /// RPC port of the provider
        #[clap(long, default_value_t = DEFAULT_RPC_PORT)]
        rpc_port: u16,
    },
}

impl Commands {
    pub async fn run(self) -> Result<()> {
        match self {
            Commands::Blobs { rpc_port } => {
                let client = make_rpc_client(rpc_port).await?;
                let mut response = client.server_streaming(ListBlobsRequest).await?;
                while let Some(item) = response.next().await {
                    let item = item?;
                    println!("{} {} ({})", item.path, item.hash, HumanBytes(item.size),);
                }
            }
            Commands::IncompleteBlobs { rpc_port } => {
                let client = make_rpc_client(rpc_port).await?;
                let mut response = client.server_streaming(ListIncompleteBlobsRequest).await?;
                while let Some(item) = response.next().await {
                    let item = item?;
                    println!("{} {}", item.hash, item.size);
                }
            }
            Commands::Collections { rpc_port } => {
                let client = make_rpc_client(rpc_port).await?;
                let mut response = client.server_streaming(ListCollectionsRequest).await?;
                while let Some(collection) = response.next().await {
                    let collection = collection?;
                    let total_blobs_count = collection.total_blobs_count.unwrap_or_default();
                    let total_blobs_size = collection.total_blobs_size.unwrap_or_default();
                    println!(
                        "{}: {} {} ({})",
                        collection.hash,
                        total_blobs_count,
                        if total_blobs_count > 1 {
                            "blobs"
                        } else {
                            "blob"
                        },
                        HumanBytes(total_blobs_size),
                    );
                }
            }
        }
        Ok(())
    }
}
