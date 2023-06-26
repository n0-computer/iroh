use anyhow::Result;
use clap::Subcommand;
use futures::StreamExt;
use indicatif::HumanBytes;
use iroh_bytes::cid::Blake3Cid;

use crate::rpc_protocol::{ListBlobsRequest, ListCollectionsRequest};

use super::{make_rpc_client, DEFAULT_RPC_PORT};

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// List the available blobs on the running provider.
    Blobs {
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
                    println!(
                        "{} {} ({})",
                        item.path.display(),
                        Blake3Cid(item.hash),
                        HumanBytes(item.size),
                    );
                }
            }
            Commands::Collections { rpc_port } => {
                let client = make_rpc_client(rpc_port).await?;
                let mut response = client.server_streaming(ListCollectionsRequest).await?;
                while let Some(collection) = response.next().await {
                    let collection = collection?;
                    println!(
                        "{}: {} {} ({})",
                        Blake3Cid(collection.hash),
                        collection.total_blobs_count,
                        if collection.total_blobs_count > 1 {
                            "blobs"
                        } else {
                            "blob"
                        },
                        HumanBytes(collection.total_blobs_size),
                    );
                }
            }
        }
        Ok(())
    }
}
