use anyhow::Result;
use clap::Subcommand;
use futures::StreamExt;
use indicatif::HumanBytes;
use iroh::{
    client::quic::RpcClient,
    rpc_protocol::{ListBlobsRequest, ListCollectionsRequest, ListIncompleteBlobsRequest},
};

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// List the available blobs on the running provider.
    Blobs,
    /// List the available blobs on the running provider.
    IncompleteBlobs,
    /// List the available collections on the running provider.
    Collections,
}

impl Commands {
    pub async fn run(self, client: RpcClient) -> Result<()> {
        match self {
            Commands::Blobs => {
                let mut response = client.server_streaming(ListBlobsRequest).await?;
                while let Some(item) = response.next().await {
                    let item = item?;
                    println!("{} {} ({})", item.path, item.hash, HumanBytes(item.size),);
                }
            }
            Commands::IncompleteBlobs => {
                let mut response = client.server_streaming(ListIncompleteBlobsRequest).await?;
                while let Some(item) = response.next().await {
                    let item = item?;
                    println!("{} {}", item.hash, item.size);
                }
            }
            Commands::Collections => {
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
