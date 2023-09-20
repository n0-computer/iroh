use anyhow::Result;
use clap::Subcommand;
use futures::StreamExt;
use indicatif::HumanBytes;
use iroh::client::quic::Iroh;

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
    pub async fn run(self, iroh: &Iroh) -> Result<()> {
        match self {
            Commands::Blobs => {
                let mut response = iroh.blobs.list().await?;
                while let Some(item) = response.next().await {
                    let item = item?;
                    println!("{} {} ({})", item.path, item.hash, HumanBytes(item.size),);
                }
            }
            Commands::IncompleteBlobs => {
                let mut response = iroh.blobs.list_incomplete().await?;
                while let Some(item) = response.next().await {
                    let item = item?;
                    println!("{} {}", item.hash, item.size);
                }
            }
            Commands::Collections => {
                let mut response = iroh.blobs.list_collections().await?;
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
