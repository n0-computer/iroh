use anyhow::Result;
use clap::Subcommand;
use iroh::client::quic::Iroh;
use iroh_bytes::Hash;

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Delete the given blobs
    Blob {
        /// Blobs to delete
        #[arg(required = true)]
        hash: Hash,
    },
}

impl Commands {
    pub async fn run(self, iroh: &Iroh) -> Result<()> {
        match self {
            Commands::Blob { hash } => {
                let response = iroh.blobs.delete_blob(hash).await;
                if let Err(e) = response {
                    println!("Error: {}", e);
                }
            }
        }
        Ok(())
    }
}
