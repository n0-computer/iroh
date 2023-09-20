use anyhow::Result;
use clap::Subcommand;
use iroh::client::quic::Iroh;
use iroh_bytes::Hash;

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Delete the given tag
    Tag {
        /// Tag names to delete
        #[arg(required = true)]
        name: String,

        /// Tag names are hex encoded
        ///
        /// This is useful for tags that are not valid utf8.
        #[arg(long, default_value_t = false)]
        hex: bool,
    },

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
            Commands::Tag { name, hex } => {
                let name = if hex {
                    hex::decode(name)?
                } else {
                    name.into_bytes()
                }
                .into();
                let response = iroh.blobs.delete_tag(name).await;
                if let Err(e) = response {
                    println!("Error: {}", e);
                }
            }
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
