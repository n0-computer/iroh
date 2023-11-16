use anyhow::Result;
use bytes::Bytes;
use clap::Subcommand;
use futures::StreamExt;
use iroh::client::quic::Iroh;
use iroh_bytes::Tag;

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum TagCommands {
    /// List all tags
    List,
    /// Delete a tag
    Delete {
        tag: String,
        #[clap(long, default_value_t = false)]
        hex: bool,
    },
}

impl TagCommands {
    pub async fn run(self, iroh: &Iroh) -> Result<()> {
        match self {
            Self::List => {
                let mut response = iroh.tags.list().await?;
                while let Some(res) = response.next().await {
                    let res = res?;
                    println!("{}: {} ({:?})", res.name, res.hash, res.format,);
                }
            }
            Self::Delete { tag, hex } => {
                let tag = if hex {
                    Tag::from(Bytes::from(hex::decode(tag)?))
                } else {
                    Tag::from(tag)
                };
                iroh.tags.delete(tag).await?;
            }
        }
        Ok(())
    }
}
