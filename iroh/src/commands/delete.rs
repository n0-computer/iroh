use anyhow::Result;
use clap::Subcommand;
use iroh::{client::quic::RpcClient, rpc_protocol::SetTagRequest};

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Delete the given tags
    Tags {
        /// Tag names to delete
        #[arg(required = true)]
        names: Vec<String>,

        /// Tag names are hex encoded
        ///
        /// This is useful for tags that are not valid utf8.
        #[arg(long, default_value_t = false)]
        hex: bool,
    },
}

impl Commands {
    pub async fn run(self, client: RpcClient) -> Result<()> {
        match self {
            Commands::Tags { names, hex } => {
                for name in names {
                    let name = if hex {
                        hex::decode(name)?
                    } else {
                        name.into_bytes()
                    }
                    .into();
                    let response = client.rpc(SetTagRequest { name, value: None }).await?;
                    if let Err(e) = response {
                        println!("Error: {}", e);
                    }
                }
            }
        }
        Ok(())
    }
}
