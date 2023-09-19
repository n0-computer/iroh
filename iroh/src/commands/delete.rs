use anyhow::Result;
use clap::Subcommand;
use iroh::{client::quic::RpcClient, rpc_protocol::SetRootRequest};

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Delete the given roots
    Roots { name: String },
}

impl Commands {
    pub async fn run(self, client: RpcClient) -> Result<()> {
        match self {
            Commands::Roots { name } => {
                let name = if name.starts_with("\"") && name.ends_with("\"") && name.len() > 1 {
                    name[1..name.len() - 1].as_bytes().to_vec()
                } else {
                    hex::decode(name)?
                }
                .into();
                let response = client.rpc(SetRootRequest { name, value: None }).await?;
                if let Err(e) = response {
                    println!("Error: {}", e);
                }
            }
        }
        Ok(())
    }
}
