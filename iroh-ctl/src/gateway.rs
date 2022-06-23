use anyhow::Result;
use clap::{Args, Subcommand};
use iroh_rpc_client::Client;

#[derive(Args, Debug, Clone)]
pub struct Gateway {
    #[clap(subcommand)]
    command: GatewayCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum GatewayCommands {
    #[clap(about = "Version of the iroh gateway binary")]
    Version,
}

pub async fn run_command(rpc: Client, g: Gateway) -> Result<()> {
    match g.command {
        GatewayCommands::Version => {
            let v = rpc.gateway.version().await?;
            println!("v{}", v);
        }
    }
    Ok(())
}
