use anyhow::Result;
use clap::{Args, Subcommand};

#[derive(Args, Debug, Clone)]
pub struct Gateway {
    #[clap(subcommand)]
    command: GatewayCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum GatewayCommands {
    #[clap(about = "Version of the iroh gateway binary")]
    Version,
    Dev(Dev),
}

#[derive(Args, Debug, Clone)]
#[clap(hide = true)]
pub struct Dev {
    #[clap(subcommand)]
    command: DevCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum DevCommands {
    #[clap(hide = true)]
    Get { curl: String },
    #[clap(hide = true)]
    Head,
}

pub async fn run_command(g: &Gateway) -> Result<()> {
    match &g.command {
        GatewayCommands::Version => {
            todo!("Gateway version not yet implemented");
            // let v = rpc.try_gateway()?.version().await?;
            // println!("v{}", v);
        }
        GatewayCommands::Dev(dev) => match &dev.command {
            DevCommands::Get { curl } => {
                todo!("Get not yet implemented: {}", curl);
            }
            DevCommands::Head => {
                todo!("Head not yet implemented");
            }
        },
    }
}
