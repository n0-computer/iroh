#[derive(Args, Debug, Clone)]
pub struct Gateway {
    #[clap(subcommand)]
    command: GatewayCommands
}

 
