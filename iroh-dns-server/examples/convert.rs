use std::str::FromStr;

use clap::Parser;
use iroh::NodeId;
use n0_snafu::{Result, ResultExt};

#[derive(Debug, Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    NodeToPkarr { node_id: String },
    PkarrToNode { z32_pubkey: String },
}

fn main() -> Result<()> {
    let args = Cli::parse();
    match args.command {
        Command::NodeToPkarr { node_id } => {
            let node_id = NodeId::from_str(&node_id)?;
            let public_key = pkarr::PublicKey::try_from(node_id.as_bytes()).e()?;
            println!("{}", public_key.to_z32())
        }
        Command::PkarrToNode { z32_pubkey } => {
            let public_key = pkarr::PublicKey::try_from(z32_pubkey.as_str()).e()?;
            let node_id = NodeId::from_bytes(public_key.as_bytes()).e()?;
            println!("{}", node_id)
        }
    }
    Ok(())
}
