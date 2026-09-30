use std::str::FromStr;

use clap::{Parser, Subcommand};
use iroh::EndpointId;
use n0_error::{Result, StdResultExt};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    EndpointToPkarr { endpoint_id: String },
    PkarrToEndpoint { z32_pubkey: String },
}

fn main() -> Result<()> {
    let args = Cli::parse();
    match args.command {
        Command::EndpointToPkarr { endpoint_id } => {
            let endpoint_id = EndpointId::from_str(&endpoint_id)?;
            println!("{}", endpoint_id.to_z32())
        }
        Command::PkarrToEndpoint { z32_pubkey } => {
            let endpoint_id = EndpointId::from_z32(&z32_pubkey).anyerr()?;
            println!("{endpoint_id}")
        }
    }
    Ok(())
}
