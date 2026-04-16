use std::str::FromStr;

use clap::Parser;
use iroh::EndpointId;
use n0_error::{Result, StdResultExt};

#[derive(Debug, Parser)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
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
