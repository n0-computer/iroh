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
            let public_key = pkarr::PublicKey::try_from(endpoint_id.as_bytes()).e()?;
            println!("{}", public_key.to_z32())
        }
        Command::PkarrToEndpoint { z32_pubkey } => {
            let public_key = pkarr::PublicKey::try_from(z32_pubkey.as_str()).e()?;
            let endpoint_id = EndpointId::from_bytes(public_key.as_bytes())?;
            println!("{endpoint_id}")
        }
    }
    Ok(())
}
