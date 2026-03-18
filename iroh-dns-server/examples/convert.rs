use std::str::FromStr;

use clap::Parser;
use iroh::EndpointId;
use iroh_relay::pkarr::{public_key_from_z32, public_key_to_z32};
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
            println!("{}", public_key_to_z32(&endpoint_id))
        }
        Command::PkarrToEndpoint { z32_pubkey } => {
            let public_key = public_key_from_z32(&z32_pubkey).anyerr()?;
            let endpoint_id = EndpointId::from_bytes(public_key.as_bytes())?;
            println!("{endpoint_id}")
        }
    }
    Ok(())
}
