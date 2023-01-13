use std::{net::SocketAddr, path::PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};

use sendme::{client, server};

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
#[clap(about = "Send data.")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Serve the data from the given path
    #[clap(about = "Serve the data from the given path")]
    Server {
        paths: Vec<PathBuf>,
        #[clap(long, short)]
        /// Optional port, efaults to 4433.
        port: Option<u16>,
    },
    /// Fetch some data
    #[clap(about = "Fetch the data from the hash")]
    Client {
        hash: bao::Hash,
        #[clap(long, short)]
        /// Option address of the server, defaults to 127.0.0.1:4433.
        addr: Option<SocketAddr>,
        #[clap(long, short)]
        /// Option path to save the file, defaults to using the hash as the name.
        out: Option<PathBuf>,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Client { hash, addr, out } => {
            println!("Requesting: {}", hash.to_hex());
            let opts = client::Options { addr, out };
            client::run(hash, opts).await?
        }
        Commands::Server { paths, port } => {
            let db = server::create_db(paths.iter().map(|p| p.as_path()).collect()).await?;
            let opts = server::Options { port };
            server::run(db, opts).await?
        }
    }

    Ok(())
}
