use std::collections::HashMap;
use std::path::PathBuf;

// XXX iroh-ctl for some reason is able to import from itself using its name,
// but use iroh::api::GetAdd doesn't work for some reason
use crate::api::GetAdd;
use anyhow::Result;
use cid::Cid;
use clap::{Args, Parser, Subcommand};
use iroh_resolver::{
    resolver::{Out, OutMetrics},
    unixfs_builder,
};
use iroh_rpc_client::Client;

// the CLI belongs in iroh-ctl, but we want to experiment with it here for
// now based on the various traits and mock implementations.

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None, propagate_version = true)]
struct Cli {
    #[clap(long)]
    cfg: Option<PathBuf>,
    #[clap(long = "no-metrics")]
    no_metrics: bool,
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    // Version,
    #[clap(
        about = "break up a file or directory into blocks and provide those blocks on the ipfs network"
    )]
    Add {
        path: PathBuf,
        // #[clap(long, short)]
        // recursive: bool,
        // #[clap(long, short)]
        // wrap: bool,
    },
    #[clap(
        about = "get content based on a Content Identifier from the ipfs network, and save it "
    )]
    Get {
        cid: Cid,
        #[clap(long, short)]
        output: PathBuf,
    },
}

pub async fn run_cli_command<T: GetAdd>(api: &T) -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Add { path } => {
            let cid = api.add(&path).await?;
            println!("/ipfs/{}", cid);
        }
        Commands::Get { cid, output } => {
            api.get(cid, &output).await?;
        }
    }
    Ok(())
}
