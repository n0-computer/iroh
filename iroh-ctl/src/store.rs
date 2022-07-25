use std::path::PathBuf;

use anyhow::Result;
use cid::Cid;
use clap::{Args, Subcommand};
use iroh_rpc_client::Client;

#[derive(Args, Debug, Clone)]
pub struct Store {
    #[clap(subcommand)]
    command: StoreCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum StoreCommands {
    #[clap(about = "Version of the iroh store binary")]
    Version,
    Block(Block),
    #[clap(hide = true)]
    GetLinks {
        cid: Cid,
    },
}

#[derive(Args, Debug, Clone)]
#[clap(about = "Interact with raw IPFS blocks")]
pub struct Block {
    #[clap(subcommand)]
    command: BlockCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum BlockCommands {
    #[clap(about = "Get a raw IPFS block.")]
    Get { cid: Cid },
    #[clap(
        about = "Store input as an IPFS block.
Not yet implemented.",
        hide = true
    )]
    Put { path: PathBuf },
    #[clap(
        about = "Remove IPFS block(s).
Not yet implemented.",
        hide = true
    )]
    Rm { cid: Cid },
    #[clap(hide = true)]
    Has { cid: Cid },
}

pub async fn run_command(rpc: Client, cmd: Store) -> Result<()> {
    match cmd.command {
        StoreCommands::Version => {
            let v = rpc.try_store()?.version().await?;
            println!("v{}", v);
        }
        StoreCommands::Block(block) => match block.command {
            BlockCommands::Get { cid } => {
                let b = rpc.try_store()?.get(cid).await?;
                println!("{:?}\n", b);
            }
            BlockCommands::Put { path } => {
                todo!("`block put` command not yet implemented - path {:?}", path);
            }
            BlockCommands::Rm { cid } => {
                todo!(
                    "`block rm` command not yet implemented\narguments:\n\tcid {:?}",
                    cid
                );
            }
            BlockCommands::Has { cid } => {
                let b = rpc.try_store()?.has(cid).await?;
                println!("{}", b);
            }
        },
        StoreCommands::GetLinks { cid } => {
            let links = rpc.try_store()?.get_links(cid).await?;
            println!("{:#?}", links);
        }
    };
    Ok(())
}
