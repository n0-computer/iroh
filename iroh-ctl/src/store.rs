use std::io::prelude::*;
use std::path::PathBuf;

use anyhow::Result;
use cid::Cid;
use clap::{Args, Subcommand};
use iroh_resolver::unixfs_builder;
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
    #[clap(about = "Get a raw IPFS block from the store & print the content to stdout")]
    Get { cid: Cid },
    #[clap(about = "Store input as an IPFS block.")]
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
                if let Some(b) = b {
                    std::io::stdout().write_all(&b)?;
                } else {
                    println!("local store does not contain block {}", cid);
                }
            }
            BlockCommands::Put { path } => {
                let cid = unixfs_builder::add_file(Some(&rpc), path.as_path(), false).await?;
                println!("/ipfs/{}\n", cid);
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
