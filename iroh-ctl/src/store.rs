use std::io::prelude::*;
use std::path::PathBuf;

use anyhow::Result;
use cid::Cid;
use clap::{Args, Subcommand};
use iroh::StoreApi;

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

pub async fn run_command(store: &impl StoreApi, cmd: &Store) -> Result<()> {
    match &cmd.command {
        StoreCommands::Version => {
            let v = store.store_version().await?;
            println!("v{}", v);
        }
        StoreCommands::Block(block) => match block.command {
            BlockCommands::Get { cid } => {
                let b = store.block_get(&cid).await?;
                if let Some(b) = b {
                    std::io::stdout().write_all(&b)?;
                } else {
                    println!("local store does not contain block {}", cid);
                }
            }
            BlockCommands::Put { path: _ } => {
                todo!("TBD");
                // I think this shouldn't be in terms of a path but in terms of bytes or stdin
                // let cid = unixfs_builder::add_file(Some(&rpc), path.as_path(), false).await?;
                // println!("/ipfs/{}\n", cid);
            }
            BlockCommands::Rm { cid } => {
                todo!(
                    "`block rm` command not yet implemented\narguments:\n\tcid {:?}",
                    cid
                );
            }
            BlockCommands::Has { cid } => {
                let b = store.block_has(&cid).await?;
                println!("{}", b);
            }
        },
        StoreCommands::GetLinks { cid } => {
            let links = store.get_links(&cid).await?;
            println!("{:#?}", links);
        }
    };
    Ok(())
}
