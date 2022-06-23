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
    Dag(Dag),
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
    Rm {
        cids: Vec<String>,
        #[clap(short, long)]
        force: bool,
    },
    #[clap(hide = true)]
    Has { cid: Cid },
}

#[derive(Args, Debug, Clone)]
#[clap(
    about = "Interact with IPLD DAG objects.
Not yet implemented.",
    hide = true
)]
pub struct Dag {
    #[clap(subcommand)]
    command: DagCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum DagCommands {
    #[clap(
        about = "Streams the selected DAG as a .car stream on stdout.
Not yet implemented.",
        hide = true
    )]
    Export {
        root: Cid,
        #[clap(short, long)]
        progress: bool,
    },
    #[clap(
        about = "Get a DAG node from IPFS.
Not yet implemented.",
        hide = true
    )]
    Get {
        cid: Cid,
        #[clap(short, long = "output-codec")]
        output_codec: String,
    },
    #[clap(
        about = "Import the contents of .car files.
Not yet implemented.",
        hide = true
    )]
    Import {
        path: PathBuf,
        #[clap(short, long = "pin-roots")]
        pin_roots: bool,
    },
    #[clap(
        about = "Add a DAG node to IPFS.
Not yet implemented.",
        hide = true
    )]
    Put { path: PathBuf },
    #[clap(
        about = "Remove DAG from IPFS node.
Not yet implemented.",
        hide = true
    )]
    Remove { cid: Cid },
}

pub async fn run_command(rpc: Client, cmd: Store) -> Result<()> {
    match cmd.command {
        StoreCommands::Version => {
            let v = rpc.store.version().await?;
            println!("v{}", v);
        }
        StoreCommands::Block(block) => {
            match block.command {
                BlockCommands::Get { cid } => {
                    let b = rpc.store.get(cid).await?;
                    println!("{:?}\n", b);
                }
                BlockCommands::Put { path } => {
                    todo!("`block put` command not yet implemented - path {:?}", path);
                }
                BlockCommands::Rm { cids, force } => {
                    todo!("`block rm` command not yet implemented\narguments:\n\tcid {:?}\n\tforce {:?}", cids, force);
                }
                BlockCommands::Has { cid } => {
                    let b = rpc.store.has(cid).await?;
                    println!("{}", b);
                }
            }
        }
        StoreCommands::Dag(dag) => match dag.command {
            DagCommands::Export { root, progress } => {
                todo!("`dag export` command not yet implemented\narguments:\n\troot {:?}\n\tprogress {:?}", root, progress);
            }
            DagCommands::Get { cid, output_codec } => {
                todo!("`dag get` command not yet implemented\narguments:\n\tcid {:?}\n\toutput_codec {:?}", cid, output_codec);
            }
            DagCommands::Put { path } => {
                todo!(
                    "`dag put` command not yet implemented\narguments:\n\tpath {:?}",
                    path
                );
            }
            DagCommands::Import { path, pin_roots } => {
                todo!("`dag import` command not yet implemented\narguments:\n\tpath {:?}\n\tpin_roots {:?}", path, pin_roots);
            }
            DagCommands::Remove { cid } => {
                todo!(
                    "`dag remove` command not yet implemented\narguments:\n\tcid {:?}",
                    cid
                );
            }
        },
        StoreCommands::GetLinks { cid } => {
            let links = rpc.store.get_links(cid).await?;
            println!("{:#?}", links);
        }
    };
    Ok(())
}
