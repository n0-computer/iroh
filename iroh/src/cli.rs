use std::path::PathBuf;
use std::str::FromStr;

use crate::api::{Api, P2p, Store};
use cid::Cid;
use clap::{Args, Parser, Subcommand};
use libp2p::{Multiaddr, PeerId};

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
    P2p(P2pSubCommand),
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

pub async fn run_cli_command<A: Api<P, S>, P: P2p, S: Store>(api: &A) -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::P2p(p2p_sub_command) => run_p2p_command(api.p2p()?, p2p_sub_command).await?,
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

async fn run_p2p_command<P: P2p>(p2p: P, cmd: P2pSubCommand) -> anyhow::Result<()> {
    match cmd.command {
        P2pCommands::PeerId => {
            let peer_id = p2p.local_peer_id().await?;
            println!("{}", peer_id);
        }
        P2pCommands::Addrs(addrs) => match addrs.command {
            None => {
                let addrs = p2p.peers().await?;
                println!("{:#?}", addrs);
            }
            Some(AddrsCommands::Listen) => {
                let addrs = p2p.addrs_listen().await?;
                println!("{:#?}", addrs);
            }
            Some(AddrsCommands::Local) => {
                let addrs = p2p.addrs_local().await?;
                println!("external addressses:");
                addrs.iter().for_each(|a| println!("\t:{:?}", a));
            }
        },
        P2pCommands::Peers => {
            let peers = p2p.peers().await?;
            println!("{:#?}", peers);
        }
        P2pCommands::Ping { ping_args, count } => {
            todo!("{:?} {:?}", ping_args, count);
        }
    }
    Ok(())
}

#[derive(Args, Debug, Clone)]
#[clap(about = "Manage peer-2-peer networking.")]
pub struct P2pSubCommand {
    #[clap(subcommand)]
    command: P2pCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum P2pCommands {
    #[clap(about = "The local peer id of this node")]
    PeerId,
    Addrs(Addrs),
    #[clap(
        about = "List the set of peers this node is connected to. Addresses are shown in multiaddress format, with each entry in the list showing a unique connection."
    )]
    Peers,
    #[clap(
        about = "Ping is a tool to test sending data to other peers. It sends pings, waits for pongs, and prints out round-trip latency information.
If a multiaddress is provided, only that address is dialed.
If a peerID is provided, ping looks up the peer via the routing system, and will choose an addresses during connection negotiation.",
        hide = true
    )]
    Ping {
        ping_args: Vec<PingArg>,
        #[clap(long, short = 'n')]
        count: usize,
    },
}

#[derive(Args, Debug, Clone)]
#[clap(
    about = "When connected to a p2p network, this peer will discover the addresses of other peers. This command lists all multiaddresses this node has encountered, grouped by the peerID they are associated with"
)]
pub struct Addrs {
    #[clap(subcommand)]
    command: Option<AddrsCommands>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum AddrsCommands {
    #[clap(
        about = "Lists all interface addresses this node is listening on. Addresses are shown in multiaddress format"
    )]
    Listen,
    #[clap(
        about = "Show addresses this node has broadcast for other peers to connect to this process. Addresses are listed in multiaddress format.
A number of factors can change the set of addresses, including a change in IP address, discovery of additional IP addresses outside of NAT layers, and changes in addresses announced to the network.
Not yet implemented.",
        hide = true
    )]
    Local,
}

#[derive(Debug, Clone)]
pub enum PingArg {
    PeerId(PeerId),
    Multiaddr(Multiaddr),
}

impl FromStr for PingArg {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(m) = Multiaddr::from_str(s) {
            return Ok(PingArg::Multiaddr(m));
        }
        if let Ok(p) = PeerId::from_str(s) {
            return Ok(PingArg::PeerId(p));
        }
        Err(anyhow::anyhow!("invalid peer id or multiaddress"))
    }
}
