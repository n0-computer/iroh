use std::str::FromStr;

use anyhow::{Error, Result};
use clap::{Args, Subcommand};
use iroh::P2pApi;
use iroh::PeerIdOrAddr;
use libp2p::{Multiaddr, PeerId};

#[derive(Args, Debug, Clone)]
#[clap(about = "Manage peer-2-peer networking.")]
pub struct P2p {
    #[clap(subcommand)]
    command: P2pCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum P2pCommands {
    #[clap(about = "Retrieve info about a node")]
    Lookup { addr: PeerIdOrAddrArg },
}

#[derive(Debug, Clone)]
pub struct PeerIdOrAddrArg(PeerIdOrAddr);

impl FromStr for PeerIdOrAddrArg {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(m) = Multiaddr::from_str(s) {
            return Ok(PeerIdOrAddrArg(PeerIdOrAddr::Multiaddr(m)));
        }
        if let Ok(p) = PeerId::from_str(s) {
            return Ok(PeerIdOrAddrArg(PeerIdOrAddr::PeerId(p)));
        }
        Err(anyhow::anyhow!("invalid peer id or multiaddress"))
    }
}

pub async fn run_command(p2p: &impl P2pApi, cmd: &P2p) -> Result<()> {
    match &cmd.command {
        P2pCommands::Lookup { addr } => {
            let lookup = p2p.lookup(&addr.0).await?;
            println!("peer id: {}", lookup.peer_id);
        }
    };
    Ok(())
}
