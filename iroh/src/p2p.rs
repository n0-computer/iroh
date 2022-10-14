use std::str::FromStr;

use anyhow::{Error, Result};
use clap::{Args, Subcommand};
use iroh_api::{Multiaddr, P2pApi, PeerId, PeerIdOrAddr};

#[derive(Args, Debug, Clone)]
#[clap(about = "Peer-2-peer commands")]
#[clap(
    after_help = "p2p commands all relate to peer-2-peer connectivity. See subcommands for
additional details."
)]
pub struct P2p {
    #[clap(subcommand)]
    command: P2pCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum P2pCommands {
    #[clap(about = "Connect to a peer")]
    #[clap(after_help = "
Attempts to open a new direct connection to a peer address. By default p2p
continulously maintains an open set of peer connections based on requests &
internal hueristics. Connect is useful in situations where it makes sense to
manually force libp2p to dial a known peer. A common example includes when you
know the multiaddr or peer ID of a peer that you would like to exchange data
with.

The address format is in multiaddr format. For example:

 > iroh p2p connect /ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ

for more info on multiaddrs see https://iroh.computer/docs/concepts#multiaddr

If a peer ID is provided, connect first perform a distribtued hash table (DHT)
lookup to learn the address of the given peer ID before dialing.")]
    Connect {
        /// Multiaddr or peer ID of a peer to connect to
        addr: PeerIdOrAddrArg,
    },
    #[clap(about = "Retrieve info about a node")]
    #[clap(
        after_help = "Takes as input a peer ID or address and prints the output of the libp2p-identify
protocol. When provided with a peer ID, the address is looked up on the 
Network's Distributed Hash Table (DHT) before connecting to the node. When 
provided with a multiaddress, the connection is dialed directly.

Providing no <ADDR> argument will return your local node information."
    )]
    Lookup {
        /// multiaddress or peer ID
        addr: PeerIdOrAddrArg,
    },
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
        P2pCommands::Connect { .. } => {
            todo!("`iroh p2p connect` is not yet implemented")
        }
        P2pCommands::Lookup { addr } => {
            let lookup = p2p.lookup(&addr.0).await?;
            println!("peer id: {}", lookup.peer_id);
        }
    };
    Ok(())
}
