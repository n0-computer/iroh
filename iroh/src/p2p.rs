use crate::doc;
use anyhow::{Error, Result};
use clap::{Args, Subcommand};
use crossterm::style::Stylize;
use iroh_api::{peer_id_from_multiaddr, Lookup, Multiaddr, P2pApi, PeerId, PeerIdOrAddr};
use std::{collections::HashMap, fmt::Display, str::FromStr};

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
    #[clap(after_help = doc::P2P_CONNECT_LONG_DESCRIPTION)]
    Connect {
        /// Multiaddr or peer ID of a peer to connect to
        addr: PeerIdOrAddrArg,
    },
    #[clap(about = "Retrieve info about a node")]
    #[clap(after_help = doc::P2P_LOOKUP_LONG_DESCRIPTION)]
    Lookup {
        /// multiaddress or peer ID
        addr: Option<PeerIdOrAddrArg>,
    },
    #[clap(about = "List connected peers")]
    #[clap(after_help = doc::P2P_PEERS_LONG_DESCRIPTION)]
    Peers {},
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

impl Display for PeerIdOrAddrArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let peer_id_or_addr = match &self.0 {
            PeerIdOrAddr::PeerId(p) => p.to_string(),
            PeerIdOrAddr::Multiaddr(a) => a.to_string(),
        };
        write!(f, "{peer_id_or_addr}")
    }
}

pub async fn run_command(p2p: &P2pApi, cmd: &P2p) -> Result<()> {
    match &cmd.command {
        P2pCommands::Connect { addr } => {
            let res = match &addr.0 {
                PeerIdOrAddr::PeerId(peer_id) => p2p.connect(*peer_id, vec![]).await,
                PeerIdOrAddr::Multiaddr(addr) => {
                    let peer_id = peer_id_from_multiaddr(addr)?;
                    p2p.connect(peer_id, vec![addr.clone()]).await
                }
            };
            match res {
                Ok(_) => {
                    println!("Connected to {addr}!");
                }
                Err(e) => return Err(e),
            }
        }
        P2pCommands::Lookup { addr } => {
            let lookup = match addr {
                Some(addr) => p2p.lookup(&addr.0).await?,
                None => p2p.lookup_local().await?,
            };
            display_lookup(&lookup);
        }
        P2pCommands::Peers {} => {
            let peers = p2p.peers().await?;
            display_peers(peers);
        }
    };
    Ok(())
}

fn display_lookup(l: &Lookup) {
    println!("{}\n  {}", "Peer ID:".bold().dim(), l.peer_id);
    println!("{}\n  {}", "Agent Version:".bold().dim(), l.agent_version);
    println!(
        "{}\n  {}",
        "Protocol Version:".bold().dim(),
        l.protocol_version
    );
    println!(
        "{} {}",
        "Observed Addresses".bold().dim(),
        format!("({}):", l.observed_addrs.len()).bold().dim()
    );
    l.observed_addrs
        .iter()
        .for_each(|addr| println!("  {addr}"));
    println!(
        "{} {}",
        "Listening Addresses".bold().dim(),
        format!("({}):", l.listen_addrs.len()).bold().dim()
    );
    l.listen_addrs.iter().for_each(|addr| println!("  {addr}"));
    println!(
        "{} {}\n  {}",
        "Protocols".bold().dim(),
        format!("({}):", l.protocols.len()).bold().dim(),
        l.protocols.join("\n  ")
    );
}

fn display_peers(peers: HashMap<PeerId, Vec<Multiaddr>>) {
    // let mut pid_str: String;
    for (peer_id, addrs) in peers {
        if let Some(addr) = addrs.first() {
            println!("{addr}/p2p/{peer_id}");
        }
    }
}
