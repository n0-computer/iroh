use crate::doc;
use anyhow::{Error, Result};
use clap::{Args, Subcommand};
use iroh_api::{Lookup, Multiaddr, P2pApi, PeerId, PeerIdOrAddr};
use std::{fmt::Display, str::FromStr};

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
        write!(f, "{}", peer_id_or_addr)
    }
}

pub async fn run_command(p2p: &impl P2pApi, cmd: &P2p) -> Result<()> {
    match &cmd.command {
        P2pCommands::Connect { addr } => match p2p.connect(&addr.0).await {
            Ok(_) => {
                println!("Connected to {}!", addr);
            }
            Err(e) => return Err(e),
        },
        P2pCommands::Lookup { addr } => {
            let lookup = match addr {
                Some(addr) => p2p.lookup(&addr.0).await?,
                None => p2p.lookup_local().await?,
            };
            display_lookup(&lookup);
        }
    };
    Ok(())
}

fn display_lookup(l: &Lookup) {
    println!(
        r#"
peer id: {}
listening addresses: {:?}
protocols: {:?}
protocol version: {}
observed addresses: {:?}
"#,
        l.peer_id, l.listen_addrs, l.protocols, l.protocol_version, l.observed_addrs
    );
}
