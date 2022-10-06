use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Error, Result};
use cid::Cid;
use clap::{Args, Subcommand};
use iroh::P2pApi;
use libp2p::{Multiaddr, PeerId};

#[derive(Args, Debug, Clone)]
#[clap(about = "Manage peer-2-peer networking.")]
pub struct P2p {
    #[clap(subcommand)]
    command: P2pCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum P2pCommands {
    Version,
    #[clap(about = "The local peer id of this node")]
    PeerId,
    Addrs(Addrs),
    #[clap(about = "Open a new direct connection to one or more peer addresses.
The address format is a Multiaddress.")]
    Connect {
        #[clap(long = "peer-id", short)]
        peer_id: PeerId,
        #[clap(long, short, required = true)]
        addrs: Vec<Multiaddr>,
    },
    #[clap(
        about = "Closes a connection to a peer address. The address format is a Multiaddress.
The disconnect is not permanent; if iroh needs to talk to that address later, it will reconnect."
    )]
    Disconnect {
        #[clap(long = "peer-id", short)]
        peer_id: PeerId,
    },
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
    Dht(Dht),
    Bitswap(Bitswap),
    Dev(Dev),
}

#[derive(Debug, Clone)]
pub enum PingArg {
    PeerId(PeerId),
    Multiaddr(Multiaddr),
}

impl FromStr for PingArg {
    type Err = Error;
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
A number of factors can change the set of addresses, including a change in IP address, discovery of additional IP addresses outside of NAT layers, and changes in addresses announced to the network.",
        hide = true
    )]
    Local,
}

#[derive(Args, Debug, Clone)]
#[clap(about = "Issue distributed hash table (DHT) commands", hide = true)]
pub struct Dht {
    #[clap(subcommand)]
    command: DhtCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum DhtCommands {
    #[clap(
        about = "Find the multiaddresses associated with a Peer ID.
Not yet implemented.",
        hide = true
    )]
    FindPeer { peer_id: PeerId },
    #[clap(about = "Find peers that can provide a specific value, given a key.")]
    FindProvs { cid: Cid },
    #[clap(
        about = "Given a key, query the routing system for its best value.
Not yet implemented.",
        hide = true
    )]
    Get { cid: Cid },
    #[clap(
        about = "Announce this node is providing values for a key to the network.
Not yet implemented.",
        hide = true
    )]
    Provide {
        cid: Cid,
        #[clap(long, short)]
        recursive: bool,
    },
    #[clap(
        about = "Write a key/value pair to the routing system.
Not yet implemented.",
        hide = true
    )]
    Put { key: Cid, file_path: PathBuf },
    #[clap(
        about = "Find the closest Peer IDs to a given Peer ID by querying the DHT.
Not yet implemented.",
        hide = true
    )]
    Query { peer_id: PeerId },
}

#[derive(Args, Debug, Clone)]
#[clap(
    about = "Interact with the bitswap agent.
Not yet implemented.",
    hide = true
)]
pub struct Bitswap {
    #[clap(subcommand)]
    command: BitswapCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum BitswapCommands {
    #[clap(
        about = "Show the current ledger for a peer.
Not yet implemented.",
        hide = true
    )]
    Ledger { peer_id: PeerId },
    #[clap(
        about = "Trigger reprovider to announce our data to the network.
Not yet implemented.",
        hide = true
    )]
    Reprovide,
    #[clap(
        about = "Show blocks currently on the wantlist.
Not yet implemented.",
        hide = true
    )]
    Wantlist,
}

#[derive(Args, Debug, Clone)]
#[clap(hide = true)]
pub struct Dev {
    #[clap(subcommand)]
    command: DevCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum DevCommands {
    FetchBitswap {
        cid: Cid,
        #[clap(required = true)]
        providers: Vec<PeerId>,
    },
    FetchProviders {
        cid: Cid,
    },
    Gossipsub(Gossipsub),
}

#[derive(Args, Debug, Clone)]
#[clap(hide = true)]
pub struct Gossipsub {
    #[clap(subcommand)]
    command: GossipsubCommands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum GossipsubCommands {
    Publish {
        topic: String,
        #[clap(long, short)]
        file: Option<PathBuf>,
    },
    Subscribe {
        topic: String,
    },
    Unsubscribe {
        topic: String,
    },
}

pub async fn run_command(p2p: &impl P2pApi, cmd: &P2p) -> Result<()> {
    match &cmd.command {
        P2pCommands::Version => {
            let version = p2p.p2p_version().await?;
            println!("v{}", version);
        }
        P2pCommands::PeerId => {
            let peer_id = p2p.local_peer_id().await?;
            println!("{}", peer_id);
        }
        P2pCommands::Addrs(addrs) => match addrs.command {
            None => {
                let peer_map = p2p.peers().await?;
                println!("{:#?}", peer_map);
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
        P2pCommands::Connect { peer_id, addrs } => {
            p2p.connect(peer_id, addrs).await?;
            println!("connected to {}", peer_id);
        }
        P2pCommands::Disconnect { peer_id } => {
            p2p.disconnect(peer_id).await?;
            println!("disconnected from {}", peer_id);
        }
        P2pCommands::Peers => {
            let peer_ids = p2p.peer_ids().await?;
            for peer_id in peer_ids {
                println!("{}", peer_id);
            }
        }
        P2pCommands::Ping { ping_args, count } => {
            todo!("{:?} {:?}", ping_args, count);
        }
        P2pCommands::Dht(d) => match d.command {
            DhtCommands::FindProvs { cid } => {
                let providers = p2p.fetch_providers(&cid).await?;
                for prov in providers {
                    println!("{}", prov);
                }
            }
            _ => todo!("not yet implemented - {:?}", d.command),
        },
        P2pCommands::Bitswap(d) => {
            todo!("Bitswap commands are not yet implemented - {:#?}", d);
        }
        P2pCommands::Dev(dev) => match &dev.command {
            DevCommands::FetchBitswap { cid, providers } => {
                let res = p2p.fetch_bitswap(cid, providers).await?;
                println!("{:#?}", res);
            }
            DevCommands::FetchProviders { cid } => {
                let res = p2p.fetch_providers(cid).await?;
                println!("{:#?}", res);
            }
            DevCommands::Gossipsub(g) => match &g.command {
                GossipsubCommands::Publish { topic, file } => {
                    let message_id = p2p.publish(topic, file.as_deref()).await?;
                    println!("Message Id: {}", message_id);
                }
                GossipsubCommands::Subscribe { topic } => {
                    let success = p2p.subscribe(topic).await?;
                    if success {
                        println!("Subscribed to {}", topic);
                    } else {
                        println!("Failed to subscribe to {}", topic);
                    }
                }
                GossipsubCommands::Unsubscribe { topic } => {
                    let success = p2p.unsubscribe(topic).await?;
                    if success {
                        println!("Unsubscribed from {}", topic);
                    } else {
                        println!("Failed to unsubscribe from {}", topic);
                    }
                }
            },
        },
    };
    Ok(())
}
