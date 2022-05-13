use std::collections::{HashMap, HashSet};

use cid::Cid;
use futures::channel::oneshot::Sender as OneShotSender;
use libp2p::kad::record::Key;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

use iroh_bitswap::Block;

pub struct Namespace;

impl std::fmt::Display for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "p2p")
    }
}

#[allow(clippy::from_over_into)]
impl Into<String> for Namespace {
    fn into(self) -> String {
        self.to_string()
    }
}

pub enum Methods {
    FetchBitswap,
    FetchProvider,
    GetListeningAddrs,
    GetPeers,
    Connect,
    Disconnect,
}

impl std::fmt::Display for Methods {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let s = match self {
            Methods::FetchBitswap => "fetch_bitswap",
            Methods::FetchProvider => "fetch_provider",
            Methods::GetListeningAddrs => "get_listening_addrs",
            Methods::GetPeers => "get_peers",
            Methods::Connect => "connect",
            Methods::Disconnect => "disconnect",
        };
        write!(f, "{}", s)
    }
}

#[allow(clippy::from_over_into)]
impl Into<String> for Methods {
    fn into(self) -> String {
        self.to_string()
    }
}

/// Rpc specific messages handled by the p2p node
#[derive(Debug)]
pub enum RpcMessage {
    BitswapRequest {
        cids: Vec<Cid>,
        response_channels: Vec<OneShotSender<Block>>,
        providers: Option<HashSet<PeerId>>,
    },
    ProviderRequest {
        key: Key,
        response_channel: OneShotSender<Option<Result<HashSet<PeerId>, String>>>,
    },
    NetAddrsListen(OneShotSender<(PeerId, Vec<Multiaddr>)>),
    NetPeers(OneShotSender<HashMap<PeerId, Vec<Multiaddr>>>),
    NetConnect(OneShotSender<bool>, PeerId, Vec<Multiaddr>),
    NetDisconnect(OneShotSender<()>, PeerId),
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum Requests {
    // TODO: expand to ask for multiple cids
    FetchBitswap {
        cid: Cid,
        providers: Option<HashSet<PeerId>>,
    },
    FetchProvider {
        key: Key,
    },
    NetConnect {
        peer_id: PeerId,
        addrs: Vec<Multiaddr>,
    },
    NetDisconnect(PeerId),
}

impl std::fmt::Display for Requests {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum Responses {
    // TODO: check into this response, not sure if it's correct
    ProviderResponse(Option<Result<HashSet<PeerId>, String>>),
    NetAddrsListen {
        peer_id: PeerId,
        listeners: Vec<Multiaddr>,
    },
    NetPeers(HashMap<PeerId, Vec<Multiaddr>>),
    NetConnect(bool),
    NetDisconnect(()),
}

impl std::fmt::Display for Responses {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
