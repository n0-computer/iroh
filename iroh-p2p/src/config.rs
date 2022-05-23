use std::net::SocketAddr;

use iroh_rpc_client::RpcClientConfig;
use libp2p::Multiaddr;

/// Libp2p config for the node.
#[derive(Debug)]
pub struct Libp2pConfig {
    /// Local address.
    pub listening_multiaddr: Multiaddr,
    /// Bootstrap peer list.
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Mdns discovery enabled.
    pub mdns: bool,
    /// Kademlia discovery enabled.
    pub kademlia: bool,
    /// Target peer count.
    pub target_peer_count: u32,
    /// Rpc listening addr
    pub rpc_addr: SocketAddr,
    pub rpc_client: RpcClientConfig,
}

// Based on https://github.com/ipfs/go-ipfs-config/blob/master/bootstrap_peers.go#L17.
pub const DEFAULT_BOOTSTRAP: &[&str] = &[
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
    "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ", // mars.i.ipfs.io
];
// no udp support yet

// "/ip4/104.131.131.82/udp/4001/quic/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ", // mars.i.ipfs.io

impl Default for Libp2pConfig {
    fn default() -> Self {
        let bootstrap_peers = DEFAULT_BOOTSTRAP
            .iter()
            .map(|node| node.parse().unwrap())
            .collect();

        Self {
            listening_multiaddr: "/ip4/0.0.0.0/tcp/4444".parse().unwrap(),
            bootstrap_peers,
            mdns: false,
            kademlia: true,
            target_peer_count: 75,
            rpc_addr: "0.0.0.0:4401".parse().unwrap(),
            rpc_client: RpcClientConfig::default(),
        }
    }
}
