use std::net::SocketAddr;

use config::{ConfigError, Map, Source, Value, ValueKind};
use iroh_rpc_client::Config as RpcClientConfig;
use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};

pub const CONFIG: &str = "p2p.config.toml";

/// Libp2p config for the node.
#[derive(PartialEq, Debug, Clone, Deserialize, Serialize)]
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

impl Source for Libp2pConfig {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }
    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let rpc_client = self.rpc_client.collect()?;
        let mut map: Map<String, Value> = Map::new();
        insert_into_config_map(&mut map, "rpc_client", rpc_client);
        insert_into_config_map(&mut map, "rpc_addr", self.rpc_addr.to_string());
        // `config` package converts all unsigned integers into U64, which then has problems
        // downcasting to, in this case, u32. To get it to allow the convertion between the
        // config::Config and the p2p::Config, we need to cast it as a signed int
        insert_into_config_map(&mut map, "target_peer_count", self.target_peer_count as i64);
        insert_into_config_map(&mut map, "kademlia", self.kademlia);
        insert_into_config_map(&mut map, "mdns", self.mdns);
        let peers: Vec<String> = self.bootstrap_peers.iter().map(|b| b.to_string()).collect();
        insert_into_config_map(&mut map, "bootstrap_peers", peers);
        insert_into_config_map(
            &mut map,
            "listening_multiaddr",
            self.listening_multiaddr.to_string(),
        );
        Ok(map)
    }
}

fn insert_into_config_map<I: Into<String>, V: Into<ValueKind>>(
    map: &mut Map<String, Value>,
    field: I,
    val: V,
) {
    map.insert(field.into(), Value::new(None, val));
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

#[cfg(test)]
mod tests {
    use super::*;
    use config::Config as ConfigBuilder;

    #[test]
    fn test_collect() {
        let default = Libp2pConfig::default();
        let mut rpc_client_expect: Map<String, Value> = Map::new();
        rpc_client_expect.insert(
            "gateway_addr".to_string(),
            Value::new(None, default.rpc_client.gateway_addr.to_string()),
        );
        rpc_client_expect.insert(
            "p2p_addr".to_string(),
            Value::new(None, default.rpc_client.p2p_addr.to_string()),
        );
        rpc_client_expect.insert(
            "store_addr".to_string(),
            Value::new(None, default.rpc_client.store_addr.to_string()),
        );

        let bootstrap_peers: Vec<String> = default
            .bootstrap_peers
            .iter()
            .map(|node| node.to_string())
            .collect();
        // let mut bootstrap_peers_expect: Map<String, Value> = Map::new();
        // bootstrap_peers_expect.insert(
        //     "bootstrap_peers".to_string(),
        //     Value::new(None, bootstrap_peers),
        // );

        let mut expect: Map<String, Value> = Map::new();
        expect.insert(
            "rpc_client".to_string(),
            Value::new(None, rpc_client_expect),
        );
        expect.insert(
            "rpc_addr".to_string(),
            Value::new(None, default.rpc_addr.to_string()),
        );
        expect.insert(
            "target_peer_count".to_string(),
            // see `Source` implementation for  why we need to cast this as a signed int
            Value::new(None, default.target_peer_count as i64),
        );
        expect.insert("kademlia".to_string(), Value::new(None, default.kademlia));
        expect.insert("mdns".to_string(), Value::new(None, default.mdns));
        expect.insert(
            "bootstrap_peers".to_string(),
            Value::new(None, bootstrap_peers),
        );
        expect.insert(
            "listening_multiaddr".to_string(),
            Value::new(None, default.listening_multiaddr.to_string()),
        );

        let got = Libp2pConfig::default().collect().unwrap();
        for key in got.keys() {
            let left = expect.get(key).unwrap();
            let right = got.get(key).unwrap();
            assert_eq!(left, right);
        }
    }

    #[test]
    fn test_build_config_from_struct() {
        let expect = Libp2pConfig::default();
        let got: Libp2pConfig = ConfigBuilder::builder()
            .add_source(Libp2pConfig::default())
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();

        assert_eq!(expect, got);
    }
}
