use std::path::PathBuf;

use anyhow::{bail, Result};
use config::{ConfigError, Map, Source, Value};
use iroh_metrics::config::Config as MetricsConfig;
use iroh_rpc_client::{network::P2pClientAddr, Config as RpcClientConfig};
use iroh_rpc_types::Addr;
use iroh_util::{insert_into_config_map, iroh_data_root};
use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};

use crate::rpc::P2pServerAddr;

/// CONFIG_FILE_NAME is the name of the optional config file located in the iroh home directory
pub const CONFIG_FILE_NAME: &str = "p2p.config.toml";
/// ENV_PREFIX should be used along side the config field name to set a config field using
/// environment variables
/// For example, `IROH_P2P_MDNS=true` would set the value of the `Libp2pConfig.mdns` field
pub const ENV_PREFIX: &str = "IROH_P2P";

/// Default bootstrap nodes
///
/// Based on https://github.com/ipfs/go-ipfs-config/blob/master/bootstrap_peers.go#L17.
pub const DEFAULT_BOOTSTRAP: &[&str] = &[
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
    "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ", // mars.i.ipfs.io
];
// no udp support yet

// "/ip4/104.131.131.82/udp/4001/quic/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ", // mars.i.ipfs.io

/// Libp2p config for the node.
#[derive(PartialEq, Eq, Debug, Clone, Deserialize, Serialize)]
pub struct Libp2pConfig {
    /// Local address.
    pub listening_multiaddr: Multiaddr,
    /// Bootstrap peer list.
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Mdns discovery enabled.
    pub mdns: bool,
    /// Bitswap discovery enabled.
    pub bitswap: bool,
    /// Kademlia discovery enabled.
    pub kademlia: bool,
    /// Autonat holepunching enabled.
    pub autonat: bool,
    /// Relay server enabled.
    pub relay_server: bool,
    /// Relay client enabled.
    pub relay_client: bool,
    /// Gossipsub enabled.
    pub gossipsub: bool,
    pub max_conns_out: u32,
    pub max_conns_in: u32,
    pub max_conns_pending_out: u32,
    pub max_conns_pending_in: u32,
    pub max_conns_per_peer: u32,
    pub notify_handler_buffer_size: usize,
    pub connection_event_buffer_size: usize,
    pub dial_concurrency_factor: u8,
}

/// Configuration for the node.
#[derive(PartialEq, Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub libp2p: Libp2pConfig,
    pub rpc_client: RpcClientConfig,
    pub metrics: MetricsConfig,
    pub key_store_path: PathBuf,
}

impl Source for Libp2pConfig {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut map: Map<String, Value> = Map::new();
        // `config` package converts all unsigned integers into U64, which then has problems
        // downcasting to, in this case, u32. To get it to allow the convertion between the
        // config::Config and the p2p::Config, we need to cast it as a signed int
        insert_into_config_map(&mut map, "max_conns_in", self.max_conns_in as i64);
        insert_into_config_map(&mut map, "max_conns_out", self.max_conns_out as i64);
        insert_into_config_map(
            &mut map,
            "max_conns_pending_in",
            self.max_conns_pending_in as i64,
        );
        insert_into_config_map(
            &mut map,
            "max_conns_pending_out",
            self.max_conns_pending_out as i64,
        );
        insert_into_config_map(
            &mut map,
            "max_conns_per_peer",
            self.max_conns_per_peer as i64,
        );
        insert_into_config_map(
            &mut map,
            "notify_handler_buffer_size",
            self.notify_handler_buffer_size as i64,
        );
        insert_into_config_map(
            &mut map,
            "connection_event_buffer_size",
            self.connection_event_buffer_size as i64,
        );
        insert_into_config_map(
            &mut map,
            "dial_concurrency_factor",
            self.dial_concurrency_factor as i64,
        );

        insert_into_config_map(&mut map, "kademlia", self.kademlia);
        insert_into_config_map(&mut map, "autonat", self.autonat);
        insert_into_config_map(&mut map, "bitswap", self.bitswap);
        insert_into_config_map(&mut map, "mdns", self.mdns);
        insert_into_config_map(&mut map, "relay_server", self.relay_server);
        insert_into_config_map(&mut map, "relay_client", self.relay_client);
        insert_into_config_map(&mut map, "gossipsub", self.gossipsub);
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

impl Source for Config {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut map: Map<String, Value> = Map::new();

        insert_into_config_map(&mut map, "libp2p", self.libp2p.collect()?);
        insert_into_config_map(&mut map, "rpc_client", self.rpc_client.collect()?);
        insert_into_config_map(&mut map, "metrics", self.metrics.collect()?);
        insert_into_config_map(&mut map, "key_store_path", self.key_store_path.to_str());
        Ok(map)
    }
}

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
            autonat: true,
            relay_server: true,
            relay_client: true,
            gossipsub: true,
            bitswap: true,
            max_conns_pending_out: 256,
            max_conns_pending_in: 256,
            max_conns_in: 256,
            max_conns_out: 512,
            max_conns_per_peer: 8,
            notify_handler_buffer_size: 256,
            connection_event_buffer_size: 256,
            dial_concurrency_factor: 8,
        }
    }
}

impl Config {
    pub fn default_with_rpc(client_addr: P2pClientAddr) -> Self {
        Self {
            libp2p: Libp2pConfig::default(),
            rpc_client: RpcClientConfig {
                p2p_addr: Some(client_addr),
                ..Default::default()
            },
            metrics: MetricsConfig::default(),
            key_store_path: iroh_data_root().unwrap(),
        }
    }

    pub fn default_tcp() -> Self {
        let rpc_client = RpcClientConfig::default_tcp();

        Self {
            libp2p: Libp2pConfig::default(),
            rpc_client,
            metrics: MetricsConfig::default(),
            key_store_path: iroh_data_root().unwrap(),
        }
    }

    /// Derive server addr for non memory addrs.
    pub fn server_rpc_addr(&self) -> Result<Option<P2pServerAddr>> {
        self.rpc_client
            .p2p_addr
            .as_ref()
            .map(|addr| {
                #[allow(unreachable_patterns)]
                match addr {
                    Addr::Tcp(addr) => Ok(Addr::Tcp(*addr)),
                    #[cfg(unix)]
                    Addr::Uds(path) => Ok(Addr::Uds(path.clone())),
                    Addr::Mem(_) => bail!("can not derive rpc_addr for mem addr"),
                    _ => bail!("invalid rpc_addr"),
                }
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::Config as ConfigBuilder;

    #[test]
    fn test_collect() {
        let default = Config::default_tcp();
        let bootstrap_peers: Vec<String> = default
            .libp2p
            .bootstrap_peers
            .iter()
            .map(|node| node.to_string())
            .collect();

        let mut expect: Map<String, Value> = Map::new();
        expect.insert(
            "libp2p".to_string(),
            Value::new(None, default.libp2p.collect().unwrap()),
        );
        expect.insert(
            "rpc_client".to_string(),
            Value::new(None, default.rpc_client.collect().unwrap()),
        );
        expect.insert(
            "metrics".to_string(),
            Value::new(None, default.metrics.collect().unwrap()),
        );
        expect.insert(
            "key_store_path".to_string(),
            Value::new(None, iroh_data_root().unwrap().to_str()),
        );

        let got = default.collect().unwrap();
        for key in got.keys() {
            let left = expect.get(key).unwrap();
            let right = got.get(key).unwrap();
            assert_eq!(left, right);
        }

        // libp2p
        let mut expect: Map<String, Value> = Map::new();
        let default = &default.libp2p;

        // see `Source` implementation for  why we need to cast this as a signed int
        expect.insert(
            "max_conns_in".to_string(),
            Value::new(None, default.max_conns_in as i64),
        );
        expect.insert(
            "max_conns_out".to_string(),
            Value::new(None, default.max_conns_out as i64),
        );
        expect.insert(
            "max_conns_pending_in".to_string(),
            Value::new(None, default.max_conns_pending_in as i64),
        );
        expect.insert(
            "max_conns_pending_out".to_string(),
            Value::new(None, default.max_conns_pending_out as i64),
        );
        expect.insert(
            "max_conns_per_peer".to_string(),
            Value::new(None, default.max_conns_per_peer as i64),
        );

        expect.insert(
            "notify_handler_buffer_size".to_string(),
            Value::new(None, default.notify_handler_buffer_size as i64),
        );

        expect.insert(
            "connection_event_buffer_size".to_string(),
            Value::new(None, default.connection_event_buffer_size as i64),
        );
        expect.insert(
            "dial_concurrency_factor".to_string(),
            Value::new(None, default.dial_concurrency_factor as i64),
        );

        expect.insert("kademlia".to_string(), Value::new(None, default.kademlia));
        expect.insert("autonat".to_string(), Value::new(None, default.autonat));
        expect.insert("mdns".to_string(), Value::new(None, default.mdns));
        expect.insert("bitswap".to_string(), Value::new(None, default.bitswap));
        expect.insert(
            "relay_server".to_string(),
            Value::new(None, default.relay_server),
        );
        expect.insert(
            "relay_client".to_string(),
            Value::new(None, default.relay_client),
        );
        expect.insert("gossipsub".to_string(), Value::new(None, default.gossipsub));
        expect.insert(
            "bootstrap_peers".to_string(),
            Value::new(None, bootstrap_peers),
        );
        expect.insert(
            "listening_multiaddr".to_string(),
            Value::new(None, default.listening_multiaddr.to_string()),
        );

        let got = default.collect().unwrap();
        for key in got.keys() {
            dbg!(key);
            let left = expect.get(key).unwrap();
            let right = got.get(key).unwrap();
            assert_eq!(left, right);
        }
    }

    #[test]
    fn test_build_config_from_struct() {
        let expect = Config::default_tcp();
        let got: Config = ConfigBuilder::builder()
            .add_source(expect.clone())
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();

        assert_eq!(expect, got);
    }
}
