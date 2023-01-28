use std::path::PathBuf;

use anyhow::Result;
use config::{ConfigError, Map, Source, Value};
use iroh_metrics::config::Config as MetricsConfig;
use iroh_rpc_client::Config as RpcClientConfig;
use iroh_rpc_types::p2p::P2pAddr;
use iroh_util::{insert_into_config_map, iroh_data_root};
use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};

/// CONFIG_FILE_NAME is the name of the optional config file located in the iroh home directory
pub const CONFIG_FILE_NAME: &str = "p2p.config.toml";
/// ENV_PREFIX should be used along side the config field name to set a config field using
/// environment variables
/// For example, `IROH_P2P_MDNS=true` would set the value of the `Libp2pConfig.mdns` field
pub const ENV_PREFIX: &str = "IROH_P2P";

/// Default bootstrap nodes
///
/// Based on <https://github.com/ipfs/go-ipfs-config/blob/master/bootstrap_peers.go#L17>.
pub const DEFAULT_BOOTSTRAP: &[&str] = &[
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
    "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ", // mars.i.ipfs.io
];
// no udp support yet

// "/ip4/104.131.131.82/udp/4001/quic/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ", // mars.i.ipfs.io

/// The configuration for the p2p server.
///
/// This is the configuration which the p2p server binary needs to run.  It is a superset
/// from the configuration needed by the p2p service, which can also run integrated into
/// another binary like in iroh-one, iroh-share or iroh-embed.
#[derive(PartialEq, Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    pub p2p: Config,
    pub metrics: MetricsConfig,
}

impl ServerConfig {
    pub fn new() -> Self {
        Default::default()
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            p2p: Config::default_network(),
            metrics: Default::default(),
        }
    }
}

impl Source for ServerConfig {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut map: Map<String, Value> = Map::new();
        insert_into_config_map(&mut map, "p2p", self.p2p.collect()?);
        insert_into_config_map(&mut map, "metrics", self.metrics.collect()?);
        Ok(map)
    }
}

/// Libp2p config for the node.
#[derive(PartialEq, Eq, Debug, Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Libp2pConfig {
    /// Local address.
    pub listening_multiaddrs: Vec<Multiaddr>,
    /// Bootstrap peer list.
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Mdns discovery enabled.
    pub mdns: bool,
    /// Bitswap server mode enabled.
    pub bitswap_server: bool,
    /// Bitswap client mode enabled.
    pub bitswap_client: bool,
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
    /// Don't dial RFC 1918 addresses if enabled.
    pub global_only: bool,
}

/// Configuration for the [`iroh-p2p`] node.
#[derive(PartialEq, Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Configuration for libp2p.
    pub libp2p: Libp2pConfig,
    /// Configuration of RPC to other iroh services.
    pub rpc_client: RpcClientConfig,
    /// Directory where cryptographic keys are stored.
    ///
    /// The p2p node needs to have an identity consisting of a cryptographic key pair.  As
    /// it is useful to have the same identity across restarts this is stored on disk in a
    /// format compatible with how ssh stores keys.  This points to a directory where these
    /// keypairs are stored.
    pub key_store_path: PathBuf,
}

impl From<ServerConfig> for Config {
    fn from(source: ServerConfig) -> Self {
        source.p2p
    }
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
        insert_into_config_map(&mut map, "bitswap_client", self.bitswap_client);
        insert_into_config_map(&mut map, "bitswap_server", self.bitswap_server);
        insert_into_config_map(&mut map, "mdns", self.mdns);
        insert_into_config_map(&mut map, "relay_server", self.relay_server);
        insert_into_config_map(&mut map, "relay_client", self.relay_client);
        insert_into_config_map(&mut map, "gossipsub", self.gossipsub);
        let peers: Vec<String> = self.bootstrap_peers.iter().map(|b| b.to_string()).collect();
        insert_into_config_map(&mut map, "bootstrap_peers", peers);
        let addrs: Vec<String> = self
            .listening_multiaddrs
            .iter()
            .map(|b| b.to_string())
            .collect();
        insert_into_config_map(&mut map, "listening_multiaddrs", addrs);
        insert_into_config_map(&mut map, "global_only", self.global_only);
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
            listening_multiaddrs: vec![
                "/ip4/0.0.0.0/tcp/4444".parse().unwrap(),
                "/ip4/0.0.0.0/udp/4445/quic-v1".parse().unwrap(),
            ],
            bootstrap_peers,
            mdns: false,
            kademlia: true,
            autonat: true,
            relay_server: true,
            relay_client: true,
            gossipsub: true,
            bitswap_client: true,
            bitswap_server: true,
            max_conns_pending_out: 256,
            max_conns_pending_in: 256,
            max_conns_in: 256,
            max_conns_out: 512,
            max_conns_per_peer: 8,
            notify_handler_buffer_size: 256,
            connection_event_buffer_size: 256,
            dial_concurrency_factor: 8,
            global_only: false,
        }
    }
}

impl Config {
    pub fn default_with_rpc(client_addr: P2pAddr) -> Self {
        Self {
            libp2p: Libp2pConfig::default(),
            rpc_client: RpcClientConfig {
                p2p_addr: Some(client_addr),
                ..Default::default()
            },
            key_store_path: iroh_data_root().unwrap(),
        }
    }

    pub fn default_network() -> Self {
        let rpc_client = RpcClientConfig::default_network();

        Self {
            libp2p: Libp2pConfig::default(),
            rpc_client,
            key_store_path: iroh_data_root().unwrap(),
        }
    }

    pub fn rpc_addr(&self) -> Option<P2pAddr> {
        self.rpc_client.p2p_addr.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::Config as ConfigBuilder;

    #[test]
    fn test_collect() {
        let default = ServerConfig::default();
        let bootstrap_peers: Vec<String> = default
            .p2p
            .libp2p
            .bootstrap_peers
            .iter()
            .map(|node| node.to_string())
            .collect();

        let addrs: Vec<String> = default
            .p2p
            .libp2p
            .listening_multiaddrs
            .iter()
            .map(|addr| addr.to_string())
            .collect();

        let mut expect: Map<String, Value> = Map::new();
        expect.insert(
            "p2p".to_string(),
            Value::new(None, default.p2p.collect().unwrap()),
        );
        expect.insert(
            "metrics".to_string(),
            Value::new(None, default.metrics.collect().unwrap()),
        );

        let got = default.collect().unwrap();
        for key in got.keys() {
            let left = expect.get(key).unwrap();
            let right = got.get(key).unwrap();
            assert_eq!(left, right);
        }

        // libp2p
        let mut expect: Map<String, Value> = Map::new();
        let default = &default.p2p.libp2p;

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
        expect.insert(
            "bitswap_server".to_string(),
            Value::new(None, default.bitswap_server),
        );
        expect.insert(
            "bitswap_client".to_string(),
            Value::new(None, default.bitswap_client),
        );
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
        expect.insert("listening_multiaddrs".to_string(), Value::new(None, addrs));
        expect.insert(
            "global_only".to_string(),
            Value::new(None, default.global_only),
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
        let expect = Config::default_network();
        let got: Config = ConfigBuilder::builder()
            .add_source(expect.clone())
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();

        assert_eq!(expect, got);
    }
}
