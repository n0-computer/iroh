use std::{fmt::Display, net::SocketAddr, path::PathBuf, str::FromStr};

use anyhow::anyhow;
use config::{ConfigError, Map, Source, Value};
use iroh_util::insert_into_config_map;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
// Config for the rpc Client
pub struct Config {
    // gateway rpc address
    pub gateway_addr: Addr,
    // p2p rpc address
    pub p2p_addr: Addr,
    // store rpc address
    pub store_addr: Addr,
}

#[derive(SerializeDisplay, DeserializeFromStr, Debug, Clone, PartialEq)]
pub enum Addr {
    GrpcHttp2(SocketAddr),
    GrpcUds(PathBuf),
    Mem, // TODO: channel
}

impl Addr {
    pub fn try_as_socket_addr(&self) -> Option<SocketAddr> {
        if let Addr::GrpcHttp2(addr) = self {
            return Some(*addr);
        }
        None
    }
}

impl Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Addr::GrpcHttp2(addr) => write!(f, "grpc://{}", addr),
            Addr::GrpcUds(path) => write!(f, "grpc://{}", path.display()),
            Addr::Mem => write!(f, "mem"),
        }
    }
}

impl FromStr for Addr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "mem" {
            return Ok(Addr::Mem);
        }

        let mut parts = s.split("://");
        if let Some(prefix) = parts.next() {
            if prefix == "grpc" {
                if let Some(part) = parts.next() {
                    if let Ok(addr) = part.parse::<SocketAddr>() {
                        return Ok(Addr::GrpcHttp2(addr));
                    }
                    if let Ok(path) = part.parse::<PathBuf>() {
                        return Ok(Addr::GrpcUds(path));
                    }
                }
            }
        }

        Err(anyhow!("invalid addr: {}", s))
    }
}

impl Source for Config {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut map: Map<String, Value> = Map::new();
        insert_into_config_map(&mut map, "gateway_addr", self.gateway_addr.to_string());
        insert_into_config_map(&mut map, "p2p_addr", self.p2p_addr.to_string());
        insert_into_config_map(&mut map, "store_addr", self.store_addr.to_string());
        Ok(map)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            gateway_addr: "grpc://0.0.0.0:4400".parse().unwrap(),
            p2p_addr: "grpc://0.0.0.0:4401".parse().unwrap(),
            store_addr: "grpc://0.0.0.0:4402".parse().unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::Config as ConfigBuilder;

    #[test]
    fn test_collect() {
        let default = Config::default();
        let mut expect: Map<String, Value> = Map::new();
        expect.insert(
            "gateway_addr".to_string(),
            Value::new(None, default.gateway_addr.to_string()),
        );
        expect.insert(
            "p2p_addr".to_string(),
            Value::new(None, default.p2p_addr.to_string()),
        );
        expect.insert(
            "store_addr".to_string(),
            Value::new(None, default.store_addr.to_string()),
        );
        let got = Config::default().collect().unwrap();
        for key in got.keys() {
            let left = expect.get(key).unwrap();
            let right = got.get(key).unwrap();
            assert_eq!(left, right);
        }
    }

    #[test]
    fn test_build_config_from_struct() {
        let expect = Config::default();
        let got: Config = ConfigBuilder::builder()
            .add_source(Config::default())
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();

        assert_eq!(expect, got);
    }

    #[test]
    fn test_addr_roundtrip() {
        let socket: SocketAddr = "198.168.2.1:1234".parse().unwrap();
        let addr = Addr::GrpcHttp2(socket);

        assert_eq!(addr.to_string().parse::<Addr>().unwrap(), addr);
        assert_eq!(addr.to_string(), "grpc://198.168.2.1:1234");

        let path: PathBuf = "/foo/bar".parse().unwrap();
        let addr = Addr::GrpcUds(path);

        assert_eq!(addr.to_string().parse::<Addr>().unwrap(), addr);
        assert_eq!(addr.to_string(), "grpc:///foo/bar");

        let addr = Addr::Mem;

        assert_eq!(addr.to_string().parse::<Addr>().unwrap(), addr);
        assert_eq!(addr.to_string(), "mem");
    }
}
