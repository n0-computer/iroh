use std::{
    fmt::{Debug, Display},
    net::SocketAddr,
    str::FromStr,
};

use anyhow::{anyhow, bail};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use tokio::sync::mpsc::{Receiver, Sender};

#[derive(SerializeDisplay, DeserializeFromStr, Clone)]
pub enum Addr<T = ()> {
    #[cfg(feature = "grpc")]
    GrpcHttp2(SocketAddr),
    #[cfg(feature = "grpc")]
    GrpcHttp2Lookup(String),
    #[cfg(all(feature = "grpc", unix))]
    GrpcUds(std::path::PathBuf),
    #[cfg(feature = "mem")]
    Mem(T),
}

impl<T> PartialEq for Addr<T> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            #[cfg(feature = "grpc")]
            (Self::GrpcHttp2(addr1), Self::GrpcHttp2(addr2)) => addr1.eq(addr2),
            #[cfg(feature = "grpc")]
            (Self::GrpcHttp2Lookup(addr1), Self::GrpcHttp2Lookup(addr2)) => addr1.eq(addr2),
            #[cfg(all(feature = "grpc", unix))]
            (Self::GrpcUds(path1), Self::GrpcUds(path2)) => path1.eq(path2),
            _ => false,
        }
    }
}

impl<T> Addr<T> {
    pub fn new_mem() -> (Addr<Receiver<T>>, Addr<Sender<T>>) {
        let (s, r) = tokio::sync::mpsc::channel(256);

        (Addr::Mem(r), Addr::Mem(s))
    }
}

impl<T> Addr<T> {
    pub fn try_as_socket_addr(&self) -> Option<SocketAddr> {
        #[cfg(feature = "grpc")]
        if let Addr::GrpcHttp2(addr) = self {
            return Some(*addr);
        }
        None
    }
}

impl<T> Display for Addr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "grpc")]
            Addr::GrpcHttp2(addr) => write!(f, "grpc://{}", addr),
            #[cfg(feature = "grpc")]
            Addr::GrpcHttp2Lookup(addr) => write!(f, "grpc://{}", addr),
            #[cfg(all(feature = "grpc", unix))]
            Addr::GrpcUds(path) => write!(f, "grpc://{}", path.display()),
            #[cfg(feature = "mem")]
            Addr::Mem(_) => write!(f, "mem"),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }
}

impl<T> Debug for Addr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl<T> FromStr for Addr<T> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        #[cfg(feature = "mem")]
        if s == "mem" {
            bail!("memory addresses can not be serialized or deserialized");
        }

        #[cfg(feature = "grpc")]
        {
            use std::net::ToSocketAddrs;
            let mut parts = s.split("://");
            if let Some(prefix) = parts.next() {
                if prefix == "grpc" {
                    if let Some(part) = parts.next() {
                        if let Ok(addr) = part.parse::<SocketAddr>() {
                            return Ok(Addr::GrpcHttp2(addr));
                        }
                        // attempt to resolve the address, if it can be resolved,
                        // it's considered a lookup address
                        if let Ok(mut addr_iter) = part.to_socket_addrs() {
                            if addr_iter.next().is_some() {
                                return Ok(Addr::GrpcHttp2Lookup(String::from(part)));
                            }
                        }
                        #[cfg(unix)]
                        if let Ok(path) = part.parse::<std::path::PathBuf>() {
                            return Ok(Addr::GrpcUds(path));
                        }
                    }
                }
            }
        }

        Err(anyhow!("invalid addr: {}", s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "grpc")]
    #[test]
    fn test_addr_roundtrip_grpc_http2() {
        let socket: SocketAddr = "198.168.2.1:1234".parse().unwrap();
        let addr = Addr::GrpcHttp2(socket);

        assert_eq!(addr.to_string().parse::<Addr>().unwrap(), addr);
        assert_eq!(addr.to_string(), "grpc://198.168.2.1:1234");
    }

    // TODO(b5): only running this on unix b/c windows doesn't have localhost
    // enabled by default
    #[cfg(all(feature = "grpc", unix))]
    #[test]
    fn test_addr_roundtrip_http2_lookup() {
        let name = "localhost:1234".to_string();
        let addr = Addr::GrpcHttp2Lookup(name);

        assert_eq!(addr.to_string().parse::<Addr>().unwrap(), addr);
        assert_eq!(addr.to_string(), "grpc://localhost:1234");
    }

    #[cfg(all(feature = "grpc", unix))]
    #[test]
    fn test_addr_roundtrip_grpc_uds() {
        let path: std::path::PathBuf = "/foo/bar".parse().unwrap();
        let addr = Addr::GrpcUds(path);

        assert_eq!(addr.to_string().parse::<Addr>().unwrap(), addr);
        assert_eq!(addr.to_string(), "grpc:///foo/bar");
    }
}
