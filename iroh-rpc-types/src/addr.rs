use std::{fmt::Display, net::SocketAddr, str::FromStr};

use anyhow::anyhow;
use serde_with::{DeserializeFromStr, SerializeDisplay};

#[derive(SerializeDisplay, DeserializeFromStr, Debug, Clone, PartialEq)]
pub enum Addr {
    #[cfg(feature = "grpc")]
    GrpcHttp2(SocketAddr),
    #[cfg(feature = "grpc")]
    GrpcUds(std::path::PathBuf),
    #[cfg(feature = "mem")]
    Mem, // TODO: channel
}

impl Addr {
    pub fn try_as_socket_addr(&self) -> Option<SocketAddr> {
        #[cfg(feature = "grpc")]
        if let Addr::GrpcHttp2(addr) = self {
            return Some(*addr);
        }
        None
    }
}

impl Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "grpc")]
            Addr::GrpcHttp2(addr) => write!(f, "grpc://{}", addr),
            #[cfg(feature = "grpc")]
            Addr::GrpcUds(path) => write!(f, "grpc://{}", path.display()),
            #[cfg(feature = "mem")]
            Addr::Mem => write!(f, "mem"),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }
}

impl FromStr for Addr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        #[cfg(feature = "mem")]
        if s == "mem" {
            return Ok(Addr::Mem);
        }

        let mut parts = s.split("://");
        if let Some(prefix) = parts.next() {
            #[cfg(feature = "grpc")]
            if prefix == "grpc" {
                if let Some(part) = parts.next() {
                    if let Ok(addr) = part.parse::<SocketAddr>() {
                        return Ok(Addr::GrpcHttp2(addr));
                    }
                    if let Ok(path) = part.parse::<std::path::PathBuf>() {
                        return Ok(Addr::GrpcUds(path));
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
    fn test_addr_roundtrip_grpc() {
        let socket: SocketAddr = "198.168.2.1:1234".parse().unwrap();
        let addr = Addr::GrpcHttp2(socket);

        assert_eq!(addr.to_string().parse::<Addr>().unwrap(), addr);
        assert_eq!(addr.to_string(), "grpc://198.168.2.1:1234");

        let path: std::path::PathBuf = "/foo/bar".parse().unwrap();
        let addr = Addr::GrpcUds(path);

        assert_eq!(addr.to_string().parse::<Addr>().unwrap(), addr);
        assert_eq!(addr.to_string(), "grpc:///foo/bar");
    }

    #[cfg(feature = "mem")]
    #[test]
    fn test_addr_roundtrip_mem() {
        let addr = Addr::Mem;

        assert_eq!(addr.to_string().parse::<Addr>().unwrap(), addr);
        assert_eq!(addr.to_string(), "mem");
    }
}
