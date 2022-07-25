use std::{
    fmt::{Debug, Display},
    net::SocketAddr,
    str::FromStr,
};

use anyhow::{anyhow, bail};
use async_channel::{Receiver, Sender};
use serde_with::{DeserializeFromStr, SerializeDisplay};

#[derive(SerializeDisplay, DeserializeFromStr, Clone)]
pub enum Addr<SEND = (), RECV = ()> {
    #[cfg(feature = "grpc")]
    GrpcHttp2(SocketAddr),
    #[cfg(all(feature = "grpc", unix))]
    GrpcUds(std::path::PathBuf),
    #[cfg(feature = "mem")]
    Mem(Sender<RECV>, Receiver<SEND>),
}

impl<S, R> PartialEq for Addr<S, R> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            #[cfg(feature = "grpc")]
            (Self::GrpcHttp2(addr1), Self::GrpcHttp2(addr2)) => addr1.eq(addr2),
            #[cfg(all(feature = "grpc", unix))]
            (Self::GrpcUds(path1), Self::GrpcUds(path2)) => path1.eq(path2),
            _ => false,
        }
    }
}

impl<S, R> Addr<S, R> {
    pub fn new_mem() -> (Addr<S, R>, Addr<R, S>) {
        let (s1, r1) = async_channel::bounded(256);
        let (s2, r2) = async_channel::bounded(256);

        (Addr::Mem(s1, r2), Addr::Mem(s2, r1))
    }

    pub fn try_as_socket_addr(&self) -> Option<SocketAddr> {
        #[cfg(feature = "grpc")]
        if let Addr::GrpcHttp2(addr) = self {
            return Some(*addr);
        }
        None
    }
}

impl<S, R> Display for Addr<S, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "grpc")]
            Addr::GrpcHttp2(addr) => write!(f, "grpc://{}", addr),
            #[cfg(all(feature = "grpc", unix))]
            Addr::GrpcUds(path) => write!(f, "grpc://{}", path.display()),
            #[cfg(feature = "mem")]
            Addr::Mem(_, _) => write!(f, "mem"),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }
}

impl<S, R> Debug for Addr<S, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl<S, R> FromStr for Addr<S, R> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        #[cfg(feature = "mem")]
        if s == "mem" {
            bail!("memory addresses can not be serialized or deserialized");
        }

        let mut parts = s.split("://");
        if let Some(prefix) = parts.next() {
            #[cfg(feature = "grpc")]
            if prefix == "grpc" {
                if let Some(part) = parts.next() {
                    if let Ok(addr) = part.parse::<SocketAddr>() {
                        return Ok(Addr::GrpcHttp2(addr));
                    }
                    #[cfg(unix)]
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
    fn test_addr_roundtrip_grpc_http2() {
        let socket: SocketAddr = "198.168.2.1:1234".parse().unwrap();
        let addr = Addr::GrpcHttp2(socket);

        assert_eq!(addr.to_string().parse::<Addr>().unwrap(), addr);
        assert_eq!(addr.to_string(), "grpc://198.168.2.1:1234");
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
