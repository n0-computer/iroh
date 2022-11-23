use anyhow::{anyhow, bail};
use quic_rpc::{RpcMessage, Service};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::{
    fmt::{Debug, Display},
    net::SocketAddr,
    str::FromStr,
};

/// A client addr for a service. This can be either a socket address or
/// the actual mem channel to use to reach the server side.
#[derive(SerializeDisplay, DeserializeFromStr)]
pub enum Addr<In: RpcMessage, Out: RpcMessage> {
    Qrpc(SocketAddr),
    Mem(quic_rpc::mem::Channel<In, Out>),
}

impl<Req: RpcMessage, Res: RpcMessage> PartialEq for Addr<Req, Res> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Qrpc(addr1), Self::Qrpc(addr2)) => addr1.eq(addr2),
            _ => false,
        }
    }
}

impl<Req: RpcMessage, Res: RpcMessage> Addr<Req, Res> {
    pub fn new_mem() -> (Addr<Req, Res>, Addr<Res, Req>) {
        let (client, server) = quic_rpc::mem::connection(1);

        (Addr::Mem(server), Addr::Mem(client))
    }

    pub fn flip(&self) -> anyhow::Result<Addr<Res, Req>> {
        match self {
            Self::Qrpc(addr) => Ok(Addr::Qrpc(*addr)),
            Self::Mem(_) => Err(anyhow!("Cannot flip mem channel")),
        }
    }
}

impl<Req: RpcMessage, Res: RpcMessage> Addr<Req, Res> {
    pub fn try_as_socket_addr(&self) -> Option<SocketAddr> {
        if let Addr::Qrpc(addr) = self {
            return Some(*addr);
        }
        None
    }
}

impl<Req: RpcMessage, Res: RpcMessage> Display for Addr<Req, Res> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Addr::Qrpc(addr) => write!(f, "qrpc://{}", addr),
            Addr::Mem(_) => write!(f, "mem"),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }
}

impl<Req: RpcMessage, Res: RpcMessage> Debug for Addr<Req, Res> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl<Req: RpcMessage, Res: RpcMessage> Clone for Addr<Req, Res> {
    fn clone(&self) -> Self {
        match self {
            Addr::Qrpc(addr) => Addr::Qrpc(*addr),
            Addr::Mem(mem) => Addr::Mem(mem.clone()),
        }
    }
}

impl<Req: RpcMessage, Res: RpcMessage> FromStr for Addr<Req, Res> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "mem" {
            bail!("memory addresses can not be serialized or deserialized");
        }

        let mut parts = s.split("://");
        if let Some(prefix) = parts.next() {
            if prefix == "qrpc" {
                if let Some(part) = parts.next() {
                    if let Ok(addr) = part.parse::<SocketAddr>() {
                        return Ok(Addr::Qrpc(addr));
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
        use crate::gateway::GatewayClientAddr;

        let socket: SocketAddr = "198.168.2.1:1234".parse().unwrap();
        let addr = Addr::Qrpc(socket);

        assert_eq!(addr.to_string().parse::<GatewayClientAddr>().unwrap(), addr);
        assert_eq!(addr.to_string(), "qrpc://198.168.2.1:1234");
    }

    // // TODO(b5): only running this on unix b/c windows doesn't have localhost
    // // enabled by default
    // #[cfg(all(feature = "grpc", unix))]
    // #[test]
    // fn test_addr_roundtrip_http2_lookup() {
    //     let name = "localhost:1234".to_string();
    //     let addr = Addr::GrpcHttp2Lookup(name);

    //     assert_eq!(addr.to_string().parse::<Addr>().unwrap(), addr);
    //     assert_eq!(addr.to_string(), "grpc://localhost:1234");
    // }
    //
    // #[cfg(all(feature = "grpc", unix))]
    // #[test]
    // fn test_addr_roundtrip_grpc_uds() {
    //     let path: std::path::PathBuf = "/foo/bar".parse().unwrap();
    //     let addr = Addr::GrpcUds(path);

    //     assert_eq!(addr.to_string().parse::<Addr>().unwrap(), addr);
    //     assert_eq!(addr.to_string(), "grpc:///foo/bar");
    // }
}
