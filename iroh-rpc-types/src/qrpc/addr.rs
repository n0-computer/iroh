use anyhow::{anyhow, bail};
use quic_rpc::Service;
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::{
    fmt::{Debug, Display},
    net::SocketAddr,
    str::FromStr,
};

#[derive(DeserializeFromStr, Clone)]
pub enum Addr<S: Service> {
    Qrpc(SocketAddr),
    Mem(quic_rpc::mem::Channel<S::Res, S::Req>),
}

impl<S: Service> PartialEq for Addr<S> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Qrpc(addr1), Self::Qrpc(addr2)) => addr1.eq(addr2),
            _ => false,
        }
    }
}

impl<S: Service> Addr<S> {
    pub fn new_mem() -> (Addr<S>, quic_rpc::mem::Channel<S::Req, S::Res>) {
        let (r, s) = quic_rpc::mem::connection(1);

        (Addr::Mem(r), s)
    }
}

impl<S: Service> Addr<S> {
    pub fn try_as_socket_addr(&self) -> Option<SocketAddr> {
        if let Addr::Qrpc(addr) = self {
            return Some(*addr);
        }
        None
    }
}

impl<S: Service> Display for Addr<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Addr::Qrpc(addr) => write!(f, "qrpc://{}", addr),
            Addr::Mem(_) => write!(f, "mem"),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }
}

impl<S: Service> Debug for Addr<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl<S: Service> FromStr for Addr<S> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "mem" {
            bail!("memory addresses can not be serialized or deserialized");
        }

        let mut parts = s.split("://");
        if let Some(prefix) = parts.next() {
            if prefix == "grpc" {
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
        use crate::qrpc::gateway::GatewayService;

        let socket: SocketAddr = "198.168.2.1:1234".parse().unwrap();
        let addr = Addr::Qrpc(socket);

        assert_eq!(
            addr.to_string().parse::<Addr<GatewayService>>().unwrap(),
            addr
        );
        assert_eq!(addr.to_string(), "grpc://198.168.2.1:1234");
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
