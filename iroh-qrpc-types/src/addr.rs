use anyhow::{anyhow, bail};
use quic_rpc::Service;
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::{
    fmt::{Debug, Display},
    net::SocketAddr,
    str::FromStr,
};

/// An address. This can be either a memory address, already containing the channel, or a network
/// address which will have to be opened.
#[derive(SerializeDisplay, DeserializeFromStr)]
pub enum Addr<S: Service> {
    Http2(SocketAddr),
    Http2Lookup(String),
    Mem(
        quic_rpc::mem::ServerChannel<S::Req, S::Res>,
        quic_rpc::mem::ClientChannel<S::Res, S::Req>,
    ),
}

impl<S: Service> PartialEq for Addr<S> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Http2(addr1), Self::Http2(addr2)) => addr1.eq(addr2),
            (Self::Http2Lookup(addr1), Self::Http2Lookup(addr2)) => addr1.eq(addr2),
            _ => false,
        }
    }
}

impl<S: Service> Addr<S> {
    pub fn new_mem() -> Self {
        let (server, client) = quic_rpc::mem::connection(1);

        Self::Mem(server, client)
    }
}

impl<S: Service> Addr<S> {
    pub fn try_as_socket_addr(&self) -> Option<SocketAddr> {
        if let Addr::Http2(addr) = self {
            return Some(*addr);
        }
        None
    }
}

impl<S: Service> Display for Addr<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Addr::Http2(addr) => write!(f, "http://{}", addr),
            Addr::Http2Lookup(addr) => write!(f, "http://{}", addr),
            Addr::Mem(_, _) => write!(f, "mem"),
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

impl<S: Service> Clone for Addr<S> {
    fn clone(&self) -> Self {
        match self {
            Addr::Http2(addr) => Addr::Http2(*addr),
            Addr::Http2Lookup(addr) => Addr::Http2Lookup(addr.clone()),
            Addr::Mem(server, client) => Addr::Mem(server.clone(), client.clone()),
        }
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
            if prefix == "http" {
                if let Some(part) = parts.next() {
                    return Ok(if let Ok(addr) = part.parse() {
                        Addr::Http2(addr)
                    } else {
                        Addr::Http2Lookup(part.to_string())
                    });
                }
            }
        }

        Err(anyhow!("invalid addr: {}", s))
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_addr_roundtrip_grpc_http2() {
        use crate::gateway::GatewayAddr;
        use crate::Addr;
        use std::net::SocketAddr;

        let socket: SocketAddr = "198.168.2.1:1234".parse().unwrap();
        let addr = Addr::Http2(socket);

        assert_eq!(addr.to_string().parse::<GatewayAddr>().unwrap(), addr);
        assert_eq!(addr.to_string(), "http://198.168.2.1:1234");
    }
}
