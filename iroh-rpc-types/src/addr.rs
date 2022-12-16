use anyhow::{anyhow, bail};
use quic_rpc::{transport::mem, Service};
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
    Irpc(SocketAddr),
    IrpcLookup(String),
    Mem(
        mem::ServerChannel<S::Req, S::Res>,
        mem::ClientChannel<S::Res, S::Req>,
    ),
}

impl<S: Service> PartialEq for Addr<S> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Irpc(addr1), Self::Irpc(addr2)) => addr1.eq(addr2),
            (Self::IrpcLookup(addr1), Self::IrpcLookup(addr2)) => addr1.eq(addr2),
            _ => false,
        }
    }
}

impl<S: Service> Addr<S> {
    pub fn new_mem() -> Self {
        let (server, client) = mem::connection(256);

        Self::Mem(server, client)
    }
}

impl<S: Service> Addr<S> {
    pub fn try_as_socket_addr(&self) -> Option<SocketAddr> {
        if let Addr::Irpc(addr) = self {
            return Some(*addr);
        }
        None
    }
}

impl<S: Service> Display for Addr<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Addr::Irpc(addr) => write!(f, "irpc://{addr}"),
            Addr::IrpcLookup(addr) => write!(f, "irpc://{addr}"),
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
            Addr::Irpc(addr) => Addr::Irpc(*addr),
            Addr::IrpcLookup(addr) => Addr::IrpcLookup(addr.clone()),
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

        let mut parts = s.splitn(2, "://");
        if let Some(prefix) = parts.next() {
            if prefix == "irpc" {
                if let Some(part) = parts.next() {
                    return Ok(if let Ok(addr) = part.parse() {
                        Addr::Irpc(addr)
                    } else {
                        Addr::IrpcLookup(part.to_string())
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
    fn test_addr_roundtrip_irpc_http2() {
        use crate::gateway::GatewayAddr;
        use crate::Addr;
        use std::net::SocketAddr;

        let socket: SocketAddr = "198.168.2.1:1234".parse().unwrap();
        let addr = Addr::Irpc(socket);

        assert_eq!(addr.to_string().parse::<GatewayAddr>().unwrap(), addr);
        assert_eq!(addr.to_string(), "irpc://198.168.2.1:1234");
    }
}
