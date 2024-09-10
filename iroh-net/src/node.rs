#![allow(missing_docs)]

use std::net::{SocketAddrV4, SocketAddrV6};

use anyhow::Result;
use iroh_base::{key::SecretKey, node_addr::NodeAddr};

use crate::{discovery::Discovery, dns::DnsResolver, relay::RelayMode};

use super::endpoint::{Builder as EndpointBuilder, Endpoint};

/// The node
#[derive(Debug, Clone)]
pub struct Node {
    endpoint: Endpoint,
}

impl Node {
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
}

/// Build it
#[derive(Debug)]
pub struct Builder {
    endpoint: EndpointBuilder,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            endpoint: Default::default(),
        }
    }
}

impl Builder {
    pub fn get_secret_key(&self) -> &SecretKey {
        &self.endpoint.secret_key
    }

    pub fn relay_mode(mut self, relay_mode: RelayMode) -> Self {
        self.endpoint = self.endpoint.relay_mode(relay_mode);
        self
    }

    pub fn discovery(mut self, discovery: Option<Box<dyn Discovery>>) -> Self {
        self.endpoint = self.endpoint.discovery(discovery);
        self
    }
    pub fn dns_resolver(mut self, dns_resolver: DnsResolver) -> Self {
        self.endpoint = self.endpoint.dns_resolver(dns_resolver);
        self
    }

    pub fn bind_addr_v4(mut self, addr: SocketAddrV4) -> Self {
        self.endpoint = self.endpoint.bind_addr_v4(addr);
        self
    }

    pub fn bind_addr_v6(mut self, addr: SocketAddrV6) -> Self {
        self.endpoint = self.endpoint.bind_addr_v6(addr);
        self
    }

    pub fn bind_random_port(mut self) -> Self {
        self.endpoint = self.endpoint.bind_random_port();
        self
    }

    pub fn secret_key(mut self, secret_key: SecretKey) -> Self {
        self.endpoint = self.endpoint.secret_key(secret_key);
        self
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn insecure_skip_relay_cert_verify(mut self, skip_verify: bool) -> Self {
        self.endpoint = self.endpoint.insecure_skip_relay_cert_verify(skip_verify);
        self
    }

    pub fn keylog(mut self, keylog: bool) -> Self {
        self.endpoint = self.endpoint.keylog(keylog);
        self
    }

    pub fn known_nodes(mut self, nodes: Vec<NodeAddr>) -> Self {
        self.endpoint = self.endpoint.known_nodes(nodes);
        self
    }

    pub async fn build(self) -> Result<Node> {
        let endpoint = self.endpoint.bind().await?;
        Ok(Node { endpoint })
    }
}
