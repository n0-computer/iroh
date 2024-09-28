#![allow(missing_docs)]

use std::{
    net::{SocketAddrV4, SocketAddrV6},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use futures_lite::StreamExt;
use futures_util::{
    future::{MapErr, Shared},
    FutureExt, TryFutureExt,
};
use iroh_base::{key::SecretKey, node_addr::NodeAddr};
use tokio::task::{JoinError, JoinSet};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{debug, error, error_span, warn, Instrument};

use crate::{
    discovery::Discovery, dns::DnsResolver, endpoint::Incoming, protocol::{ProtocolHandler, ProtocolMap}, relay::RelayMode
};

use super::endpoint::{Builder as EndpointBuilder, Endpoint};

/// How long we wait at most for some endpoints to be discovered.
const ENDPOINT_WAIT: Duration = Duration::from_secs(5);

/// The node
#[derive(Debug, Clone)]
pub struct Node {
    endpoint: Endpoint,
    protocols: Arc<ProtocolMap>,
    task: Shared<MapErr<AbortOnDropHandle<()>, JoinErrToStr>>,
    cancel_token: CancellationToken,
}

pub(crate) type JoinErrToStr = Box<dyn Fn(JoinError) -> String + Send + Sync + 'static>;

impl Node {
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn protocols(&self) -> &Arc<ProtocolMap> {
        &self.protocols
    }

    pub async fn shutdown(self) -> Result<()> {
        self.cancel_token.cancel();
        self.task.await.map_err(|err| anyhow::anyhow!(err))?;
        Ok(())
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

    pub async fn build(self) -> Result<ProtocolBuilder> {
        let endpoint = self.endpoint.bind().await?;

        Ok(ProtocolBuilder {
            endpoint,
            protocols: ProtocolMap::default(),
        })
    }
}

/// A node that is initialized but not yet spawned.
#[derive(Debug)]
pub struct ProtocolBuilder {
    endpoint: Endpoint,
    protocols: ProtocolMap,
}

impl ProtocolBuilder {
    pub fn accept(mut self, alpn: Vec<u8>, handler: Arc<dyn ProtocolHandler>) -> Self {
        self.protocols.insert(alpn, handler);
        self
    }

    /// Returns the [`Endpoint`] of the node.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Returns a protocol handler for an ALPN.
    ///
    /// This downcasts to the concrete type and returns `None` if the handler registered for `alpn`
    /// does not match the passed type.
    pub fn get_protocol<P: ProtocolHandler>(&self, alpn: &[u8]) -> Option<Arc<P>> {
        self.protocols.get_typed(alpn)
    }

    /// Spawns the node and starts accepting connections.
    pub async fn spawn(self) -> Result<Node> {
        let Self {
            endpoint,
            protocols,
        } = self;
        let protocols = Arc::new(protocols);
        let node_id = endpoint.node_id();

        // Update the endpoint with our alpns.
        let alpns = protocols
            .alpns()
            .map(|alpn| alpn.to_vec())
            .collect::<Vec<_>>();
        if let Err(err) = endpoint.set_alpns(alpns) {
            shutdown(endpoint, &protocols).await;
            return Err(err);
        }

        let mut join_set = JoinSet::<anyhow::Result<()>>::new();
        let cancel_token = CancellationToken::new();

        // Spawn the main task and store it in the node for structured termination in shutdown.
        let fut = {
            let endpoint = endpoint.clone();
            let cancel_token = cancel_token.clone();
            let protocols = protocols.clone();

            async move {
                let (ipv4, ipv6) = endpoint.bound_sockets();
                debug!(
                    "listening at: {}{}",
                    ipv4,
                    ipv6.map(|addr| format!(" and {addr}")).unwrap_or_default()
                );

                loop {
                    tokio::select! {
                        biased;
                        _ = cancel_token.cancelled() => {
                            break;
                        }
                        // handle incoming p2p connections.
                        Some(incoming) = endpoint.accept() => {
                            let protocols = protocols.clone();
                            join_set.spawn(async move {
                                handle_connection(incoming, protocols).await;
                                Ok(())
                            });
                        }
                        // handle task terminations and quit on panics.
                        res = join_set.join_next(), if !join_set.is_empty() => {
                            match res {
                                Some(Err(outer)) => {
                                    if outer.is_panic() {
                                        error!("Task panicked: {outer:?}");
                                        break;
                                    } else if outer.is_cancelled() {
                                        debug!("Task cancelled: {outer:?}");
                                    } else {
                                        error!("Task failed: {outer:?}");
                                        break;
                                    }
                                }
                                Some(Ok(Err(inner))) => {
                                    debug!("Task errored: {inner:?}");
                                }
                                _ => {}
                            }
                        },
                        else => break,

                    }
                }
                shutdown(endpoint, &protocols).await;
                join_set.shutdown().await;

            }
            .instrument(error_span!("node", me=%node_id.fmt_short()))
        };
        let task = tokio::task::spawn(fut);

        let node = Node {
            endpoint: endpoint.clone(),
            protocols,
            task: AbortOnDropHandle::new(task)
                .map_err(Box::new(|e: JoinError| e.to_string()) as JoinErrToStr)
                .shared(),
            cancel_token,
        };

        // Wait for a single direct address update, to make sure
        // we found at least one direct address.
        let wait_for_endpoints = {
            let endpoint = endpoint.clone();
            async move {
                tokio::time::timeout(ENDPOINT_WAIT, endpoint.direct_addresses().next())
                    .await
                    .context("waiting for endpoint")?
                    .context("no endpoints")?;
                Ok(())
            }
        };

        if let Err(err) = wait_for_endpoints.await {
            node.shutdown().await?;
            return Err(err);
        }

        Ok(node)
    }
}

async fn shutdown(endpoint: Endpoint, protocols: &ProtocolMap) {
    let error_code = 1u16;

    // We ignore all errors during shutdown.
    let _ = tokio::join!(
        // Close the endpoint.
        endpoint.close(error_code.into(), b"provider terminating"),
        // Shutdown protocol handlers.
        protocols.shutdown(),
    );
}

async fn handle_connection(incoming: Incoming, protocols: Arc<ProtocolMap>) {
    let mut connecting = match incoming.accept() {
        Ok(conn) => conn,
        Err(err) => {
            warn!("Ignoring connection: accepting failed: {err:#}");
            return;
        }
    };
    let alpn = match connecting.alpn().await {
        Ok(alpn) => alpn,
        Err(err) => {
            warn!("Ignoring connection: invalid handshake: {err:#}");
            return;
        }
    };
    let Some(handler) = protocols.get(&alpn) else {
        warn!("Ignoring connection: unsupported ALPN protocol");
        return;
    };
    if let Err(err) = handler.accept(connecting).await {
        warn!("Handling incoming connection ended with error: {err}");
    }
}
