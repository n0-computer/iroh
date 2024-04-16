//! Utilities to dial a node.

use anyhow::Context;
use iroh_net::key::SecretKey;
use iroh_net::relay::{RelayMap, RelayMode};
use iroh_net::NodeAddr;

/// Options for the client
#[derive(Clone, Debug)]
pub struct Options {
    /// The secret key of the node
    pub secret_key: SecretKey,
    /// The peer to connect to.
    pub peer: NodeAddr,
    /// Whether to log the SSL keys when `SSLKEYLOGFILE` environment variable is set
    pub keylog: bool,
    /// The configuration of the relay services
    pub relay_map: Option<RelayMap>,
}

/// Create a new endpoint and dial a peer, returning the connection
///
/// Note that this will create an entirely new endpoint, so it should be only
/// used for short lived connections. If you want to connect to multiple peers,
/// it is preferable to create an endpoint and use `connect` on the endpoint.
pub async fn dial(opts: Options) -> anyhow::Result<quinnx::Connection> {
    let endpoint = iroh_net::MagicEndpoint::builder()
        .secret_key(opts.secret_key)
        .keylog(opts.keylog);
    let relay_mode = match opts.relay_map {
        Some(relay_map) => RelayMode::Custom(relay_map),
        None => RelayMode::Default,
    };
    let endpoint = endpoint.relay_mode(relay_mode);
    let endpoint = endpoint.bind(0).await?;
    endpoint
        .connect(opts.peer, iroh_bytes::protocol::ALPN)
        .await
        .context("failed to connect to provider")
}
