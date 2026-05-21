//! Runtime revocation of relay access via the [`AccessControl`] trait.
//!
//! Exercises a [`RestrictedServer`] that fronts a relay [`Server`] with a
//! runtime-mutable token allow-list. The [`AccessControl`] implementation
//! indexes connections by auth token (built from `on_connect`/`on_disconnect`),
//! so revoking a token yields the connections to evict through
//! [`Clients::disconnect`].
//!
//! [`AccessControl`]: iroh_relay::server::AccessControl
//! [`Clients::disconnect`]: iroh_relay::server::clients::Clients::disconnect

#![cfg(feature = "server")]

use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};

use iroh_base::{EndpointId, RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    client::{Client, ClientBuilder, ConnectError},
    protos::{
        handshake,
        relay::{ClientToRelayMsg, RelayToClientMsg},
    },
    server::{
        Access, AccessControl, ClientRequest, ConnectionId, RelayConfig, Server, ServerConfig,
    },
    tls::{CaRootsConfig, default_provider},
};
use n0_error::{Result, StackResultExt, StdResultExt};
use n0_future::{SinkExt, StreamExt};
use n0_tracing_test::traced_test;
use rand::RngExt;

/// Shared state behind [`TokenAccess`].
#[derive(Debug, Default)]
struct AccessState {
    /// Auth tokens currently permitted to connect.
    allowed: HashSet<String>,
    /// Index of connected connections, grouped by the auth token they used.
    ///
    /// Built from `on_connect`/`on_disconnect`.
    connections: HashMap<(EndpointId, ConnectionId), String>,
}

/// An [`AccessControl`] with a runtime-mutable token allow-list.
///
/// Admits a connection if its auth token is currently allowed, and indexes the
/// connection under that token so a revoked token maps back to the connections
/// that used it. `on_disconnect` prunes the index.
#[derive(Debug)]
struct TokenAccess(Mutex<AccessState>);

impl TokenAccess {
    fn new(allowed: impl IntoIterator<Item = &'static str>) -> Arc<Self> {
        Arc::new(Self(Mutex::new(AccessState {
            allowed: allowed.into_iter().map(String::from).collect(),
            connections: HashMap::new(),
        })))
    }

    /// Adds `token` to the allow-list.
    fn allow(&self, token: &str) {
        self.0
            .lock()
            .expect("poisoned")
            .allowed
            .insert(token.into());
    }

    /// Removes `token` from the allow-list and returns its indexed connections.
    fn revoke(&self, revoked_token: &str) -> Vec<(EndpointId, ConnectionId)> {
        let mut state = self.0.lock().expect("poisoned");
        state.allowed.remove(revoked_token);
        let mut removed = vec![];
        state.connections.retain(|id, token| {
            if token == revoked_token {
                removed.push(*id);
                false
            } else {
                true
            }
        });
        removed
    }
}

impl AccessControl for TokenAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let mut state = self.0.lock().expect("poisoned");
        match request.auth_token() {
            Some(token) if state.allowed.contains(token) => {
                let id = (request.endpoint_id(), request.connection_id());
                state.connections.insert(id, token.to_string());
                Access::Allow
            }
            _ => Access::Deny,
        }
    }

    fn on_disconnect(&self, endpoint_id: EndpointId, connection_id: ConnectionId) {
        let mut state = self.0.lock().expect("poisoned");
        state.connections.remove(&(endpoint_id, connection_id));
    }
}

/// A relay [`Server`] paired with the [`TokenAccess`] guarding it.
///
/// Bundles the token allow-list with the running server so tests can grant and
/// revoke tokens, and have revocation evict the matching connections.
struct RestrictedServer {
    server: Server,
    access: Arc<TokenAccess>,
}

impl RestrictedServer {
    /// Spawns a relay server that initially admits `allowed` tokens.
    async fn spawn(allowed: impl IntoIterator<Item = &'static str>) -> Result<Self> {
        let access = TokenAccess::new(allowed);

        let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
        relay.access = access.clone();
        let mut config = ServerConfig::default();
        config.relay = Some(relay);
        let server = Server::spawn(config).await?;

        Ok(Self { server, access })
    }

    /// Returns the relay URL clients should connect to.
    fn relay_url(&self) -> RelayUrl {
        format!("http://{}", self.server.http_addr().expect("http addr"))
            .parse()
            .expect("valid relay url")
    }

    /// Allows `token`: connection attempts that present it now succeed.
    fn add_token(&self, token: &str) {
        self.access.allow(token);
    }

    /// Revokes `token` and disconnects every connection that used it.
    fn remove_token(&self, token: &str) {
        let clients = self
            .server
            .relay_service()
            .expect("relay configured")
            .clients();
        for (endpoint_id, connection_id) in self.access.revoke(token) {
            clients.disconnect(endpoint_id, Some(connection_id));
        }
    }

    /// Returns the number of currently connected connections.
    fn connection_count(&self) -> usize {
        self.access.0.lock().expect("poisoned").connections.len()
    }
}

#[tokio::test]
#[traced_test]
async fn relay_runtime_revokes_disallowed_tokens() -> Result<()> {
    let server = RestrictedServer::spawn(["token-b"]).await?;
    let relay_url = server.relay_url();

    // token-a is not allowed yet.
    assert_denied(connect(&relay_url, "token-a").await);

    // Allow token-a at runtime; three clients then connect, two on token-a.
    server.add_token("token-a");
    let mut client_a = connect(&relay_url, "token-a").await?;
    let mut client_b = connect(&relay_url, "token-b").await?;
    let mut client_c = connect(&relay_url, "token-a").await?;
    ping_round_trip(&mut client_a, [1u8; 8]).await?;
    ping_round_trip(&mut client_b, [2u8; 8]).await?;
    ping_round_trip(&mut client_c, [3u8; 8]).await?;
    assert_eq!(server.connection_count(), 3);

    // Revoke token-a: both connections that used it are disconnected.
    server.remove_token("token-a");
    assert_disconnected(&mut client_a).await;
    assert_disconnected(&mut client_c).await;

    // The token-b client keeps working, and `on_disconnect` prunes the index
    // down to that single remaining connection.
    ping_round_trip(&mut client_b, [4u8; 8]).await?;
    wait_for(Duration::from_secs(5), || server.connection_count() == 1).await;

    // New connections honor the updated allow-list.
    assert_denied(connect(&relay_url, "token-a").await);
    let mut client_d = connect(&relay_url, "token-b").await?;
    ping_round_trip(&mut client_d, [5u8; 8]).await?;
    wait_for(Duration::from_secs(5), || server.connection_count() == 2).await;

    // Dropping a client also prunes the index, via `on_disconnect`.
    drop(client_d);
    wait_for(Duration::from_secs(5), || server.connection_count() == 1).await;

    Ok(())
}

/// Connects a fresh relay client authenticating with `token`.
async fn connect(relay_url: &RelayUrl, token: &str) -> Result<Client, ConnectError> {
    let tls = CaRootsConfig::default()
        .client_config(default_provider())
        .expect("valid client config");
    let secret = SecretKey::from_bytes(&rand::rng().random());
    ClientBuilder::new(relay_url.clone(), secret, DnsResolver::new())
        .tls_client_config(tls)
        .auth_token(token)
        .connect()
        .await
}

/// Sends a relay-level ping and asserts the matching pong comes back.
async fn ping_round_trip(client: &mut Client, data: [u8; 8]) -> Result<()> {
    client.send(ClientToRelayMsg::Ping(data)).await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let msg = client.next().await.context("stream ended")??;
            match msg {
                RelayToClientMsg::Ping(payload) => {
                    client.send(ClientToRelayMsg::Pong(payload)).await?;
                }
                RelayToClientMsg::Pong(echo) => {
                    n0_error::ensure_any!(echo == data, "pong mismatch");
                    break;
                }
                other => n0_error::bail_any!("expected pong, got {other:?}"),
            }
        }
        n0_error::Ok(())
    })
    .await
    .std_context("ping roundtrip timeout")?
}

/// Asserts that `client`'s stream closes within a few seconds.
async fn assert_disconnected(client: &mut Client) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(msg) = client.next().await {
            let _ = msg.expect("expected message, got error");
        }
    })
    .await
    .expect("timeout while waiting for disconnect");
}

/// Asserts that a connection attempt was rejected by the access hook.
fn assert_denied(result: Result<Client, ConnectError>) {
    let result = result.map(|_| ());
    assert!(
        matches!(
            result,
            Err(ConnectError::Handshake { source: handshake::Error::ServerDeniedAuth { ref reason, .. }, .. })
                if reason == "not authorized"
        ),
        "expected handshake denial, got {result:?}",
    );
}

/// Polls `cond` until it is true or the timeout elapses.
async fn wait_for(timeout: Duration, cond: impl Fn() -> bool) {
    tokio::time::timeout(timeout, async {
        while !cond() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("condition not met within timeout");
}
