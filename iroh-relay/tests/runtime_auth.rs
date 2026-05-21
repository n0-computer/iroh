//! Runtime revocation of relay access via the [`AccessControl`] trait.
//!
//! These tests drive a [`RestrictedServer`]: a relay [`Server`] fronted by a
//! runtime-mutable token allow-list. Its [`AccessControl`] implementation
//! records the auth token of every admitted connection through
//! `on_connect`/`on_disconnect`, so revoking a token yields the connections to
//! evict through [`Clients::disconnect`].
//!
//! [`AccessControl`]: iroh_relay::server::AccessControl
//! [`Clients::disconnect`]: iroh_relay::server::clients::Clients::disconnect

#![cfg(feature = "server")]

use std::{
    collections::HashMap,
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
    next_token_id: u64,
    /// Auth tokens currently permitted to connect.
    tokens: HashMap<String, u64>,
    /// Auth token recorded for each connected connection.
    ///
    /// Built from `on_connect`/`on_disconnect`.
    connections: HashMap<(EndpointId, ConnectionId), u64>,
}

/// An [`AccessControl`] with a runtime-mutable token allow-list.
///
/// Admits a connection if its auth token is currently allowed, and records the
/// token each admitted connection used, so a revoked token maps back to the
/// connections that must be evicted. `on_disconnect` prunes the index.
#[derive(Debug, Default)]
struct TokenAccess(Mutex<AccessState>);

impl TokenAccess {
    fn new(allowed: impl IntoIterator<Item = &'static str>) -> Arc<Self> {
        let this = TokenAccess::default();
        for token in allowed {
            this.allow(token);
        }
        Arc::new(this)
    }

    /// Adds `token` to the allow-list.
    fn allow(&self, token: &str) {
        let mut state = self.0.lock().expect("poisoned");
        if !state.tokens.contains_key(token) {
            let id = state.next_token_id;
            state.next_token_id += 1;
            state.tokens.insert(token.to_string(), id);
        }
    }

    /// Removes `token` from the allow-list and returns its indexed connections.
    fn revoke(&self, revoked_token: &str) -> Vec<(EndpointId, ConnectionId)> {
        let mut state = self.0.lock().expect("poisoned");
        let mut removed = vec![];
        if let Some(revoked_id) = state.tokens.remove(revoked_token) {
            state.connections.retain(|conn_id, token_id| {
                if *token_id == revoked_id {
                    removed.push(*conn_id);
                    false
                } else {
                    true
                }
            });
        }
        removed
    }
}

impl AccessControl for TokenAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let mut state = self.0.lock().expect("poisoned");
        match request.auth_token() {
            Some(token) if let Some(token_id) = state.tokens.get(token).copied() => {
                let conn_id = (request.endpoint_id(), request.connection_id());
                state.connections.insert(conn_id, token_id);
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

/// A token that is not on the allow-list is rejected during the handshake.
#[tokio::test]
#[traced_test]
async fn unknown_token_is_denied() -> Result<()> {
    let server = RestrictedServer::spawn(["token-a"]).await?;
    assert_denied(connect(&server.relay_url(), "token-b").await);
    Ok(())
}

/// A token added to the allow-list at runtime admits new connections.
#[tokio::test]
#[traced_test]
async fn token_added_at_runtime_is_admitted() -> Result<()> {
    let server = RestrictedServer::spawn(["token-b"]).await?;
    let url = server.relay_url();

    // token-a is not on the initial allow-list.
    assert_denied(connect(&url, "token-a").await);

    // Adding it at runtime lets a new connection through.
    server.add_token("token-a");
    let mut client = connect(&url, "token-a").await?;
    ping_round_trip(&mut client, [1u8; 8]).await?;

    Ok(())
}

/// Revoking a token disconnects its connection and leaves others untouched.
#[tokio::test]
#[traced_test]
async fn revoked_token_disconnects_its_connection() -> Result<()> {
    let server = RestrictedServer::spawn(["token-a", "token-b"]).await?;
    let url = server.relay_url();

    let mut revoked = connect(&url, "token-a").await?;
    let mut kept = connect(&url, "token-b").await?;
    ping_round_trip(&mut revoked, [1u8; 8]).await?;
    ping_round_trip(&mut kept, [2u8; 8]).await?;

    // Revoking token-a evicts its connection; the token-b connection survives.
    server.remove_token("token-a");
    assert_disconnected(&mut revoked).await;
    ping_round_trip(&mut kept, [3u8; 8]).await?;

    Ok(())
}

/// Revoking a token disconnects every connection of a shared endpoint.
#[tokio::test]
#[traced_test]
async fn revoked_token_disconnects_every_endpoint_connection() -> Result<()> {
    let server = RestrictedServer::spawn(["token-a", "token-b"]).await?;
    let url = server.relay_url();

    // One endpoint opens two connections, both authenticating with token-a.
    let shared = SecretKey::from_bytes(&rand::rng().random());
    let mut conn1 = connect_as(&url, &shared, "token-a").await?;
    ping_round_trip(&mut conn1, [1u8; 8]).await?;
    let mut conn2 = connect_as(&url, &shared, "token-a").await?;
    ping_round_trip(&mut conn2, [2u8; 8]).await?;

    // A second endpoint connects with token-b.
    let mut other = connect_as(&url, &shared, "token-b").await?;
    ping_round_trip(&mut other, [3u8; 8]).await?;
    assert_eq!(server.connection_count(), 3);

    // Revoking token-a disconnects both connections of the shared endpoint,
    // told apart by their distinct connection ids.
    server.remove_token("token-a");
    assert_disconnected(&mut conn1).await;
    assert_disconnected(&mut conn2).await;

    // The token-b endpoint keeps working, and the index is pruned to it alone.
    ping_round_trip(&mut other, [4u8; 8]).await?;
    wait_for(Duration::from_secs(5), || server.connection_count() == 1).await;

    Ok(())
}

/// Once revoked, a token can no longer be used to connect.
#[tokio::test]
#[traced_test]
async fn revoked_token_cannot_reconnect() -> Result<()> {
    let server = RestrictedServer::spawn(["token-a"]).await?;
    let url = server.relay_url();

    // The token works before it is revoked.
    let mut client = connect(&url, "token-a").await?;
    ping_round_trip(&mut client, [1u8; 8]).await?;

    // After revocation it no longer admits connections.
    server.remove_token("token-a");
    assert_denied(connect(&url, "token-a").await);

    Ok(())
}

/// A connection that closes on its own is pruned from the access index.
#[tokio::test]
#[traced_test]
async fn disconnected_connections_are_pruned() -> Result<()> {
    let server = RestrictedServer::spawn(["token-a"]).await?;
    let url = server.relay_url();

    let mut client = connect(&url, "token-a").await?;
    ping_round_trip(&mut client, [1u8; 8]).await?;
    assert_eq!(server.connection_count(), 1);

    // Dropping the client closes the connection; `on_disconnect` then prunes
    // the index, so a long-lived server does not accumulate stale entries.
    drop(client);
    wait_for(Duration::from_secs(5), || server.connection_count() == 0).await;

    Ok(())
}

/// Connects a relay client for a fresh random endpoint, authenticating with `token`.
async fn connect(relay_url: &RelayUrl, token: &str) -> Result<Client, ConnectError> {
    let secret = SecretKey::from_bytes(&rand::rng().random());
    connect_as(relay_url, &secret, token).await
}

/// Connects a relay client for `secret`'s endpoint, authenticating with `token`.
async fn connect_as(
    relay_url: &RelayUrl,
    secret: &SecretKey,
    token: &str,
) -> Result<Client, ConnectError> {
    let tls = CaRootsConfig::default()
        .client_config(default_provider())
        .expect("valid client config");
    ClientBuilder::new(relay_url.clone(), secret.clone(), DnsResolver::new())
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
