//! Runtime revocation of relay auth tokens.
//!
//! Exercises updating the set of allowed auth tokens at runtime and
//! disconnecting the now-unauthorized clients through the top-level
//! [`Server`] public API.

#![cfg(feature = "server")]

use std::{
    collections::HashSet,
    net::Ipv4Addr,
    sync::{Arc, RwLock},
    time::Duration,
};

use iroh_base::{RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    client::{Client, ClientBuilder, ConnectError},
    protos::{
        handshake,
        relay::{ClientToRelayMsg, RelayToClientMsg},
    },
    server::{Access, AccessConfig, RelayConfig, Server, ServerConfig},
    tls::{CaRootsConfig, default_provider},
};
use n0_error::{Result, StackResultExt, StdResultExt};
use n0_future::{FutureExt, SinkExt, StreamExt};
use n0_tracing_test::traced_test;
use rand::RngExt;

#[tokio::test]
#[traced_test]
async fn relay_runtime_revokes_disallowed_tokens() -> Result<()> {
    let relay = RestrictedServer::spawn(["token-b"]).await?;

    let relay_url: RelayUrl = format!("http://{}", relay.server.http_addr().expect("http addr"))
        .parse()
        .expect("valid relay url");

    assert_denied(connect(&relay_url, "token-a").await);
    // token-a is added at runtime; both clients then connect successfully.
    relay.add_token("token-a");
    let mut client_a = connect(&relay_url, "token-a").await?;
    let mut client_b = connect(&relay_url, "token-b").await?;
    ping_round_trip(&mut client_a, [1u8; 8]).await?;
    ping_round_trip(&mut client_b, [2u8; 8]).await?;

    // Revoking token-a evicts client A; client B keeps working.
    relay.remove_token("token-a");
    assert_disconnected(&mut client_a).await;
    ping_round_trip(&mut client_b, [3u8; 8]).await?;

    // New connections honor the updated allow-list.
    assert_denied(connect(&relay_url, "token-a").await);
    let mut client_c = connect(&relay_url, "token-b").await?;
    ping_round_trip(&mut client_c, [4u8; 8]).await?;

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

/// A relay [`Server`] paired with its runtime-mutable auth-token allow-list.
///
/// The allow-list is shared with the server's access hook, so mutations take
/// effect immediately for new connections. [`RestrictedServer::remove_token`]
/// additionally evicts clients that connected with a token that is no longer
/// allowed.
struct RestrictedServer {
    server: Server,
    allowed_tokens: Arc<RwLock<HashSet<String>>>,
}

impl RestrictedServer {
    /// Spawns a plain-HTTP relay that admits only the given auth `tokens`.
    async fn spawn(tokens: impl IntoIterator<Item = &'static str>) -> Result<Self> {
        let allowed_tokens: Arc<RwLock<HashSet<String>>> =
            Arc::new(RwLock::new(tokens.into_iter().map(String::from).collect()));

        let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
        relay.access = {
            let allowed_tokens = allowed_tokens.clone();
            AccessConfig::Restricted(Box::new(move |request| {
                let allowed_tokens = allowed_tokens.clone();
                async move {
                    let allowed_tokens = allowed_tokens.read().expect("poisoned");
                    match request.auth_token() {
                        Some(token) if allowed_tokens.contains(&token) => Access::Allow,
                        _ => Access::Deny,
                    }
                }
                .boxed()
            }))
        };
        let mut config = ServerConfig::default();
        config.relay = Some(relay);
        let server = Server::spawn(config).await?;

        Ok(Self {
            server,
            allowed_tokens,
        })
    }

    /// Adds `token` to the allow-list.
    fn add_token(&self, token: &str) {
        self.allowed_tokens
            .write()
            .expect("poisoned")
            .insert(token.to_string());
    }

    /// Removes `token` from the allow-list and disconnects every connected
    /// client whose auth token is no longer allowed.
    fn remove_token(&self, token: &str) {
        let allowed = {
            let mut allowed = self.allowed_tokens.write().expect("poisoned");
            allowed.remove(token);
            allowed.clone()
        };
        self.server
            .relay_service()
            .expect("relay configured")
            .clients()
            .retain(|client| client.auth_token().is_some_and(|t| allowed.contains(t)));
    }
}

/// Sends a relay-level ping and asserts the matching pong comes back.
async fn ping_round_trip(client: &mut Client, data: [u8; 8]) -> Result<()> {
    client.send(ClientToRelayMsg::Ping(data)).await?;
    let msg = tokio::time::timeout(Duration::from_secs(2), client.next())
        .await
        .std_context("ping timeout")?
        .context("stream ended")??;
    match msg {
        RelayToClientMsg::Pong(echo) => {
            n0_error::ensure_any!(echo == data, "Pong mismatch");
            Ok(())
        }
        other => n0_error::bail_any!("expected Pong, got {other:?}"),
    }
}

/// Asserts that `client`'s stream closes within a few seconds.
async fn assert_disconnected(client: &mut Client) {
    match tokio::time::timeout(Duration::from_secs(2), client.next()).await {
        Ok(None) => {}
        Ok(Some(Err(e))) => panic!("expected stream close, got Err({e:?})"),
        Ok(Some(Ok(msg))) => panic!("expected stream close, got {msg:?}"),
        Err(_) => panic!("timeout waiting for disconnect"),
    }
}

/// Asserts that a connection attempt was rejected by the access hook.
fn assert_denied(result: Result<Client, ConnectError>) {
    assert!(
        matches!(
            result,
            Err(ConnectError::Handshake { source: handshake::Error::ServerDeniedAuth { ref reason, .. }, .. })
                if reason == "not authorized"
        ),
        "expected handshake denial, got {result:?}",
    );
}
