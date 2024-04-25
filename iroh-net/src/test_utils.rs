//! Internal utilities to support testing.

use anyhow::Result;
use tokio::sync::oneshot;
use tracing::{error_span, info_span, Instrument};

use crate::{
    key::SecretKey,
    relay::{RelayMap, RelayNode, RelayUrl},
};

/// A drop guard to clean up test infrastructure.
///
/// After dropping the test infrastructure will asynchronously shutdown and release its
/// resources.
// Nightly sees the sender as dead code currently, but we only rely on Drop of the
// sender.
#[derive(Debug)]
#[allow(dead_code)]
pub struct CleanupDropGuard(pub(crate) oneshot::Sender<()>);

/// Runs a relay server with STUN enabled suitable for tests.
///
/// The returned `Url` is the url of the relay server in the returned [`RelayMap`], it
/// is always `Some` as that is how the [`MagicEndpoint::connect`] API expects it.
///
/// [`MagicEndpoint::connect`]: crate::magic_endpoint::MagicEndpoint
pub async fn run_relay_server() -> Result<(RelayMap, RelayUrl, CleanupDropGuard)> {
    let server_key = SecretKey::generate();
    let me = server_key.public().fmt_short();
    let tls_config = crate::relay::http::make_tls_config();
    let server = crate::relay::http::ServerBuilder::new("127.0.0.1:0".parse().unwrap())
        .secret_key(Some(server_key))
        .tls_config(Some(tls_config))
        .spawn()
        .instrument(error_span!("relay server", %me))
        .await?;

    let https_addr = server.addr();
    println!("relay listening on {:?}", https_addr);

    let (stun_addr, _, stun_drop_guard) = crate::stun::test::serve(server.addr().ip()).await?;
    let url: RelayUrl = format!("https://localhost:{}", https_addr.port())
        .parse()
        .unwrap();
    let m = RelayMap::from_nodes([RelayNode {
        url: url.clone(),
        stun_only: false,
        stun_port: stun_addr.port(),
    }])
    .expect("hardcoded");

    let (tx, rx) = oneshot::channel();
    tokio::spawn(
        async move {
            let _stun_cleanup = stun_drop_guard; // move into this closure

            // Wait until we're dropped or receive a message.
            rx.await.ok();
            server.shutdown().await;
        }
        .instrument(info_span!("relay-stun-cleanup")),
    );

    Ok((m, url, CleanupDropGuard(tx)))
}

#[cfg(test)]
pub(crate) mod dns_and_pkarr_servers {
    use anyhow::Result;
    use std::net::SocketAddr;
    use url::Url;

    use super::CleanupDropGuard;

    use crate::test_utils::{
        dns_server::run_dns_server, pkarr_dns_state::State, pkarr_relay::run_pkarr_relay,
    };

    pub async fn run_dns_and_pkarr_servers(
        origin: impl ToString,
    ) -> Result<(SocketAddr, Url, State, CleanupDropGuard, CleanupDropGuard)> {
        let state = State::new(origin.to_string());
        let (nameserver, dns_drop_guard) = run_dns_server(state.clone()).await?;
        let (pkarr_url, pkarr_drop_guard) = run_pkarr_relay(state.clone()).await?;
        Ok((
            nameserver,
            pkarr_url,
            state,
            dns_drop_guard,
            pkarr_drop_guard,
        ))
    }
}

#[cfg(test)]
pub(crate) mod dns_server {
    use std::net::{Ipv4Addr, SocketAddr};

    use anyhow::{ensure, Result};
    use futures::{future::BoxFuture, Future};
    use hickory_proto::{
        op::{header::MessageType, Message},
        serialize::binary::BinDecodable,
    };
    use hickory_resolver::{config::NameServerConfig, TokioAsyncResolver};
    use tokio::{net::UdpSocket, sync::oneshot};
    use tracing::{debug, error, warn};

    use super::CleanupDropGuard;

    /// Trait used by [`run_dns_server`] for answering DNS queries.
    pub trait QueryHandler: Send + Sync + 'static {
        fn resolve(
            &self,
            query: &Message,
            reply: &mut Message,
        ) -> impl Future<Output = Result<()>> + Send;
    }

    pub type QueryHandlerFunction = Box<
        dyn Fn(&Message, &mut Message) -> BoxFuture<'static, Result<()>> + Send + Sync + 'static,
    >;
    impl QueryHandler for QueryHandlerFunction {
        fn resolve(
            &self,
            query: &Message,
            reply: &mut Message,
        ) -> impl Future<Output = Result<()>> + Send {
            (self)(query, reply)
        }
    }

    /// Run a DNS server.
    ///
    /// Must pass a [`QueryHandler`] that answers queries. Can be a [`ResolveCallback`] or a struct.
    pub async fn run_dns_server(
        resolver: impl QueryHandler,
    ) -> Result<(SocketAddr, CleanupDropGuard)> {
        let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let socket = UdpSocket::bind(bind_addr).await?;
        let bound_addr = socket.local_addr()?;
        let s = TestDnsServer { socket, resolver };
        let (tx, mut rx) = oneshot::channel();
        tokio::task::spawn(async move {
            tokio::select! {
                _ = &mut rx => {
                    debug!("shutting down dns server");
                }
                res = s.run() => {
                    if let Err(e) = res {
                        error!("error running dns server {e:?}");
                    }
                }
            }
        });
        Ok((bound_addr, CleanupDropGuard(tx)))
    }

    /// Create a DNS resolver with a single nameserver.
    pub fn create_dns_resolver(nameserver: SocketAddr) -> Result<TokioAsyncResolver> {
        let mut config = hickory_resolver::config::ResolverConfig::new();
        let nameserver_config =
            NameServerConfig::new(nameserver, hickory_resolver::config::Protocol::Udp);
        config.add_name_server(nameserver_config);
        let resolver = hickory_resolver::AsyncResolver::tokio(config, Default::default());
        Ok(resolver)
    }

    struct TestDnsServer<R> {
        resolver: R,
        socket: UdpSocket,
    }

    impl<R: QueryHandler> TestDnsServer<R> {
        async fn run(self) -> Result<()> {
            let mut buf = [0; 1450];
            loop {
                let res = self.socket.recv_from(&mut buf).await;
                let (len, from) = res?;
                if let Err(err) = self.handle_datagram(from, &buf[..len]).await {
                    warn!(?err, %from, "failed to handle incoming datagram");
                }
            }
        }

        async fn handle_datagram(&self, from: SocketAddr, buf: &[u8]) -> Result<()> {
            let packet = Message::from_bytes(buf)?;
            debug!(queries = ?packet.queries(), %from, "received query");
            let mut reply = packet.clone();
            reply.set_message_type(MessageType::Response);
            self.resolver.resolve(&packet, &mut reply).await?;
            debug!(?reply, %from, "send reply");
            let buf = reply.to_vec()?;
            let len = self.socket.send_to(&buf, from).await?;
            ensure!(len == buf.len(), "failed to send complete packet");
            Ok(())
        }
    }
}

#[cfg(test)]
pub(crate) mod pkarr_relay {
    use std::future::IntoFuture;
    use std::net::{Ipv4Addr, SocketAddr};

    use anyhow::Result;
    use axum::{
        extract::{Path, State},
        response::IntoResponse,
        routing::put,
        Router,
    };
    use bytes::Bytes;
    use tokio::sync::oneshot;
    use tracing::{debug, error, warn};
    use url::Url;

    use crate::test_utils::pkarr_dns_state::State as AppState;

    use super::CleanupDropGuard;

    pub async fn run_pkarr_relay(state: AppState) -> Result<(Url, CleanupDropGuard)> {
        let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let app = Router::new()
            .route("/pkarr/:key", put(pkarr_put))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        let bound_addr = listener.local_addr()?;
        let url: Url = format!("http://{bound_addr}/pkarr")
            .parse()
            .expect("valid url");

        let (tx, mut rx) = oneshot::channel();
        tokio::spawn(async move {
            let serve = axum::serve(listener, app);
            tokio::select! {
                _ = &mut rx => {
                    debug!("shutting down pkarr server");
                }
                res = serve.into_future() => {
                    if let Err(e) = res {
                        error!("pkarr server error: {e:?}");
                    }
                }
            }
        });
        Ok((url, CleanupDropGuard(tx)))
    }

    async fn pkarr_put(
        State(state): State<AppState>,
        Path(key): Path<String>,
        body: Bytes,
    ) -> Result<impl IntoResponse, AppError> {
        let key = pkarr::PublicKey::try_from(key.as_str())?;
        let signed_packet = pkarr::SignedPacket::from_relay_response(key, body)?;
        let _updated = state.upsert(signed_packet)?;
        Ok(http::StatusCode::NO_CONTENT)
    }

    #[derive(Debug)]
    struct AppError(anyhow::Error);
    impl<T: Into<anyhow::Error>> From<T> for AppError {
        fn from(value: T) -> Self {
            Self(value.into())
        }
    }
    impl IntoResponse for AppError {
        fn into_response(self) -> axum::response::Response {
            warn!(err = ?self, "request failed");
            (http::StatusCode::INTERNAL_SERVER_ERROR, self.0.to_string()).into_response()
        }
    }
}

#[cfg(test)]
pub(crate) mod pkarr_dns_state {
    use anyhow::{bail, Result};
    use parking_lot::{Mutex, MutexGuard};
    use pkarr::SignedPacket;
    use std::{
        collections::{hash_map, HashMap},
        future::Future,
        ops::Deref,
        sync::Arc,
        time::Duration,
    };

    use crate::dns::node_info::{node_id_from_hickory_name, NodeInfo};
    use crate::test_utils::dns_server::QueryHandler;
    use crate::NodeId;

    #[derive(Debug, Clone)]
    pub struct State {
        packets: Arc<Mutex<HashMap<NodeId, SignedPacket>>>,
        origin: String,
        notify: Arc<tokio::sync::Notify>,
    }

    impl State {
        pub fn new(origin: String) -> Self {
            Self {
                packets: Default::default(),
                origin,
                notify: Arc::new(tokio::sync::Notify::new()),
            }
        }

        pub fn on_update(&self) -> tokio::sync::futures::Notified<'_> {
            self.notify.notified()
        }

        pub async fn on_node(&self, node: &NodeId, timeout: Duration) -> Result<()> {
            let timeout = tokio::time::sleep(timeout);
            tokio::pin!(timeout);
            while self.get(node).is_none() {
                tokio::select! {
                    _ = &mut timeout => bail!("timeout"),
                    _ = self.on_update() => {}
                }
            }
            Ok(())
        }

        pub fn upsert(&self, signed_packet: SignedPacket) -> anyhow::Result<bool> {
            let node_id = NodeId::from_bytes(&signed_packet.public_key().to_bytes())?;
            let mut map = self.packets.lock();
            let updated = match map.entry(node_id) {
                hash_map::Entry::Vacant(e) => {
                    e.insert(signed_packet);
                    true
                }
                hash_map::Entry::Occupied(mut e) => {
                    if signed_packet.more_recent_than(e.get()) {
                        e.insert(signed_packet);
                        true
                    } else {
                        false
                    }
                }
            };
            if updated {
                self.notify.notify_waiters();
            }
            Ok(updated)
        }

        /// Returns a mutex guard, do not hold over await points
        pub fn get(&self, node_id: &NodeId) -> Option<impl Deref<Target = SignedPacket> + '_> {
            let map = self.packets.lock();
            if map.contains_key(node_id) {
                let guard = MutexGuard::map(map, |state| state.get_mut(node_id).unwrap());
                Some(guard)
            } else {
                None
            }
        }

        pub fn resolve_dns(
            &self,
            query: &hickory_proto::op::Message,
            reply: &mut hickory_proto::op::Message,
            ttl: u32,
        ) -> Result<()> {
            for query in query.queries() {
                let Some(node_id) = node_id_from_hickory_name(query.name()) else {
                    continue;
                };
                let packet = self.get(&node_id);
                let Some(packet) = packet.as_ref() else {
                    continue;
                };
                let node_info = NodeInfo::from_pkarr_signed_packet(packet)?;
                for record in node_info.to_hickory_records(&self.origin, ttl)? {
                    reply.add_answer(record);
                }
            }
            Ok(())
        }
    }

    impl QueryHandler for State {
        fn resolve(
            &self,
            query: &hickory_proto::op::Message,
            reply: &mut hickory_proto::op::Message,
        ) -> impl Future<Output = Result<()>> + Send {
            const TTL: u32 = 30;
            let res = self.resolve_dns(query, reply, TTL);
            futures::future::ready(res)
        }
    }
}
