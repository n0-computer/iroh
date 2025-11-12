//! Internal utilities to support testing.
use std::net::Ipv4Addr;

pub use dns_and_pkarr_servers::DnsPkarrServer;
use iroh_base::RelayUrl;
use iroh_relay::{
    RelayConfig, RelayMap, RelayQuicConfig,
    server::{
        AccessConfig, CertConfig, QuicConfig, RelayConfig as RelayServerConfig, Server,
        ServerConfig, SpawnError, TlsConfig,
    },
};
use tokio::sync::oneshot;

/// A drop guard to clean up test infrastructure.
///
/// After dropping the test infrastructure will asynchronously shutdown and release its
/// resources.
// Nightly sees the sender as dead code currently, but we only rely on Drop of the
// sender.
#[derive(Debug)]
#[allow(dead_code)]
pub struct CleanupDropGuard(pub(crate) oneshot::Sender<()>);

/// Runs a relay server with QUIC enabled suitable for tests.
///
/// The returned `Url` is the url of the relay server in the returned [`RelayMap`].
/// When dropped, the returned [`Server`] does will stop running.
pub async fn run_relay_server() -> Result<(RelayMap, RelayUrl, Server), SpawnError> {
    run_relay_server_with(true).await
}

/// Runs a relay server.
///
/// If `quic` is set to `true`, it will make the appropriate [`QuicConfig`] from the generated tls certificates and run the quic server at a random free port.
///
///
/// The return value is similar to [`run_relay_server`].
pub async fn run_relay_server_with(quic: bool) -> Result<(RelayMap, RelayUrl, Server), SpawnError> {
    let (certs, server_config) = iroh_relay::server::testing::self_signed_tls_certs_and_config();

    let tls = TlsConfig {
        cert: CertConfig::<(), ()>::Manual { certs },
        https_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
        quic_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
        server_config,
    };
    let quic = if quic {
        Some(QuicConfig {
            server_config: tls.server_config.clone(),
            bind_addr: tls.quic_bind_addr,
        })
    } else {
        None
    };
    let config = ServerConfig {
        relay: Some(RelayServerConfig {
            http_bind_addr: (Ipv4Addr::LOCALHOST, 0).into(),
            tls: Some(tls),
            limits: Default::default(),
            key_cache_capacity: Some(1024),
            access: AccessConfig::Everyone,
        }),
        quic,
        ..Default::default()
    };
    let server = Server::spawn(config).await?;
    let url: RelayUrl = format!("https://{}", server.https_addr().expect("configured"))
        .parse()
        .expect("invalid relay url");

    let quic = server
        .quic_addr()
        .map(|addr| RelayQuicConfig { port: addr.port() });
    let n: RelayMap = RelayConfig {
        url: url.clone(),
        quic,
    }
    .into();
    Ok((n, url, server))
}

pub(crate) mod dns_and_pkarr_servers {
    use std::{net::SocketAddr, time::Duration};

    use iroh_base::{PublicKey, SecretKey};
    use url::Url;

    use super::CleanupDropGuard;
    use crate::{
        discovery::{ConcurrentDiscovery, dns::DnsDiscovery, pkarr::PkarrPublisher},
        dns::DnsResolver,
        test_utils::{
            dns_server::run_dns_server, pkarr_dns_state::State, pkarr_relay::run_pkarr_relay,
        },
    };

    /// Handle and drop guard for test DNS and Pkarr servers.
    ///
    /// Once the struct is dropped the servers will shut down.
    #[derive(Debug)]
    pub struct DnsPkarrServer {
        /// The endpoint origin domain.
        pub endpoint_origin: String,
        /// The shared state of the DNS and Pkarr servers.
        state: State,
        /// The socket address of the DNS server.
        pub nameserver: SocketAddr,
        /// The HTTP URL of the Pkarr server.
        pub pkarr_url: Url,
        _dns_drop_guard: CleanupDropGuard,
        _pkarr_drop_guard: CleanupDropGuard,
    }

    impl DnsPkarrServer {
        /// Run DNS and Pkarr servers on localhost.
        pub async fn run() -> std::io::Result<Self> {
            Self::run_with_origin("dns.iroh.test".to_string()).await
        }

        /// Run DNS and Pkarr servers on localhost with the specified `endpoint_origin` domain.
        pub async fn run_with_origin(endpoint_origin: String) -> std::io::Result<Self> {
            let state = State::new(endpoint_origin.clone());
            let (nameserver, dns_drop_guard) = run_dns_server(state.clone()).await?;
            let (pkarr_url, pkarr_drop_guard) = run_pkarr_relay(state.clone()).await?;
            Ok(Self {
                endpoint_origin,
                nameserver,
                pkarr_url,
                state,
                _dns_drop_guard: dns_drop_guard,
                _pkarr_drop_guard: pkarr_drop_guard,
            })
        }

        /// Create a [`ConcurrentDiscovery`] with [`DnsDiscovery`] and [`PkarrPublisher`]
        /// configured to use the test servers.
        pub fn discovery(&self, secret_key: SecretKey) -> ConcurrentDiscovery {
            ConcurrentDiscovery::from_services(vec![
                // Enable DNS discovery by default
                Box::new(
                    DnsDiscovery::builder(self.endpoint_origin.clone())
                        .dns_resolver(self.dns_resolver())
                        .build(),
                ),
                // Enable pkarr publishing by default
                Box::new(PkarrPublisher::builder(self.pkarr_url.clone()).build(secret_key)),
            ])
        }

        /// Create a [`DnsResolver`] configured to use the test DNS server.
        pub fn dns_resolver(&self) -> DnsResolver {
            DnsResolver::with_nameserver(self.nameserver)
        }

        /// Wait until a Pkarr announce for an endpoint is published to the server.
        ///
        /// If `timeout` elapses an error is returned.
        pub async fn on_endpoint(
            &self,
            endpoint_id: &PublicKey,
            timeout: Duration,
        ) -> std::io::Result<()> {
            self.state.on_endpoint(endpoint_id, timeout).await
        }
    }
}

pub(crate) mod dns_server {
    use std::{
        future::Future,
        net::{Ipv4Addr, SocketAddr},
    };

    use hickory_resolver::proto::{
        op::{Message, header::MessageType},
        serialize::binary::BinDecodable,
    };
    use n0_future::future::Boxed as BoxFuture;
    use tokio::{net::UdpSocket, sync::oneshot};
    use tracing::{debug, error, warn};

    use super::CleanupDropGuard;

    /// Trait used by [`run_dns_server`] for answering DNS queries.
    pub trait QueryHandler: Send + Sync + 'static {
        fn resolve(
            &self,
            query: &Message,
            reply: &mut Message,
        ) -> impl Future<Output = std::io::Result<()>> + Send;
    }

    pub type QueryHandlerFunction = Box<
        dyn Fn(&Message, &mut Message) -> BoxFuture<std::io::Result<()>> + Send + Sync + 'static,
    >;

    impl QueryHandler for QueryHandlerFunction {
        fn resolve(
            &self,
            query: &Message,
            reply: &mut Message,
        ) -> impl Future<Output = std::io::Result<()>> + Send {
            (self)(query, reply)
        }
    }

    /// Run a DNS server.
    ///
    /// Must pass a [`QueryHandler`] that answers queries.
    pub async fn run_dns_server(
        resolver: impl QueryHandler,
    ) -> std::io::Result<(SocketAddr, CleanupDropGuard)> {
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

    struct TestDnsServer<R> {
        resolver: R,
        socket: UdpSocket,
    }

    impl<R: QueryHandler> TestDnsServer<R> {
        async fn run(self) -> std::io::Result<()> {
            let mut buf = [0; 1450];
            loop {
                let res = self.socket.recv_from(&mut buf).await;
                let (len, from) = res?;
                if let Err(err) = self.handle_datagram(from, &buf[..len]).await {
                    warn!(?err, %from, "failed to handle incoming datagram");
                }
            }
        }

        async fn handle_datagram(&self, from: SocketAddr, buf: &[u8]) -> std::io::Result<()> {
            let packet = Message::from_bytes(buf)?;
            debug!(queries = ?packet.queries(), %from, "received query");
            let mut reply = packet.clone();
            reply.set_message_type(MessageType::Response);
            self.resolver.resolve(&packet, &mut reply).await?;
            debug!(?reply, %from, "send reply");
            let buf = reply.to_vec()?;
            let len = self.socket.send_to(&buf, from).await?;
            assert_eq!(len, buf.len(), "failed to send complete packet");
            Ok(())
        }
    }
}

pub(crate) mod pkarr_relay {
    use std::{
        future::IntoFuture,
        net::{Ipv4Addr, SocketAddr},
    };

    use axum::{
        Router,
        extract::{Path, State},
        response::IntoResponse,
        routing::put,
    };
    use bytes::Bytes;
    use tokio::sync::oneshot;
    use tracing::{debug, error, warn};
    use url::Url;

    use super::CleanupDropGuard;
    use crate::test_utils::pkarr_dns_state::State as AppState;

    pub async fn run_pkarr_relay(state: AppState) -> std::io::Result<(Url, CleanupDropGuard)> {
        let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let app = Router::new()
            .route("/pkarr/{key}", put(pkarr_put))
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
        let key = pkarr::PublicKey::try_from(key.as_str()).map_err(std::io::Error::other)?;
        let signed_packet =
            pkarr::SignedPacket::from_relay_payload(&key, &body).map_err(std::io::Error::other)?;
        let _updated = state.upsert(signed_packet)?;
        Ok(http::StatusCode::NO_CONTENT)
    }

    #[derive(Debug)]
    struct AppError(std::io::Error);
    impl<T: Into<std::io::Error>> From<T> for AppError {
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

pub(crate) mod pkarr_dns_state {
    use std::{
        collections::{HashMap, hash_map},
        future::Future,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use iroh_base::PublicKey;
    use iroh_relay::endpoint_info::{EndpointIdExt, EndpointInfo, IROH_TXT_NAME};
    use pkarr::SignedPacket;
    use tracing::debug;

    use crate::test_utils::dns_server::QueryHandler;

    #[derive(Debug, Clone)]
    pub struct State {
        packets: Arc<Mutex<HashMap<PublicKey, SignedPacket>>>,
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

        pub async fn on_endpoint(
            &self,
            endpoint: &PublicKey,
            timeout: Duration,
        ) -> std::io::Result<()> {
            let timeout = tokio::time::sleep(timeout);
            tokio::pin!(timeout);
            while self.get(endpoint, |p| {
                let endpoint_info = p
                    .as_ref()
                    .and_then(|p| EndpointInfo::from_pkarr_signed_packet(p).ok());
                debug!("got info {:#?}", endpoint_info);
                p.is_none()
            }) {
                tokio::select! {
                    _ = &mut timeout => return Err(std::io::Error::other("timeout")),
                    _ = self.on_update() => {}
                }
            }
            Ok(())
        }

        pub fn upsert(&self, signed_packet: SignedPacket) -> std::io::Result<bool> {
            let endpoint_id = PublicKey::from_bytes(&signed_packet.public_key().to_bytes())
                .map_err(std::io::Error::other)?;
            let mut map = self.packets.lock().expect("poisoned");
            let updated = match map.entry(endpoint_id) {
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
        pub fn get<F, T>(&self, endpoint_id: &PublicKey, cb: F) -> T
        where
            F: FnOnce(Option<&mut SignedPacket>) -> T,
        {
            let mut map = self.packets.lock().expect("poisoned");
            let packet = map.get_mut(endpoint_id);
            cb(packet)
        }

        pub fn resolve_dns(
            &self,
            query: &hickory_resolver::proto::op::Message,
            reply: &mut hickory_resolver::proto::op::Message,
            ttl: u32,
        ) -> std::io::Result<()> {
            for query in query.queries() {
                let domain_name = query.name().to_string();
                let Some(endpoint_id) = endpoint_id_from_domain_name(&domain_name) else {
                    continue;
                };

                self.get(&endpoint_id, |packet| {
                    if let Some(packet) = packet {
                        let endpoint_info = EndpointInfo::from_pkarr_signed_packet(packet)
                            .map_err(std::io::Error::other)?;
                        for record in
                            endpoint_info_to_hickory_records(&endpoint_info, &self.origin, ttl)
                        {
                            reply.add_answer(record);
                        }
                    }
                    Ok::<_, std::io::Error>(())
                })?;
            }
            Ok(())
        }
    }

    impl QueryHandler for State {
        fn resolve(
            &self,
            query: &hickory_resolver::proto::op::Message,
            reply: &mut hickory_resolver::proto::op::Message,
        ) -> impl Future<Output = std::io::Result<()>> + Send {
            const TTL: u32 = 30;
            let res = self.resolve_dns(query, reply, TTL);
            std::future::ready(res)
        }
    }

    /// Parses a [`EndpointId`] from a DNS domain name.
    ///
    /// Splits the domain name into labels on each dot. Expects the first label to be
    /// [`IROH_TXT_NAME`] and the second label to be a z32 encoded [`EndpointId`]. Ignores
    /// subsequent labels.
    ///
    /// Returns a [`EndpointId`] if parsed successfully, otherwise `None`.
    fn endpoint_id_from_domain_name(name: &str) -> Option<PublicKey> {
        let mut labels = name.split(".");
        let label = labels.next()?;
        if label != IROH_TXT_NAME {
            return None;
        }
        let label = labels.next()?;
        let endpoint_id = PublicKey::from_z32(label).ok()?;
        Some(endpoint_id)
    }

    /// Converts a [`EndpointInfo`]into a [`hickory_resolver::proto::rr::Record`] DNS record.
    fn endpoint_info_to_hickory_records(
        endpoint_info: &EndpointInfo,
        origin: &str,
        ttl: u32,
    ) -> impl Iterator<Item = hickory_resolver::proto::rr::Record> + 'static {
        let txt_strings = endpoint_info.to_txt_strings();
        let records = to_hickory_records(txt_strings, endpoint_info.endpoint_id.expect_ed(), origin, ttl);
        records.collect::<Vec<_>>().into_iter()
    }

    /// Converts to a list of [`hickory_resolver::proto::rr::Record`] resource records.
    fn to_hickory_records(
        txt_strings: Vec<String>,
        endpoint_id: PublicKey,
        origin: &str,
        ttl: u32,
    ) -> impl Iterator<Item = hickory_resolver::proto::rr::Record> + '_ {
        use hickory_resolver::proto::rr;
        let name = format!("{IROH_TXT_NAME}.{}.{origin}", endpoint_id.to_z32());
        let name = rr::Name::from_utf8(name).expect("invalid name");
        txt_strings.into_iter().map(move |s| {
            let txt = rr::rdata::TXT::new(vec![s]);
            let rdata = rr::RData::TXT(txt);
            rr::Record::from_rdata(name.clone(), ttl, rdata)
        })
    }

    #[cfg(test)]
    mod tests {
        use iroh_base::PublicKey;
        use n0_error::Result;

        #[test]
        fn test_endpoint_id_from_domain_name() -> Result {
            let name = "_iroh.dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy.dns.iroh.link.";
            let endpoint_id = super::endpoint_id_from_domain_name(name);
            let expected: PublicKey =
                "1992d53c02cdc04566e5c0edb1ce83305cd550297953a047a445ea3264b54b18".parse()?;
            assert_eq!(endpoint_id, Some(expected));
            Ok(())
        }
    }
}
