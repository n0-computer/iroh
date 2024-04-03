//! Internal utilities to support testing.

use anyhow::Result;
use tokio::sync::oneshot;
use tracing::{error_span, info_span, Instrument};

use crate::key::SecretKey;
use crate::relay::{RelayMap, RelayNode, RelayUrl};

/// A drop guard to clean up test infrastructure.
///
/// After dropping the test infrastructure will asynchronously shutdown and release its
/// resources.
// Nightly sees the sender as dead code currently, but we only rely on Drop of the
// sender.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct CleanupDropGuard(pub(crate) oneshot::Sender<()>);

/// Runs a relay server with STUN enabled suitable for tests.
///
/// The returned `Url` is the url of the relay server in the returned [`RelayMap`], it
/// is always `Some` as that is how the [`MagicEndpoint::connect`] API expects it.
///
/// [`MagicEndpoint::connect`]: crate::magic_endpoint::MagicEndpoint
pub(crate) async fn run_relay_server() -> Result<(RelayMap, RelayUrl, CleanupDropGuard)> {
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

pub mod dns_server {
    use std::net::{Ipv4Addr, SocketAddr};

    use anyhow::{ensure, Result};
    use futures::{future::BoxFuture, Future};
    use hickory_proto::{
        op::{header::MessageType, Message},
        serialize::binary::BinDecodable,
    };
    use hickory_resolver::{config::NameServerConfig, TokioAsyncResolver};
    use tokio::{net::UdpSocket, task::JoinHandle};
    use tokio_util::sync::CancellationToken;
    use tracing::{debug, warn};

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
        cancel: CancellationToken,
    ) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
        let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let socket = UdpSocket::bind(bind_addr).await?;
        let bound_addr = socket.local_addr()?;
        let s = TestDnsServer {
            socket,
            cancel,
            resolver,
        };
        let join_handle = tokio::task::spawn(async move { s.run().await });
        Ok((bound_addr, join_handle))
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
        cancel: CancellationToken,
    }

    impl<R: QueryHandler> TestDnsServer<R> {
        async fn run(self) -> Result<()> {
            let mut buf = [0; 1450];
            loop {
                tokio::select! {
                    _  = self.cancel.cancelled() => break,
                    res = self.socket.recv_from(&mut buf) => {
                        let (len, from) = res?;
                        if let Err(err) = self.handle_datagram(from, &buf[..len]).await {
                            warn!(?err, %from, "failed to handle incoming datagram");
                        }
                    }
                };
            }
            Ok(())
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
