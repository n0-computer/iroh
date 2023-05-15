use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{bail, ensure, Result};
use futures::future::FutureExt;
use futures::Future;
use hyper::header::{HeaderValue, UPGRADE};
use hyper::upgrade::Upgraded;
use hyper::{Body, Request, Response, StatusCode};

use tracing::debug;

use super::HTTP_UPGRADE_PROTOCOL;
use crate::hp::derp::{server::ClientConnHandler, types::PacketForwarder};

/// The server HTTP handler to do HTTP upgrades
pub async fn derp_connection_handler<P>(
    conn_handler: &ClientConnHandler<P>,
    upgraded: Upgraded,
) -> Result<()>
where
    P: PacketForwarder,
{
    debug!("derp_connection upgraded");

    // get the underlying TcpStream
    match upgraded.downcast::<tokio::net::TcpStream>() {
        Ok(parts) => {
            ensure!(
                parts.read_buf.is_empty(),
                "can not deal with buffered data yet: {:?}",
                parts.read_buf
            );

            // send to the derp server
            conn_handler.accept(Box::new(parts.io)).await
        }
        Err(upgraded) => {
            if let Ok(parts) =
                upgraded.downcast::<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>()
            {
                ensure!(
                    parts.read_buf.is_empty(),
                    "can not deal with buffered data yet: {:?}",
                    parts.read_buf
                );

                // send to the derp server
                return conn_handler.accept(Box::new(parts.io)).await;
            }

            bail!(
                "could not downcast the upgraded connection to a TcpStream or TlsStream<TcpStream>"
            )
        }
    }
}

impl<P> hyper::service::Service<Request<Body>> for ClientConnHandler<P>
where
    P: PacketForwarder,
{
    type Response = Response<Body>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        // TODO: soooo much cloning. See if there is an alternative
        let closure_conn_handler = self.clone();
        let mut builder = Response::builder();
        for (key, value) in self.default_headers.iter() {
            builder = builder.header(key, value);
        }

        async move {
            {
                let mut res = builder.body(Body::empty()).unwrap();

                // Send a 400 to any request that doesn't have an `Upgrade` header.
                if !req.headers().contains_key(UPGRADE) {
                    *res.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(res);
                }

                // Setup a future that will eventually receive the upgraded
                // connection and talk a new protocol, and spawn the future
                // into the runtime.
                //
                // Note: This can't possibly be fulfilled until the 101 response
                // is returned below, so it's better to spawn this future instead
                // waiting for it to complete to then return a response.
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(&mut req).await {
                        Ok(upgraded) => {
                            if let Err(e) =
                                derp_connection_handler(&closure_conn_handler, upgraded).await
                            {
                                tracing::warn!(
                                    "server \"{HTTP_UPGRADE_PROTOCOL}\" io error: {:?}",
                                    e
                                )
                            };
                        }
                        Err(e) => tracing::warn!("upgrade error: {:?}", e),
                    }
                });

                // Now return a 101 Response saying we agree to the upgrade to the
                // HTTP_UPGRADE_PROTOCOL
                *res.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                res.headers_mut()
                    .insert(UPGRADE, HeaderValue::from_static(HTTP_UPGRADE_PROTOCOL));
                Ok(res)
            }
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    use hyper::header::UPGRADE;
    use hyper::server::conn::Http;
    use hyper::upgrade::Upgraded;
    use hyper::{Body, Request, StatusCode};
    use tokio::sync::oneshot;

    use crate::hp::derp::server::Server as DerpServer;
    use crate::hp::key::node::{PublicKey, SecretKey};

    /// Handle client-side I/O after HTTP upgraded.
    async fn derp_client(mut upgraded: Upgraded) -> Result<()> {
        println!("in derp_client handshake");
        let secret_key = SecretKey::generate();
        let got_server_key = crate::hp::derp::client::recv_server_key(&mut upgraded).await?;
        let client_info = crate::hp::derp::types::ClientInfo {
            version: crate::hp::derp::PROTOCOL_VERSION,
            mesh_key: None,
            can_ack_pings: true,
            is_prober: true,
        };
        crate::hp::derp::send_client_key(&mut upgraded, &secret_key, &got_server_key, &client_info)
            .await?;
        let mut buf = bytes::BytesMut::new();
        let (frame_type, _) =
            crate::hp::derp::read_frame(&mut upgraded, crate::hp::derp::MAX_FRAME_SIZE, &mut buf)
                .await?;
        assert_eq!(crate::hp::derp::FrameType::ServerInfo, frame_type);
        let msg = secret_key.open_from(&got_server_key, &buf)?;
        let _info: crate::hp::derp::types::ServerInfo = postcard::from_bytes(&msg)?;
        Ok(())
    }

    /// Our client HTTP handler to initiate HTTP upgrades.
    async fn client_upgrade_request(addr: SocketAddr) -> Result<()> {
        let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        let (mut request_sender, connection) =
            hyper::client::conn::handshake(tcp_stream).await.unwrap();

        let task = tokio::spawn(async move {
            let _ = connection.without_shutdown().await;
        });

        let req = Request::builder()
            .header(UPGRADE, super::HTTP_UPGRADE_PROTOCOL)
            .body(Body::empty())
            .unwrap();

        let res = request_sender.send_request(req).await.unwrap();

        if res.status() != StatusCode::SWITCHING_PROTOCOLS {
            panic!("Our server didn't upgrade: {}", res.status());
        }

        match hyper::upgrade::on(res).await {
            Ok(upgraded) => {
                if let Err(e) = derp_client(upgraded).await {
                    eprintln!("client foobar io error: {}", e)
                };
            }
            Err(e) => eprintln!("upgrade error: {}", e),
        }
        task.abort();
        Ok(())
    }

    struct MockPacketForwarder {}

    impl PacketForwarder for MockPacketForwarder {
        fn forward_packet(&mut self, srckey: PublicKey, dstkey: PublicKey, packet: bytes::Bytes) {
            println!("forwarded packet from {srckey:?} to {dstkey:?}: msg: {packet:?}");
        }
    }

    #[tokio::test]
    async fn test_connection_handler() -> Result<()> {
        // inspired by https://github.com/hyperium/hyper/blob/v0.14.25/examples/upgrades.rs

        let addr = "127.0.0.1:0";

        // create derp_server
        let server_key = SecretKey::generate();
        let derp_server: DerpServer<MockPacketForwarder> = DerpServer::new(server_key, None);

        // create handler that sends new connections to the client
        let derp_client_handler = derp_server.client_conn_handler(Default::default());

        let listener = TcpListener::bind(&addr).await?;
        // We need the assigned address for the client to send it messages.
        let addr = listener.local_addr()?;

        // For this example, a oneshot is used to signal that after 1 request,
        // the server should be shutdown.
        let (tx, mut rx) = oneshot::channel::<()>();

        // Spawn server on the default executor,
        // which is usually a thread-pool from tokio default runtime.
        let server_task = tokio::task::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut rx => {
                        return Ok::<_, anyhow::Error>(());
                    }

                    conn = listener.accept() => {
                        let (stream, _) = conn?;
                        let derp_client_handler = derp_client_handler.clone();
                        tokio::task::spawn(async move {
                            if let Err(err) = Http::new()
                                .serve_connection(stream, derp_client_handler)
                                .with_upgrades()
                                .await
                            {
                                eprintln!("Failed to serve connection: {:?}", err);
                            }
                        });
                    }
                }
            }
        });

        // Client requests a HTTP connection upgrade.
        let request = client_upgrade_request(addr);
        request.await?;

        // Complete the oneshot so that the server stops
        // listening and the process can close down.
        assert!(tx.send(()).is_ok());
        server_task.await??;
        Ok(())
    }
}
