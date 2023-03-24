use anyhow::Result;
use futures::future::{BoxFuture, FutureExt};
use hyper::header::{HeaderValue, UPGRADE};
use hyper::upgrade::Upgraded;
use hyper::{Body, Request, Response, StatusCode};

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use super::HTTP_UPGRADE_PROTOCOL;
use crate::hp::derp::{server::ClientConnHandler, types::PacketForwarder};

// The server HTTP handler to do HTTP upgrades
pub async fn derp_connection_handler<P>(
    conn_handler: &ClientConnHandler<OwnedReadHalf, OwnedWriteHalf, P>,
    upgraded: Upgraded,
) -> Result<()>
where
    P: PacketForwarder,
{
    // get the underlying TcpStream
    let parts = match upgraded.downcast::<tokio::net::TcpStream>() {
        Ok(p) => p,
        Err(_) => {
            anyhow::bail!("could not downcast the upgraded connection to a tokio::net::TcpStream")
        }
    };

    // split into the reader and writer parts
    let (reader, writer) = parts.io.into_split();

    // send to the derp server
    conn_handler.accept(reader, writer).await
}

type HyperResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Return a closure that takes an http Request, upgrades that connection, and hands it off to the
/// derp server.
fn derp_upgrade_fn<P: PacketForwarder>(
    conn_handler: ClientConnHandler<OwnedReadHalf, OwnedWriteHalf, P>,
) -> impl Fn(Request<Body>) -> BoxFuture<'static, HyperResult<Response<Body>>> {
    move |mut req| {
        // TODO: soooo much cloning. See if there is an alternative
        let closure_conn_handler = conn_handler.clone();
        async move {
            {
                let mut res = Response::new(Body::empty());

                // Send a 400 to any request that doesn't have
                // an `Upgrade` header.
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
                                tracing::warn!("server {HTTP_UPGRADE_PROTOCOL} io error: {}", e)
                            };
                        }
                        Err(e) => tracing::warn!("upgrade error: {}", e),
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

    use tokio::sync::oneshot;

    use hyper::header::UPGRADE;
    use hyper::service::{make_service_fn, service_fn};
    use hyper::upgrade::Upgraded;
    use hyper::{Body, Client, Request, Server, StatusCode};

    use crate::hp::derp::server::Server as DerpServer;
    use crate::hp::key::node::{PublicKey, SecretKey};

    /// Handle client-side I/O after HTTP upgraded.
    async fn derp_client(mut upgraded: Upgraded) -> Result<()> {
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
        assert_eq!(crate::hp::derp::FRAME_SERVER_INFO, frame_type);
        let msg = secret_key.open_from(&got_server_key, &buf)?;
        let _info: crate::hp::derp::types::ServerInfo = postcard::from_bytes(&msg)?;
        Ok(())
    }

    /// Our client HTTP handler to initiate HTTP upgrades.
    async fn client_upgrade_request(addr: SocketAddr) -> Result<()> {
        let req = Request::builder()
            .uri(format!("http://{}/", addr))
            .header(UPGRADE, HTTP_UPGRADE_PROTOCOL)
            .body(Body::empty())
            .unwrap();

        let res = Client::new().request(req).await?;
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

        let addr = ([127, 0, 0, 1], 0).into();

        // create derp_server
        let server_key = SecretKey::generate();
        let derp_server: DerpServer<OwnedReadHalf, OwnedWriteHalf, MockPacketForwarder> =
            DerpServer::new(server_key, None);

        // create handler that sends new connections to the client
        let derp_client_handler = derp_server.client_conn_handler();

        // Would love to wrap this in a `make_derp_server_service` function that returns
        // a `hyper::service::make::MakeServiceFn`, but that's a private struct so I don't think we
        // can
        let make_service = make_service_fn(move |_| {
            let derp_client_handler = derp_client_handler.clone();
            async { Ok::<_, hyper::Error>(service_fn(derp_upgrade_fn(derp_client_handler))) }
        });

        let server = Server::bind(&addr).serve(make_service);

        // We need the assigned address for the client to send it messages.
        let addr = server.local_addr();

        // For this example, a oneshot is used to signal that after 1 request,
        // the server should be shutdown.
        let (tx, rx) = oneshot::channel::<()>();
        let server = server.with_graceful_shutdown(async move {
            rx.await.ok();
        });

        // Spawn server on the default executor,
        // which is usually a thread-pool from tokio default runtime.
        tokio::task::spawn(async move {
            if let Err(e) = server.await {
                eprintln!("server error: {}", e);
            }
        });

        // Client requests a HTTP connection upgrade.
        let request = client_upgrade_request(addr.clone());
        if let Err(e) = request.await {
            eprintln!("client error: {}", e);
        }

        // Complete the oneshot so that the server stops
        // listening and the process can close down.
        let _ = tx.send(());
        Ok(())
    }
}
