mod client;
mod server;

pub use client::{Client, ClientBuilder, ClientError};

pub use server::derp_connection_handler;

pub(crate) const HTTP_UPGRADE_PROTOCOL: &str = "iroh derp http";

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;

    use anyhow::Result;
    use bytes::Bytes;
    use hyper::server::conn::Http;
    use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tokio_util::sync::CancellationToken;

    use crate::hp::derp::{
        DerpNode, DerpRegion, ReceivedMessage, Server as DerpServer, UseIpv4, UseIpv6,
    };
    use crate::hp::key::node::{PublicKey, SecretKey};
    use crate::test_utils::setup_logging;

    async fn run_server(key: SecretKey) -> (SocketAddr, CancellationToken, JoinHandle<Result<()>>) {
        let addr = "127.0.0.1:0";

        // create derp_server
        let derp_server: DerpServer<OwnedReadHalf, OwnedWriteHalf, super::Client> =
            DerpServer::new(key, None);

        // create handler that sends new connections to the client
        let derp_client_handler = derp_server.client_conn_handler(Default::default());

        let listener = TcpListener::bind(&addr).await.unwrap();
        // We need the assigned address for the client to send it messages.
        let addr = listener.local_addr().unwrap();

        let done = CancellationToken::new();
        let server_shutdown = done.clone();
        // Spawn server on the default executor,
        // which is usually a thread-pool from tokio default runtime.
        let server_task = tokio::task::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = server_shutdown.cancelled() => {
                        derp_server.close().await;
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
        (addr, done, server_task)
    }

    #[tokio::test]
    async fn test_http_clients_and_server() -> Result<()> {
        let _guard = setup_logging();

        let server_key = SecretKey::generate();
        let a_key = SecretKey::generate();
        let b_key = SecretKey::generate();

        // start server
        let (addr, shutdown_server, server_task) = run_server(server_key).await;

        // get dial info & create region
        let port = addr.port();
        let addr = {
            if let std::net::IpAddr::V4(ipv4_addr) = addr.ip() {
                ipv4_addr
            } else {
                anyhow::bail!("cannot get ipv4 addr from socket addr {addr:?}");
            }
        };
        println!("addr: {addr}:{port}");

        let region = DerpRegion {
            region_id: 1,
            avoid: false,
            nodes: vec![DerpNode {
                name: "test_node".to_string(),
                region_id: 1,
                host_name: "".to_string(),
                stun_only: false,
                stun_port: 0,
                stun_test_ip: None,
                ipv4: UseIpv4::Some(addr),
                ipv6: UseIpv6::Disabled,
                derp_port: port,
            }],
            region_code: "test_region".to_string(),
        };

        // create clients
        let (a_key, mut a_recv, client_a_task, client_a) =
            create_test_client(a_key, region.clone());
        println!("created client {a_key:?}");
        let (b_key, mut b_recv, client_b_task, client_b) = create_test_client(b_key, region);
        println!("created client {b_key:?}");

        client_a.ping().await?;
        client_b.ping().await?;

        println!("sending message from a to b");
        let msg = Bytes::from_static(b"hi there, client b!");
        client_a.send(b_key.clone(), msg.clone()).await?;
        println!("waiting for message from a on b");
        let (got_key, got_msg) = b_recv.recv().await.expect("expected message from client_a");
        assert_eq!(a_key, got_key);
        assert_eq!(msg, got_msg);

        println!("sending message from b to a");
        let msg = Bytes::from_static(b"right back at ya, client b!");
        client_b.send(a_key.clone(), msg.clone()).await?;
        println!("waiting for message b on a");
        let (got_key, got_msg) = a_recv.recv().await.expect("expected message from client_b");
        assert_eq!(b_key, got_key);
        assert_eq!(msg, got_msg);

        shutdown_server.cancel();
        server_task.await??;
        client_a.close().await;
        client_a_task.abort();
        client_b.close().await;
        client_b_task.abort();
        Ok(())
    }

    fn create_test_client(
        key: SecretKey,
        region: DerpRegion,
    ) -> (
        PublicKey,
        mpsc::Receiver<(PublicKey, Bytes)>,
        JoinHandle<()>,
        Client,
    ) {
        let client = ClientBuilder::new().new_region(key.clone(), move || {
            let region = region.clone();
            Box::pin(async move { Some(region) })
        });
        let public_key = key.public_key();
        let (received_msg_s, received_msg_r) = tokio::sync::mpsc::channel(10);
        let client_reader = client.clone();
        let client_reader_task = tokio::spawn(async move {
            loop {
                println!("waiting for message on {:?}", key.public_key());
                match client_reader.recv_detail().await {
                    Err(e) => {
                        println!("client {:?} `recv_detail` error {e}", key.public_key());
                        return;
                    }
                    Ok((msg, _)) => {
                        println!("got message on {:?}: {msg:?}", key.public_key());
                        if let ReceivedMessage::ReceivedPacket { source, data } = msg {
                            received_msg_s
                                .send((source.clone(), data))
                                .await
                                .unwrap_or_else(|err| {
                                    panic!(
                                        "client {:?}, error sending message over channel: {:?}",
                                        key.public_key(),
                                        err
                                    )
                                });
                        }
                    }
                }
            }
        });
        (public_key, received_msg_r, client_reader_task, client)
    }
}
