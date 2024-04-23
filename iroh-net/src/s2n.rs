use anyhow::{Context, Result};
use bytes::Bytes;
use iroh_base::{key::SecretKey, node_addr::NodeAddr};
use s2n_quic::{client::Connect, Client, Server};
use s2n_quic_rustls::{client::Client as TlsClient, server::Server as TlsServer};
use std::net::SocketAddr;

use crate::magicsock::{self, MagicSock};

mod io;

pub async fn s2n_client(node_addr: NodeAddr) -> Result<()> {
    let key = SecretKey::generate();
    let alpns = vec![b"hello".to_vec()];
    let tls_client: TlsClient = super::tls::make_client_config(&key, None, alpns, false)?.into();

    let magic = MagicSock::new(magicsock::Options {
        secret_key: key.clone(),
        port: 9998,
        ..Default::default()
    })
    .await?;
    magic.add_node_addr(node_addr.clone());
    let addr: SocketAddr = magic.get_mapping_addr(&node_addr.node_id).unwrap();

    let io = io::Io::new(magic, "0.0.0.0:0").context("io")?;

    let client = Client::builder()
        .with_tls(tls_client)
        .context("tls")?
        .with_io(io)
        .context("io")?
        .start()
        .context("start")?;

    let connect = Connect::new(addr).with_server_name("localhost");
    let mut connection = client.connect(connect).await.context("connect")?;

    // ensure the connection doesn't time out with inactivity
    connection.keep_alive(true).context("keep alive")?;

    // open a new stream and split the receiving and sending sides
    let stream = connection
        .open_bidirectional_stream()
        .await
        .context("open stream")?;
    let (mut receive_stream, mut send_stream) = stream.split();

    send_stream
        .send(Bytes::from_static(b"hello world"))
        .await
        .context("send")?;
    let res = receive_stream.receive().await.context("receive")?;
    let res = res.expect("no chunk");
    assert_eq!(std::str::from_utf8(&res).unwrap(), "hello world");

    Ok(())
}

pub async fn s2n_server(magic: MagicSock, key: SecretKey) -> Result<()> {
    let alpns = vec![b"hello".to_vec()];
    let tls_client: TlsServer = super::tls::make_server_config(&key, alpns, false)?.into();

    let io = io::Io::new(magic, "0.0.0.0:9999")?;

    let mut server = Server::builder()
        .with_tls(tls_client)?
        .with_io(io)?
        .start()?;

    let mut connection = server.accept().await.expect("no connection");

    // ensure the connection doesn't time out with inactivity
    connection.keep_alive(true)?;

    // open a new stream and split the receiving and sending sides
    let stream = connection
        .accept_bidirectional_stream()
        .await?
        .expect("no stream");
    let (mut receive_stream, mut send_stream) = stream.split();

    let chunk = receive_stream.receive().await?;
    let chunk = chunk.expect("no chunk");
    send_stream.send(chunk).await?;
    send_stream.close().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use super::*;
    use crate::defaults::default_relay_map;

    #[tokio::test(flavor = "multi_thread")]
    async fn basics() -> Result<()> {
        iroh_test::logging::setup_multithreaded();

        let server_key = SecretKey::generate();
        let server_id = server_key.public();

        let magic = MagicSock::new(magicsock::Options {
            secret_key: server_key.clone(),
            port: 9999,
            // relay_map: default_relay_map(),
            ..Default::default()
        })
        .await?;
        let addrs = magic
            .local_endpoints()
            .next()
            .await
            .ok_or(anyhow::anyhow!("No endpoints found"))?;
        let relay = magic.my_relay();
        let addrs = addrs.into_iter().map(|x| x.addr).collect();
        let server_addr = NodeAddr::from_parts(server_id, relay, addrs);

        dbg!(&server_addr);

        let server =
            tokio::task::spawn(
                async move { s2n_server(magic, server_key).await.context("server") },
            );

        let client =
            tokio::task::spawn(async move { s2n_client(server_addr).await.context("client") });

        server.await??;
        client.await??;
        Ok(())
    }
}
