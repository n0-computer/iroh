use anyhow::{Context, Result};
use bytes::Bytes;
use iroh_base::key::SecretKey;
use s2n_quic::{client::Connect, Client, Server};
use s2n_quic_rustls::{client::Client as TlsClient, server::Server as TlsServer};
use std::net::SocketAddr;

use crate::magicsock::MagicSock;

mod io;

pub async fn s2n_client() -> Result<()> {
    let key = SecretKey::generate();
    let alpns = vec![b"hello".to_vec()];
    let tls_client: TlsClient = super::tls::make_client_config(&key, None, alpns, false)?.into();

    let magic = MagicSock::new(Default::default()).await?;
    let io = io::Io::new(magic, "0.0.0.0:0").context("io")?;

    let client = Client::builder()
        .with_tls(tls_client).context("tls")?
        .with_io(io).context("io")?
        .start().context("start")?;

    let addr: SocketAddr = "127.0.0.1:9999".parse()?;
    let connect = Connect::new(addr).with_server_name("localhost");
    let mut connection = client.connect(connect).await.context("connect")?;

    // ensure the connection doesn't time out with inactivity
    connection.keep_alive(true).context("keep alive")?;

    // open a new stream and split the receiving and sending sides
    let stream = connection.open_bidirectional_stream().await.context("open stream")?;
    let (mut receive_stream, mut send_stream) = stream.split();

    send_stream.send(Bytes::from_static(b"hello world")).await.context("send")?;
    let res = receive_stream.receive().await.context("receive")?;
    let res = res.expect("no chunk");
    assert_eq!(std::str::from_utf8(&res).unwrap(), "hello world");

    Ok(())
}

pub async fn s2n_server() -> Result<()> {
    let key = SecretKey::generate();
    let alpns = vec![b"hello".to_vec()];
    let tls_client: TlsServer = super::tls::make_server_config(&key, alpns, false)?.into();

    let magic = MagicSock::new(Default::default()).await?;
    let io = io::Io::new(magic, "0.0.0.0:9999")?;

    let mut server = Server::builder()
        .with_tls(tls_client)?
        .with_io(io)?
        .start()?;

    let mut connection = server.accept().await.expect("no connection");

    // ensure the connection doesn't time out with inactivity
    connection.keep_alive(true)?;

    // open a new stream and split the receiving and sending sides
    let stream = connection.accept_bidirectional_stream().await?.expect("no stream");
    let (mut receive_stream, mut send_stream) = stream.split();

    let chunk = receive_stream.receive().await?;
    let chunk = chunk.expect("no chunk");
    send_stream.send(chunk).await?;
    send_stream.close().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn basics() -> Result<()> {
        let server = tokio::task::spawn(async move { s2n_server().await.context("server") });

        s2n_client().await.context("client")?;

        server.await??;
        Ok(())
    }
}
