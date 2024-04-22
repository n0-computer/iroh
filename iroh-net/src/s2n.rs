use anyhow::Result;
use iroh_base::key::SecretKey;
use s2n_quic::{client::Connect, Client, Server};
use s2n_quic_rustls::{client::Client as TlsClient, server::Server as TlsServer};
use std::net::SocketAddr;

mod io;

pub async fn s2n_client() -> Result<()> {
    let key = SecretKey::generate();
    let alpns = vec![b"hello".to_vec()];
    let tls_client: TlsClient = super::tls::make_client_config(&key, None, alpns, false)?.into();

    let io = io::Io::new("0.0.0.0:0")?;

    let client = Client::builder()
        .with_tls(tls_client)?
        .with_io(io)?
        .start()?;

    let addr: SocketAddr = "127.0.0.1:4433".parse()?;
    let connect = Connect::new(addr).with_server_name("localhost");
    let mut connection = client.connect(connect).await?;

    // ensure the connection doesn't time out with inactivity
    connection.keep_alive(true)?;

    // open a new stream and split the receiving and sending sides
    let stream = connection.open_bidirectional_stream().await?;
    let (mut receive_stream, mut send_stream) = stream.split();

    // spawn a task that copies responses from the server to stdout
    tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        let _ = tokio::io::copy(&mut receive_stream, &mut stdout).await;
    });

    // copy data from stdin and send it to the server
    let mut stdin = tokio::io::stdin();
    tokio::io::copy(&mut stdin, &mut send_stream).await?;

    Ok(())
}

pub async fn s2n_server() -> Result<()> {
    let key = SecretKey::generate();
    let alpns = vec![b"hello".to_vec()];
    let tls_client: TlsServer = super::tls::make_server_config(&key, alpns, false)?.into();

    let io = io::Io::new("0.0.0.0:0")?;

    let mut server = Server::builder()
        .with_tls(tls_client)?
        .with_io(io)?
        .start()?;

    let mut connection = server.accept().await.unwrap();

    // ensure the connection doesn't time out with inactivity
    connection.keep_alive(true)?;

    // open a new stream and split the receiving and sending sides
    let stream = connection.accept_bidirectional_stream().await?.unwrap();
    let (mut receive_stream, mut send_stream) = stream.split();

    // spawn a task that copies responses from the server to stdout
    tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        let _ = tokio::io::copy(&mut receive_stream, &mut stdout).await;
    });

    // copy data from stdin and send it to the server
    let mut stdin = tokio::io::stdin();
    tokio::io::copy(&mut stdin, &mut send_stream).await?;

    Ok(())
}
