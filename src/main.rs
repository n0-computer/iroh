use std::{env, net::SocketAddr, path::PathBuf, time::Instant};

use anyhow::{anyhow, bail, Result};
use libp2p_core::identity::ed25519::Keypair;
use s2n_quic::{client::Connect, Client, Server};

async fn main_client(source: PathBuf) -> Result<()> {
    let keypair = libp2p_core::identity::Keypair::Ed25519(Keypair::generate());
    let client_config = libp2p_tls::make_client_config(&keypair, None)?;
    let tls = s2n_quic::provider::tls::rustls::Client::from(client_config);

    let client = Client::builder()
        .with_tls(tls)?
        .with_io("0.0.0.0:0")?
        .start()
        .map_err(|e| anyhow!("{:?}", e))?;

    let addr: SocketAddr = "127.0.0.1:4433".parse()?;
    let connect = Connect::new(addr).with_server_name("localhost");
    let mut connection = client.connect(connect).await?;

    // ensure the connection doesn't time out with inactivity
    connection.keep_alive(true)?;

    // open a new stream and split the receiving and sending sides
    let stream = connection.open_bidirectional_stream().await?;
    let (mut receive_stream, mut send_stream) = stream.split();

    let now = Instant::now();
    // spawn a task that copies responses from the server to stdout
    tokio::spawn(async move {
        let do_it = || async move {
            let data = tokio::fs::File::open(source).await?;
            let mut data = tokio::io::BufReader::new(data);
            // let mut stdin = tokio::io::stdin();
            tokio::io::copy(&mut data, &mut send_stream).await?;
            Ok::<_, anyhow::Error>(())
        };
        if let Err(e) = do_it().await {
            eprintln!("transfer failed: {:?}", e);
        }
    });

    let mut stdout = tokio::io::sink();
    let _ = tokio::io::copy(&mut receive_stream, &mut stdout).await;

    println!("echo roundtrip: {}ms", now.elapsed().as_millis());

    Ok(())
}

async fn main_server() -> Result<()> {
    let keypair = libp2p_core::identity::Keypair::Ed25519(Keypair::generate());
    let server_config = libp2p_tls::make_server_config(&keypair)?;
    let tls = s2n_quic::provider::tls::rustls::Server::from(server_config);

    let mut server = Server::builder()
        .with_tls(tls)?
        .with_io("127.0.0.1:4433")?
        .start()
        .map_err(|e| anyhow!("{:?}", e))?;

    while let Some(mut connection) = server.accept().await {
        // spawn a new task for the connection
        tokio::spawn(async move {
            eprintln!("Connection accepted from {:?}", connection.remote_addr());

            while let Ok(Some(mut stream)) = connection.accept_bidirectional_stream().await {
                // spawn a new task for the stream
                tokio::spawn(async move {
                    eprintln!("Stream opened from {:?}", stream.connection().remote_addr());

                    // echo any data back to the stream
                    while let Ok(Some(data)) = stream.receive().await {
                        stream.send(data).await.expect("stream should be open");
                    }
                });
            }
        });
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        bail!("invalid arguments");
    }

    match args[1].as_str() {
        "client" => {
            let source = PathBuf::from(&args[2]);
            println!("Sending: {}", source.display());
            main_client(source).await?
        }
        "server" => main_server().await?,
        _ => bail!("unknown argument: {}", &args[0]),
    }

    Ok(())
}
