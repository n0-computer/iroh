use std::{net::SocketAddr};

use clap::Parser;
use ed25519_dalek::SigningKey as SecretKey;
use iroh_net::{
    defaults::default_derp_map,
    endpoint::{accept_conn, MagicEndpoint},
    tls::{Keypair, PeerId},
};

const EXAMPLE_ALPN: &[u8] = b"n0/iroh/examples/magic/0";

#[derive(Debug, Parser)]
struct Cli {
    #[clap(short, long)]
    secret: Option<String>,
    #[clap(short, long, default_value = "0.0.0.0:0")]
    bind_address: SocketAddr,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    Listen,
    Connect {
        peer_id: String,
        addrs: Option<Vec<SocketAddr>>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Cli::parse();
    let keypair = match args.secret {
        None => {
            let keypair = Keypair::generate();
            println!("our secret key: {}", fmt_secret(&keypair));
            keypair
        }
        Some(key) => parse_secret(&key)?,
    };

    let endpoint = MagicEndpoint::bind(
        keypair,
        args.bind_address,
        vec![EXAMPLE_ALPN.to_vec()],
        None,
        Some(default_derp_map()),
        false,
    )
    .await?;

    println!("endpoint bound! our peer id: {}", endpoint.peer_id());
    let me = endpoint.peer_id();

    match args.command {
        Command::Listen => {
            while let Some(conn) = endpoint.accept().await {
                let (peer_id, alpn, conn) = accept_conn(conn).await?;
                println!(
                    "> new connection from {peer_id} (on {}) with ALPN {alpn}",
                    conn.remote_address()
                );
                tokio::spawn(async move {
                    let (mut send, mut recv) = conn.accept_bi().await?;
                    let message = format!("hi! you connected to {me}. bye bye");
                    send.write_all(message.as_bytes()).await?;
                    send.finish().await?;
                    let message = recv.read_to_end(100).await?;
                    let message = String::from_utf8(message)?;
                    println!("received: {message}");
                    Ok::<_, anyhow::Error>(())
                });
            }
        }
        Command::Connect { peer_id, addrs } => {
            let peer_id: PeerId = peer_id.parse()?;
            let addrs = addrs.unwrap_or_default();
            let conn = endpoint.connect(peer_id, EXAMPLE_ALPN, &addrs).await?;
            let (mut send, mut recv) = conn.open_bi().await?;
            let message = format!("hello here's {me}");
            send.write_all(message.as_bytes()).await?;
            send.finish().await?;
            let message = recv.read_to_end(100).await?;
            let message = String::from_utf8(message)?;
            println!("received: {message}");
        }
    }
    Ok(())
}

fn fmt_secret(keypair: &Keypair) -> String {
    let mut text = data_encoding::BASE32_NOPAD.encode(&keypair.secret().to_bytes());
    text.make_ascii_lowercase();
    text
}
fn parse_secret(secret: &str) -> anyhow::Result<Keypair> {
    let bytes: [u8; 32] = data_encoding::BASE32_NOPAD
        .decode(secret.to_ascii_uppercase().as_bytes())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid secret"))?;
    let key = SecretKey::from_bytes(&bytes);
    Ok(key.into())
}
