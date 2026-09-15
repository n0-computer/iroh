use std::{io::Write, net::SocketAddr};

use iroh::{Endpoint, EndpointAddr, SecretKey, endpoint::presets::Empty};

const ALPN: &[u8] = b"released-identity-test/1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let endpoint = Endpoint::builder(Empty)
        .crypto_provider(iroh::tls::default_provider())
        .secret_key(SecretKey::from_bytes(&[77; 32]))
        .bind_addr("127.0.0.1:0".parse::<SocketAddr>()?)?
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;
    let address = endpoint
        .bound_sockets()
        .into_iter()
        .find(|a| a.is_ipv4())
        .ok_or("no IPv4 socket")?;
    println!("{} {}", endpoint.id(), address);
    std::io::stdout().flush()?;
    let connection = match args.get(1).map(String::as_str) {
        Some("server") => endpoint.accept().await.ok_or("closed")?.await?,
        Some("client") => {
            let remote = args.get(2).ok_or("missing ID")?.parse()?;
            let addr = args.get(3).ok_or("missing address")?.parse()?;
            endpoint
                .connect(EndpointAddr::new(remote).with_ip_addr(addr), ALPN)
                .await?
        }
        _ => return Err("expected server or client".into()),
    };
    if args[1] == "client" {
        let (mut send, mut recv) = connection.open_bi().await?;
        send.write_all(b"released Ed25519 peer").await?;
        send.finish()?;
        if recv.read_to_end(128).await? != b"released Ed25519 peer" {
            return Err("echo mismatch".into());
        }
    } else {
        let (mut send, mut recv) = connection.accept_bi().await?;
        let data = recv.read_to_end(128).await?;
        send.write_all(&data).await?;
        send.finish()?;
        send.stopped().await?;
    }
    endpoint.close().await;
    Ok(())
}
