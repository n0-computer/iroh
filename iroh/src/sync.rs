use std::net::SocketAddr;

use anyhow::Result;
use bytes::BytesMut;
use iroh_net::{client::dial_peer, hp::derp::DerpMap, tls::PeerId};

pub const SYNC_ALPN: &[u8] = b"n0/iroh-sync/1";

pub async fn run(
    namespace: String,
    author: String,
    addrs: Vec<SocketAddr>,
    peer: PeerId,
    derp_map: Option<DerpMap>,
) -> Result<()> {
    let namespace: iroh_sync::sync::Namespace = namespace
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid namespace"))?;
    let author: iroh_sync::sync::Author = author
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid author"))?;
    println!("Syncing {} with peer {}", namespace.id(), peer);
    let keylog = false;

    let alice = iroh_sync::sync::Replica::new(namespace.clone());

    alice.insert("alice-is-cool", &author, "alice");

    let connection = dial_peer(&addrs, peer, SYNC_ALPN, keylog, derp_map).await?;
    println!("Connected to {}", peer);

    let (mut send_stream, mut recv_stream) = connection.open_bi().await?;

    let mut buffer = BytesMut::with_capacity(1024);
    let mut msg_to_write = Some(alice.sync_initial_message());
    while let Some(msg) = msg_to_write.take() {
        println!("tick");
        let msg_bytes = postcard::to_stdvec(&msg)?;
        iroh_bytes::protocol::write_lp(&mut send_stream, &msg_bytes).await?;

        println!("reading");
        if let Some(read) = iroh_bytes::protocol::read_lp(&mut recv_stream, &mut buffer).await? {
            println!("read {}", read.len());
            let msg = postcard::from_bytes(&read)?;
            if let Some(msg) = alice.sync_process_message(msg) {
                msg_to_write = Some(msg);
            } else {
                println!("no further sync message");
                break;
            }
        }
    }

    println!("sync finished");
    for (key, value) in alice.all() {
        println!(
            "got {:?}\n{:?}\n {:?}\n",
            std::str::from_utf8(key.key()),
            key,
            value
        );
    }

    Ok(())
}

pub async fn handle_connection(
    connecting: quinn::Connecting,
    replica: iroh_sync::sync::Replica,
) -> Result<()> {
    println!("replica: {}", replica.namespace());
    let connection = connecting.await?;
    let (mut send_stream, mut recv_stream) = connection.accept_bi().await?;

    let mut buffer = BytesMut::with_capacity(1024);

    println!("currently have: {} elements", replica.all().len());

    println!("reading");
    while let Some(read) = iroh_bytes::protocol::read_lp(&mut recv_stream, &mut buffer).await? {
        println!("read {}", read.len());
        let msg = postcard::from_bytes(&read)?;

        if let Some(msg) = replica.sync_process_message(msg) {
            let msg_bytes = postcard::to_stdvec(&msg)?;

            iroh_bytes::protocol::write_lp(&mut send_stream, &msg_bytes).await?;
            println!("written {} bytes", msg_bytes.len());
        } else {
            println!("no further sync message");
            break;
        }
    }

    send_stream.finish().await?;

    println!("done");

    Ok(())
}
