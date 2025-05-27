use std::{env, future::Future, str::FromStr, time::Instant};

use anyhow::Context;
use clap::Parser;
use iroh::{
    endpoint::{Connecting, Connection},
    watcher::Watcher,
    SecretKey,
};
use iroh_base::ticket::NodeTicket;
use n0_future::{future, StreamExt};
use rand::thread_rng;
use tracing::{info, trace};

const PINGPONG_ALPN: &[u8] = b"0rtt-pingpong";

#[derive(Parser)]
struct Args {
    /// The node id to connect to. If not set, the program will start a server.
    node: Option<NodeTicket>,
    /// Number of rounds to run.
    #[clap(long, default_value = "100")]
    rounds: u64,
    /// Run without 0-RTT for comparison.
    #[clap(long)]
    disable_0rtt: bool,
}

/// Gets a secret key from the IROH_SECRET environment variable or generates a new random one.
/// If the environment variable is set, it must be a valid string representation of a secret key.
pub fn get_or_generate_secret_key() -> anyhow::Result<SecretKey> {
    if let Ok(secret) = env::var("IROH_SECRET") {
        // Parse the secret key from string
        SecretKey::from_str(&secret).context("Invalid secret key format")
    } else {
        // Generate a new random key
        let secret_key = SecretKey::generate(&mut thread_rng());
        println!("Generated new secret key: {}", secret_key);
        println!("To reuse this key, set the IROH_SECRET environment variable to this value");
        Ok(secret_key)
    }
}

/// Do a simple ping-pong with the given connection.
///
/// We send the data on the connection. If `proceed` resolves to true,
/// read the response immediately. Otherwise, the stream pair is bad and we need
/// to open a new stream pair.
async fn pingpong(
    connection: &Connection,
    proceed: impl Future<Output = bool>,
    x: u64,
) -> anyhow::Result<()> {
    let (mut send, recv) = connection.open_bi().await?;
    let data = x.to_be_bytes();
    send.write_all(&data).await?;
    send.finish()?;
    let mut recv = if proceed.await {
        // use recv directly if we can proceed
        recv
    } else {
        // proceed returned false, so we have learned that the 0-RTT send was rejected.
        // at this point we have a fully handshaked connection, so we try again.
        let (mut send, recv) = connection.open_bi().await?;
        send.write_all(&data).await?;
        send.finish()?;
        recv
    };
    let echo = recv.read_to_end(8).await?;
    anyhow::ensure!(echo == data);
    Ok(())
}

async fn pingpong_0rtt(connecting: Connecting, i: u64) -> anyhow::Result<Connection> {
    let connection = match connecting.into_0rtt() {
        Ok((connection, accepted)) => {
            trace!("0-RTT possible from our side");
            pingpong(&connection, accepted, i).await?;
            connection
        }
        Err(connecting) => {
            trace!("0-RTT not possible from our side");
            let connection = connecting.await?;
            pingpong(&connection, future::ready(true), i).await?;
            connection
        }
    };
    Ok(connection)
}

async fn connect(args: Args) -> anyhow::Result<()> {
    let node_addr = args.node.unwrap().node_addr().clone();
    let endpoint = iroh::Endpoint::builder()
        .relay_mode(iroh::RelayMode::Disabled)
        .keylog(true)
        .bind()
        .await?;
    let t0 = Instant::now();
    for i in 0..args.rounds {
        let t0 = Instant::now();
        let connecting = endpoint
            .connect_with_opts(node_addr.clone(), PINGPONG_ALPN, Default::default())
            .await?;
        let connection = if args.disable_0rtt {
            let connection = connecting.await?;
            trace!("connecting without 0-RTT");
            pingpong(&connection, future::ready(true), i).await?;
            connection
        } else {
            pingpong_0rtt(connecting, i).await?
        };
        tokio::spawn(async move {
            // wait for some time for the handshake to complete and the server
            // to send a NewSessionTicket. This is less than ideal, but we
            // don't have a better way to wait for the handshake to complete.
            tokio::time::sleep(connection.rtt() * 2).await;
            connection.close(0u8.into(), b"");
        });
        let elapsed = t0.elapsed();
        println!("round {}: {} us", i, elapsed.as_micros());
    }
    let elapsed = t0.elapsed();
    println!("total time: {} us", elapsed.as_micros());
    println!(
        "time per round: {} us",
        elapsed.as_micros() / (args.rounds as u128)
    );
    Ok(())
}

async fn accept(_args: Args) -> anyhow::Result<()> {
    let secret_key = get_or_generate_secret_key()?;
    let endpoint = iroh::Endpoint::builder()
        .alpns(vec![PINGPONG_ALPN.to_vec()])
        .secret_key(secret_key)
        .relay_mode(iroh::RelayMode::Disabled)
        .bind()
        .await?;
    let mut addrs = endpoint.node_addr().stream();
    let addr = loop {
        let Some(addr) = addrs.next().await else {
            anyhow::bail!("Address stream closed");
        };
        if let Some(addr) = addr {
            if !addr.direct_addresses.is_empty() {
                break addr;
            }
        }
    };
    println!("Listening on: {:?}", addr);
    println!("Node ID: {:?}", addr.node_id);
    println!("Ticket: {}", NodeTicket::from(addr));
    let accept = async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let connecting = incoming.accept()?;
                let (connection, _zero_rtt_accepted) = connecting
                    .into_0rtt()
                    .expect("accept into 0.5 RTT always succeeds");
                let (mut send, mut recv) = connection.accept_bi().await?;
                trace!("recv.is_0rtt: {}", recv.is_0rtt());
                let data = recv.read_to_end(8).await?;
                trace!("recv: {}", data.len());
                send.write_all(&data).await?;
                send.finish()?;
                connection.closed().await;
                anyhow::Ok(())
            });
        }
    };
    tokio::select! {
        _ = accept => {
            info!("accept finished, shutting down");
        },
        _ = tokio::signal::ctrl_c()=> {
            info!("Ctrl-C received, shutting down");
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    if args.node.is_some() {
        connect(args).await?;
    } else {
        accept(args).await?;
    };
    Ok(())
}
