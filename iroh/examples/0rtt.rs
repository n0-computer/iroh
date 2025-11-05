use std::{env, str::FromStr, time::Instant};

use clap::Parser;
use data_encoding::HEXLOWER;
use iroh::{EndpointId, SecretKey, discovery::Discovery, endpoint::ZeroRttConnection};
use n0_error::{Result, StackResultExt, StdResultExt};
use n0_future::StreamExt;
use quinn::{RecvStream, SendStream};
use tracing::{info, trace};

const PINGPONG_ALPN: &[u8] = b"0rtt-pingpong";

#[derive(Parser)]
struct Args {
    /// The endpoint id to connect to. If not set, the program will start a server.
    endpoint_id: Option<EndpointId>,
    /// Number of rounds to run.
    #[clap(long, default_value = "100")]
    rounds: u64,
    /// Run without 0-RTT for comparison.
    #[clap(long)]
    disable_0rtt: bool,
}

/// Gets a secret key from the IROH_SECRET environment variable or generates a new random one.
/// If the environment variable is set, it must be a valid string representation of a secret key.
pub fn get_or_generate_secret_key() -> Result<SecretKey> {
    if let Ok(secret) = env::var("IROH_SECRET") {
        // Parse the secret key from string
        SecretKey::from_str(&secret).context("Invalid secret key format")
    } else {
        // Generate a new random key
        let secret_key = SecretKey::generate(&mut rand::rng());
        println!(
            "Generated new secret key: {}",
            HEXLOWER.encode(&secret_key.to_bytes())
        );
        println!("To reuse this key, set the IROH_SECRET environment variable to this value");
        Ok(secret_key)
    }
}

/// Do a simple ping-pong with the given connection.
async fn pingpong(send: SendStream, recv: RecvStream, x: u64) -> Result<()> {
    ping(send, x).await?;
    pong(recv, x).await
}

async fn ping(mut send: SendStream, x: u64) -> Result<()> {
    let data = x.to_be_bytes();
    send.write_all(&data).await.anyerr()?;
    send.finish().anyerr()
}

async fn pong(mut recv: RecvStream, x: u64) -> Result<()> {
    let data = x.to_be_bytes();
    let echo = recv.read_to_end(8).await.anyerr()?;
    assert!(echo == data);
    Ok(())
}

async fn connect(args: Args) -> Result<()> {
    let remote_id = args.endpoint_id.unwrap();
    let endpoint = iroh::Endpoint::builder()
        .relay_mode(iroh::RelayMode::Disabled)
        .keylog(true)
        .bind()
        .await?;
    // ensure we have resolved the remote_id before connecting
    // so we get a more accurate connection timing
    let mut discovery_stream = endpoint
        .discovery()
        .resolve(remote_id)
        .expect("discovery to be enabled");
    let _ = discovery_stream.next().await;

    let t0 = Instant::now();
    for i in 0..args.rounds {
        let t0 = Instant::now();
        let connecting = endpoint
            .connect_with_opts(remote_id, PINGPONG_ALPN, Default::default())
            .await?;
        let connection = if args.disable_0rtt {
            let connection = connecting.await.anyerr()?;
            trace!("connecting without 0-RTT");
            let (send, recv) = connection.open_bi().await.anyerr()?;
            pingpong(send, recv, i).await?;
            connection
        } else {
            match connecting.into_0rtt() {
                Ok(zrtt_connection) => {
                    trace!("0-RTT possible from our side");
                    let (send, recv) = zrtt_connection.open_bi().await.anyerr()?;
                    // before we get the full handshake, attempt to send 0-RTT data
                    let zrtt_task = tokio::spawn(ping(send, i));
                    match zrtt_connection.to_handshaked_connection().await? {
                        ZeroRttConnection::Accepted(conn) => {
                            let _ = zrtt_task.await.anyerr()?;
                            pong(recv, i).await?;
                            conn
                        }
                        ZeroRttConnection::Rejected(conn) => {
                            zrtt_task.abort();
                            let (send, recv) = conn.open_bi().await.anyerr()?;
                            pingpong(send, recv, i).await?;
                            conn
                        }
                    }
                }
                Err(connecting) => {
                    trace!("0-RTT not possible from our side");
                    let conn = connecting.await.anyerr()?;
                    let (send, recv) = conn.open_bi().await.anyerr()?;
                    pingpong(send, recv, i).await?;
                    conn
                }
            }
        };
        connection.close(0u8.into(), b"");
        let elapsed = t0.elapsed();
        println!("round {i}: {} us", elapsed.as_micros());
    }
    let elapsed = t0.elapsed();
    println!("total time: {} us", elapsed.as_micros());
    println!(
        "time per round: {} us",
        elapsed.as_micros() / (args.rounds as u128)
    );
    Ok(())
}

async fn accept(_args: Args) -> Result<()> {
    let secret_key = get_or_generate_secret_key()?;
    let endpoint = iroh::Endpoint::builder()
        .alpns(vec![PINGPONG_ALPN.to_vec()])
        .secret_key(secret_key)
        .relay_mode(iroh::RelayMode::Disabled)
        .bind()
        .await?;
    println!("endpoint id: {}", endpoint.id());

    let accept = async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let accepting = incoming.accept().anyerr()?;
                let connection = accepting.into_0rtt();
                let (mut send, mut recv) = connection.accept_bi().await.anyerr()?;
                trace!("recv.is_0rtt: {}", recv.is_0rtt());
                let data = recv.read_to_end(8).await.anyerr()?;
                trace!("recv: {}", data.len());
                send.write_all(&data).await.anyerr()?;
                send.finish().anyerr()?;
                connection.closed().await;
                n0_error::Ok(())
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
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    if args.endpoint_id.is_some() {
        connect(args).await?;
    } else {
        accept(args).await?;
    };
    Ok(())
}
