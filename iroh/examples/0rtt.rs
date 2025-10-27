use std::{env, future::Future, str::FromStr, time::Instant};

use clap::Parser;
use data_encoding::HEXLOWER;
use iroh::{
    EndpointId, SecretKey,
    endpoint::{Connecting, Connection},
};
use n0_error::{Result, StackResultExt, StdResultExt, bail};
use n0_future::{StreamExt, future};
use n0_watcher::Watcher;
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
///
/// We send the data on the connection. If `proceed` resolves to true,
/// read the response immediately. Otherwise, the stream pair is bad and we need
/// to open a new stream pair.
async fn pingpong(
    connection: &Connection,
    proceed: impl Future<Output = bool>,
    x: u64,
) -> Result<()> {
    let (mut send, recv) = connection.open_bi().await.e()?;
    let data = x.to_be_bytes();
    send.write_all(&data).await.e()?;
    send.finish().e()?;
    let mut recv = if proceed.await {
        // use recv directly if we can proceed
        recv
    } else {
        // proceed returned false, so we have learned that the 0-RTT send was rejected.
        // at this point we have a fully handshaked connection, so we try again.
        let (mut send, recv) = connection.open_bi().await.e()?;
        send.write_all(&data).await.e()?;
        send.finish().e()?;
        recv
    };
    let echo = recv.read_to_end(8).await.e()?;
    assert!(echo == data);
    Ok(())
}

async fn pingpong_0rtt(connecting: Connecting, i: u64) -> Result<Connection> {
    let connection = match connecting.into_0rtt() {
        Ok((connection, accepted)) => {
            trace!("0-RTT possible from our side");
            pingpong(&connection, accepted, i).await?;
            connection
        }
        Err(connecting) => {
            trace!("0-RTT not possible from our side");
            let connection = connecting.await.e()?;
            pingpong(&connection, future::ready(true), i).await?;
            connection
        }
    };
    Ok(connection)
}

async fn connect(args: Args) -> Result<()> {
    let remote_id = args.endpoint_id.context("Missing endpoint id")?;
    let endpoint = iroh::Endpoint::builder()
        .relay_mode(iroh::RelayMode::Disabled)
        .keylog(true)
        .bind()
        .await?;
    let t0 = Instant::now();
    for i in 0..args.rounds {
        let t0 = Instant::now();
        let connecting = endpoint
            .connect_with_opts(remote_id, PINGPONG_ALPN, Default::default())
            .await?;
        let connection = if args.disable_0rtt {
            let connection = connecting.await.e()?;
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
    let mut addrs = endpoint.watch_addr().stream();
    let addr = loop {
        let Some(addr) = addrs.next().await else {
            bail!("Address stream closed");
        };
        if !addr.ip_addrs().count() == 0 {
            break addr;
        }
    };
    println!("Listening on: {addr:?}");

    let accept = async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let connecting = incoming.accept().e()?;
                let (connection, _zero_rtt_accepted) = connecting
                    .into_0rtt()
                    .expect("accept into 0.5 RTT always succeeds");
                let (mut send, mut recv) = connection.accept_bi().await.e()?;
                trace!("recv.is_0rtt: {}", recv.is_0rtt());
                let data = recv.read_to_end(8).await.e()?;
                trace!("recv: {}", data.len());
                send.write_all(&data).await.e()?;
                send.finish().e()?;
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
