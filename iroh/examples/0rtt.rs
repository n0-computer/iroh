use std::time::Instant;

use clap::Parser;
use iroh::{endpoint::Connection, watcher::Watcher};
use iroh_base::ticket::NodeTicket;
use n0_future::StreamExt;
use tracing::{debug, info, trace};

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

async fn pingpong(connection: &Connection, x: u64) -> anyhow::Result<()> {
    let t0 = Instant::now();
    let (mut send, mut recv) = connection.open_bi().await?;
    let data = x.to_be_bytes();
    send.write_all(&data).await?;
    send.finish()?;
    let echo = recv.read_to_end(8).await?;
    anyhow::ensure!(echo == data);
    let elapsed = t0.elapsed();
    debug!("pingpong round {}: {} us", x, elapsed.as_micros());
    Ok(())
}

async fn connect(args: Args) -> anyhow::Result<()> {
    let node_addr = args.node.unwrap().node_addr().clone();
    let endpoint = iroh::Endpoint::builder().bind().await?;
    let t0 = Instant::now();
    for i in 0..args.rounds {
        let connecting = endpoint
            .connect_with_opts(node_addr.clone(), PINGPONG_ALPN, Default::default())
            .await?;
        if args.disable_0rtt {
            let connection = connecting.await?;
            trace!("connecting without 0-RTT");
            pingpong(&connection, i).await?;
            connection.close(0u32.into(), b"done");
        } else {
            let (connection, accepted) = match connecting.into_0rtt() {
                Ok(res) => {
                    trace!("0-RTT possible from our side");
                    res
                }
                Err(connecting) => {
                    trace!("0-RTT not possible from our side");
                    let connection = connecting.await?;
                    pingpong(&connection, i).await?;
                    continue;
                }
            };
            if pingpong(&connection, i).await.is_ok() {
                // 0-RTT worked, we don't need to wait for accept to complete
                continue;
            }
            if !accepted.await {
                trace!("0-RTT not accepted, trying again without 0-RTT");
                pingpong(&connection, i).await?;
            }
            connection.close(0u32.into(), b"done");
        }
    }
    let elapsed = t0.elapsed();
    info!("total time: {} us", elapsed.as_micros());
    info!(
        "time per round: {} us",
        elapsed.as_micros() / (args.rounds as u128)
    );
    Ok(())
}

async fn accept(_args: Args) -> anyhow::Result<()> {
    let endpoint = iroh::Endpoint::builder()
        .alpns(vec![PINGPONG_ALPN.to_vec()])
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
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let conn = incoming.accept()?.await?;
            let (mut send, mut recv) = conn.accept_bi().await?;
            trace!("recv.is_0rtt: {}", recv.is_0rtt());
            let data = recv.read_to_end(8).await?;
            trace!("recv: {}", data.len());
            send.write_all(&data).await?;
            send.finish()?;
            conn.closed().await;
            anyhow::Ok(())
        });
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
