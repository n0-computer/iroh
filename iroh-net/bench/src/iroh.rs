use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use iroh_net::{
    endpoint::{Connection, ConnectionError, RecvStream, SendStream, TransportConfig},
    relay::RelayMode,
    Endpoint, NodeAddr,
};
use tracing::trace;

use crate::{
    client_handler, stats::TransferResult, ClientStats, ConnectionSelector, EndpointSelector, Opt,
};

pub const ALPN: &[u8] = b"n0/iroh-net-bench/0";

/// Creates a server endpoint which runs on the given runtime
pub fn server_endpoint(rt: &tokio::runtime::Runtime, opt: &Opt) -> (NodeAddr, Endpoint) {
    let _guard = rt.enter();
    rt.block_on(async move {
        let ep = Endpoint::builder()
            .alpns(vec![ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .transport_config(transport_config(opt.max_streams, opt.initial_mtu))
            .bind(0)
            .await
            .unwrap();
        let addr = ep.bound_sockets();
        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), addr.0.port());
        let addr = NodeAddr::new(ep.node_id()).with_direct_addresses([addr]);
        (addr, ep)
    })
}

/// Create and run a client
pub async fn client(server_addr: NodeAddr, opt: Opt) -> Result<ClientStats> {
    let client_start = std::time::Instant::now();
    let (endpoint, connection) = connect_client(server_addr, opt).await?;
    let client_connect_time = client_start.elapsed();
    let mut res = client_handler(
        EndpointSelector::Iroh(endpoint),
        ConnectionSelector::Iroh(connection),
        opt,
    )
    .await?;
    res.connect_time = client_connect_time;
    Ok(res)
}

/// Create a client endpoint and client connection
pub async fn connect_client(server_addr: NodeAddr, opt: Opt) -> Result<(Endpoint, Connection)> {
    let endpoint = Endpoint::builder()
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .transport_config(transport_config(opt.max_streams, opt.initial_mtu))
        .bind(0)
        .await
        .unwrap();

    // TODO: We don't support passing client transport config currently
    // let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    // client_config.transport_config(Arc::new(transport_config(&opt)));

    let connection = endpoint
        .connect(server_addr, ALPN)
        .await
        .context("unable to connect")?;
    trace!("connected");

    Ok((endpoint, connection))
}

pub fn transport_config(max_streams: usize, initial_mtu: u16) -> TransportConfig {
    // High stream windows are chosen because the amount of concurrent streams
    // is configurable as a parameter.
    let mut config = TransportConfig::default();
    config.max_concurrent_uni_streams(max_streams.try_into().unwrap());
    config.initial_mtu(initial_mtu);

    // TODO: reenable when we upgrade quinn version
    // let mut acks = quinn::AckFrequencyConfig::default();
    // acks.ack_eliciting_threshold(10u32.into());
    // config.ack_frequency_config(Some(acks));

    config
}

async fn drain_stream(
    stream: &mut RecvStream,
    read_unordered: bool,
) -> Result<(usize, Duration, u64)> {
    let mut read = 0;

    let download_start = Instant::now();
    let mut first_byte = true;
    let mut ttfb = download_start.elapsed();

    let mut num_chunks: u64 = 0;

    if read_unordered {
        while let Some(chunk) = stream.read_chunk(usize::MAX, false).await? {
            if first_byte {
                ttfb = download_start.elapsed();
                first_byte = false;
            }
            read += chunk.bytes.len();
            num_chunks += 1;
        }
    } else {
        // These are 32 buffers, for reading approximately 32kB at once
        #[rustfmt::skip]
        let mut bufs = [
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        ];

        while let Some(n) = stream.read_chunks(&mut bufs[..]).await? {
            if first_byte {
                ttfb = download_start.elapsed();
                first_byte = false;
            }
            read += bufs.iter().take(n).map(|buf| buf.len()).sum::<usize>();
            num_chunks += 1;
        }
    }

    Ok((read, ttfb, num_chunks))
}

async fn send_data_on_stream(stream: &mut SendStream, stream_size: u64) -> Result<()> {
    const DATA: &[u8] = &[0xAB; 1024 * 1024];
    let bytes_data = Bytes::from_static(DATA);

    let full_chunks = stream_size / (DATA.len() as u64);
    let remaining = (stream_size % (DATA.len() as u64)) as usize;

    for _ in 0..full_chunks {
        stream
            .write_chunk(bytes_data.clone())
            .await
            .context("failed sending data")?;
    }

    if remaining != 0 {
        stream
            .write_chunk(bytes_data.slice(0..remaining))
            .await
            .context("failed sending data")?;
    }

    stream.finish().await.context("failed finishing stream")?;

    Ok(())
}

pub async fn handle_client_stream(
    connection: &Connection,
    upload_size: u64,
    read_unordered: bool,
) -> Result<(TransferResult, TransferResult)> {
    let start = Instant::now();

    let (mut send_stream, mut recv_stream) = connection
        .open_bi()
        .await
        .context("failed to open stream")?;

    send_data_on_stream(&mut send_stream, upload_size).await?;

    let upload_result = TransferResult::new(start.elapsed(), upload_size, Duration::default(), 0);

    let start = Instant::now();
    let (size, ttfb, num_chunks) = drain_stream(&mut recv_stream, read_unordered).await?;
    let download_result = TransferResult::new(start.elapsed(), size as u64, ttfb, num_chunks);

    Ok((upload_result, download_result))
}

/// Take the provided endpoint and run the server
pub async fn server(endpoint: Endpoint, opt: Opt) -> Result<()> {
    let mut server_tasks = Vec::new();

    // Handle only the expected amount of clients
    for _ in 0..opt.clients {
        let handshake = endpoint.accept().await.unwrap();
        let connection = handshake.await.context("handshake failed")?;

        server_tasks.push(tokio::spawn(async move {
            loop {
                let (mut send_stream, mut recv_stream) = match connection.accept_bi().await {
                    Err(ConnectionError::ApplicationClosed(_)) => break,
                    Err(e) => {
                        eprintln!("accepting stream failed: {e:?}");
                        break;
                    }
                    Ok(stream) => stream,
                };
                trace!("stream established");

                tokio::spawn(async move {
                    drain_stream(&mut recv_stream, opt.read_unordered).await?;
                    send_data_on_stream(&mut send_stream, opt.download_size).await?;
                    Ok::<_, anyhow::Error>(())
                });
            }

            if opt.stats {
                println!("\nServer connection stats:\n{:#?}", connection.stats());
            }
        }));
    }

    // Await all the tasks. We have to do this to prevent the runtime getting dropped
    // and all server tasks to be cancelled
    for handle in server_tasks {
        if let Err(e) = handle.await {
            eprintln!("Server task error: {e:?}");
        };
    }

    Ok(())
}
