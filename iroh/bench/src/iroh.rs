use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use bytes::Bytes;
use iroh::{
    endpoint::{Connection, ConnectionError, RecvStream, SendStream, TransportConfig},
    watcher::Watcher as _,
    Endpoint, NodeAddr, RelayMode, RelayUrl,
};
use n0_snafu::{Result, ResultExt};
use tracing::{trace, warn};

use crate::{
    client_handler, stats::TransferResult, ClientStats, ConnectionSelector, EndpointSelector, Opt,
};

pub const ALPN: &[u8] = b"n0/iroh-bench/0";

/// Creates a server endpoint which runs on the given runtime
pub fn server_endpoint(
    rt: &tokio::runtime::Runtime,
    relay_url: &Option<RelayUrl>,
    opt: &Opt,
) -> (NodeAddr, Endpoint) {
    let _guard = rt.enter();
    rt.block_on(async move {
        let relay_mode = relay_url
            .clone()
            .map_or(RelayMode::Disabled, |url| RelayMode::Custom(url.into()));

        #[allow(unused_mut)]
        let mut builder = Endpoint::builder();
        #[cfg(feature = "local-relay")]
        {
            builder = builder.insecure_skip_relay_cert_verify(relay_url.is_some());
            let path_selection = match opt.only_relay {
                true => iroh::endpoint::PathSelection::RelayOnly,
                false => iroh::endpoint::PathSelection::default(),
            };
            builder = builder.path_selection(path_selection);
        }
        let ep = builder
            .alpns(vec![ALPN.to_vec()])
            .relay_mode(relay_mode)
            .transport_config(transport_config(opt.max_streams, opt.initial_mtu))
            .bind()
            .await
            .unwrap();

        if relay_url.is_some() {
            ep.home_relay().initialized().await.unwrap();
        }

        let addr = ep.bound_sockets();
        let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), addr.0.port());
        let mut addr = NodeAddr::new(ep.node_id()).with_direct_addresses([addr]);
        if let Some(relay_url) = relay_url {
            addr = addr.with_relay_url(relay_url.clone());
        }
        (addr, ep)
    })
}

/// Create and run a client
pub async fn client(
    server_addr: NodeAddr,
    relay_url: Option<RelayUrl>,
    opt: Opt,
) -> Result<ClientStats> {
    let client_start = std::time::Instant::now();
    let (endpoint, connection) = connect_client(server_addr, relay_url, opt).await?;
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
pub async fn connect_client(
    server_addr: NodeAddr,
    relay_url: Option<RelayUrl>,
    opt: Opt,
) -> Result<(Endpoint, Connection)> {
    let relay_mode = relay_url
        .clone()
        .map_or(RelayMode::Disabled, |url| RelayMode::Custom(url.into()));
    #[allow(unused_mut)]
    let mut builder = Endpoint::builder();
    #[cfg(feature = "local-relay")]
    {
        builder = builder.insecure_skip_relay_cert_verify(relay_url.is_some());
        let path_selection = match opt.only_relay {
            true => iroh::endpoint::PathSelection::RelayOnly,
            false => iroh::endpoint::PathSelection::default(),
        };
        builder = builder.path_selection(path_selection);
    }
    let endpoint = builder
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(relay_mode)
        .transport_config(transport_config(opt.max_streams, opt.initial_mtu))
        .bind()
        .await
        .unwrap();

    if relay_url.is_some() {
        endpoint.home_relay().initialized().await?;
    }

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

    // TODO: re-enable when we upgrade quinn version
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
        while let Some(chunk) = stream.read_chunk(usize::MAX, false).await.e()? {
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

        while let Some(n) = stream.read_chunks(&mut bufs[..]).await.e()? {
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

    stream.finish().context("failed finishing stream")?;
    stream
        .stopped()
        .await
        .context("failed to wait for stream to be stopped")?;

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
        let incoming = endpoint.accept().await.unwrap();
        let connecting = match incoming.accept() {
            Ok(connecting) => connecting,
            Err(err) => {
                warn!("incoming connection failed: {err:#}");
                // we can carry on in these cases:
                // this can be caused by retransmitted datagrams
                continue;
            }
        };
        let connection = connecting.await.context("handshake failed")?;

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
                    Ok::<_, n0_snafu::Error>(())
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
