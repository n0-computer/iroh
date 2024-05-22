use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use quinn::{Connection, Endpoint, RecvStream, SendStream, TokioRuntime, TransportConfig};
use socket2::{Domain, Protocol, Socket, Type};
use tracing::{trace, warn};

use crate::{
    client_handler, stats::TransferResult, ClientStats, ConnectionSelector, EndpointSelector, Opt,
};

/// Derived from the iroh-net udp SOCKET_BUFFER_SIZE
const SOCKET_BUFFER_SIZE: usize = 7 << 20;
pub const ALPN: &[u8] = b"n0/quinn-bench/0";

/// Creates a server endpoint which runs on the given runtime
pub fn server_endpoint(rt: &tokio::runtime::Runtime, opt: &Opt) -> (SocketAddr, quinn::Endpoint) {
    let secret_key = iroh_net::key::SecretKey::generate();
    let crypto =
        iroh_net::tls::make_server_config(&secret_key, vec![ALPN.to_vec()], false).unwrap();

    let transport = transport_config(opt.max_streams, opt.initial_mtu);

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(Arc::new(transport));

    let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), 0);

    let socket = bind_socket(addr).unwrap();

    let _guard = rt.enter();
    rt.block_on(async move {
        let ep = quinn::Endpoint::new(
            Default::default(),
            Some(server_config),
            socket,
            Arc::new(TokioRuntime),
        )
        .unwrap();
        let addr = ep.local_addr().unwrap();
        (addr, ep)
    })
}

/// Create and run a client
pub async fn client(server_addr: SocketAddr, opt: Opt) -> Result<ClientStats> {
    let client_start = std::time::Instant::now();
    let (endpoint, connection) = connect_client(server_addr, opt).await?;
    let client_connect_time = client_start.elapsed();
    let mut res = client_handler(
        EndpointSelector::Quinn(endpoint),
        ConnectionSelector::Quinn(connection),
        opt,
    )
    .await?;
    res.connect_time = client_connect_time;
    Ok(res)
}

/// Create a client endpoint and client connection
pub async fn connect_client(
    server_addr: SocketAddr,
    opt: Opt,
) -> Result<(::quinn::Endpoint, Connection)> {
    let secret_key = iroh_net::key::SecretKey::generate();
    let tls_client_config =
        iroh_net::tls::make_client_config(&secret_key, None, vec![ALPN.to_vec()], false)?;
    let mut config = quinn::ClientConfig::new(Arc::new(tls_client_config));

    let transport = transport_config(opt.max_streams, opt.initial_mtu);

    // let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport));

    let addr = SocketAddr::new("127.0.0.1".parse().unwrap(), 0);

    let socket = bind_socket(addr).unwrap();

    let ep =
        quinn::Endpoint::new(Default::default(), None, socket, Arc::new(TokioRuntime)).unwrap();
    let connection = ep
        .connect_with(config, server_addr, "local")?
        .await
        .context("connecting")?;
    Ok((ep, connection))
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

fn bind_socket(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))
        .context("create socket")?;

    if addr.is_ipv6() {
        socket.set_only_v6(false).context("set_only_v6")?;
    }

    socket
        .bind(&socket2::SockAddr::from(addr))
        .context("binding endpoint")?;
    socket
        .set_send_buffer_size(SOCKET_BUFFER_SIZE)
        .context("send buffer size")?;
    socket
        .set_recv_buffer_size(SOCKET_BUFFER_SIZE)
        .context("recv buffer size")?;

    let buf_size = socket.send_buffer_size().context("send buffer size")?;
    if buf_size < SOCKET_BUFFER_SIZE {
        warn!(
            "Unable to set desired send buffer size. Desired: {}, Actual: {}",
            SOCKET_BUFFER_SIZE, buf_size
        );
    }

    let buf_size = socket.recv_buffer_size().context("recv buffer size")?;
    if buf_size < SOCKET_BUFFER_SIZE {
        warn!(
            "Unable to set desired recv buffer size. Desired: {}, Actual: {}",
            SOCKET_BUFFER_SIZE, buf_size
        );
    }

    Ok(socket.into())
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
                    Err(::quinn::ConnectionError::ApplicationClosed(_)) => break,
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
