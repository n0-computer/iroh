use std::time::Instant;

use anyhow::Result;
use futures_buffered::try_join_all;
use futures_util::FutureExt;
use iroh_net::{
    endpoint::get_remote_node_id,
    key::SecretKey,
    relay::{RelayMap, RelayUrl},
    Endpoint, NodeAddr, NodeId,
};
use quinn::ConnectionError;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
};
use tracing::{error, error_span, info, Instrument, Span};

const ALPN: &[u8] = b"foo";

/// Test that add_bytes adds the right data
#[tokio::test(flavor = "multi_thread")]
async fn auth_fail() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let (relay_map, relay_url, relay_server) = iroh_net::test_utils::run_relay_server().await?;

    let endpoint_count = std::env::var("ENDPOINTS")
        .map(|x| x.parse().expect("ENDPOINTS must be a number"))
        .unwrap_or(3);

    let connects_count = std::env::var("CONNECTS")
        .map(|x| x.parse().expect("CONNECTS must be a number"))
        .unwrap_or(2);
    let accepts_count = connects_count * (endpoint_count - 1);

    info!("starting run with {endpoint_count} endpoints and {connects_count} conns/endpoint");

    let endpoints = try_join_all((0..endpoint_count).map(|i| {
        let relay_map = relay_map.clone();
        let relay_url = relay_url.clone();
        tokio::task::spawn({
            async move {
                let ep = create_endpoint(i as u8, relay_map, relay_url)
                    .await
                    .expect("failed to bind endpoint");
                let ipv4 = ep.0.bound_sockets().0;
                info!(?i, node_id=%ep.1.fmt_short(), ?ipv4, "bound endpoint");
                ep
            }
        })
    }))
    .await?;
    info!("endpoints bound");

    for a in &endpoints {
        for b in &endpoints {
            if b.1 == a.1 {
                continue;
            }
            a.0.add_node_addr(b.2.clone())?;
        }
    }

    let start = Instant::now();
    let mut tasks = JoinSet::new();

    for a in &endpoints {
        let span = error_span!("accept", me = %a.1.fmt_short());
        let span_clone = span.clone();
        tasks.spawn(
            accept_loop(a.0.clone(), accepts_count)
                .map(move |res| (span, res))
                .instrument(span_clone),
        );
        for b in &endpoints {
            if b.1 == a.1 {
                continue;
            }
            let span = error_span!("connect", me = %a.1.fmt_short(), remote = %b.1.fmt_short());
            let span_clone = span.clone();
            tasks.spawn(
                connect_loop(a.0.clone(), b.1, connects_count)
                    .map(move |res| (span, res))
                    .instrument(span_clone),
            );
        }
    }

    while let Some(res) = tasks.join_next().await {
        let (span, res) = res.expect("task panicked");
        let _guard = span.enter();
        if res.is_err() {
            error!(?res, "FAILED task");
        }
        res.expect("failed");
    }

    info!(time=?start.elapsed(), "all tasks finished, shutdown endpoints");

    // drop, we finished everything, saves test time.
    drop(endpoints);
    relay_server.shutdown().await?;
    // this would gracefully shutdown the endpoints instead:
    // try_join_all(
    //     endpoints
    //         .into_iter()
    //         .map(|(ep, _, _)| ep.close(1u32.into(), b"shutdown")),
    // )
    // .await?;
    // info!(time=?start.elapsed(), "endpoints shutdown");

    Ok(())
}

async fn create_endpoint(
    id: u8,
    relay_map: RelayMap,
    relay_url: RelayUrl,
) -> anyhow::Result<(Endpoint, NodeId, NodeAddr)> {
    let secret_key = SecretKey::from_bytes(&[id; 32]);
    // let port = 20000 + id as u16;
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(iroh_net::relay::RelayMode::Custom(relay_map))
        .insecure_skip_relay_cert_verify(true)
        .bind(0)
        .await?;
    let node_id = endpoint.node_id();
    let addr = NodeAddr::new(node_id).with_relay_url(relay_url);
    Ok((endpoint, node_id, addr))
}

async fn connect_loop(endpoint: Endpoint, node_id: NodeId, count: usize) -> Result<()> {
    let mut tasks = JoinSet::<(usize, Result<()>)>::new();
    for i in 0..count {
        let endpoint = endpoint.clone();
        let fut = async move {
            let start = Instant::now();
            info!("connect");
            let conn = endpoint.connect_by_node_id(node_id, ALPN).await?;
            info!("connected");
            let mut stream = conn.open_uni().await?;
            stream.write_u8(23).await?;
            let reason = conn.closed().await;
            match reason {
                ConnectionError::ApplicationClosed(reason) if reason.error_code == 42u32.into() => {
                    info!(?i, time=?start.elapsed(), "closed gracefully");
                    // conn.close(43u32.into(), b"bye-bye");
                    Result::<_, anyhow::Error>::Ok(())
                }
                _ => {
                    error!(?i, ?reason, "FAILED at close");
                    // conn.close(1u32.into(), b"bad-close");
                    Err(reason.into())
                }
            }
        }
        .map(move |res| (i, res))
        .instrument(error_span!("conn", i));
        tasks.spawn(fut);
    }
    while let Some(res) = tasks.join_next().await {
        let (i, res) = res.expect("connect conn task panicked");
        if res.is_err() {
            error!(i, ?res, "FAILED at connect conn");
        }
        res?;
    }
    Ok(())
}

async fn accept_loop(endpoint: Endpoint, count: usize) -> Result<()> {
    let mut tasks = JoinSet::<(usize, Result<()>)>::new();
    for i in 0..count {
        let incoming = endpoint
            .accept()
            .await
            .expect("expected incoming connection");
        let start = Instant::now();
        tasks.spawn(
            async move {
                info!(?i, "incoming");
                let conn = incoming.accept()?.await?;
                let remote = get_remote_node_id(&conn)?;
                Span::current().record("remote", tracing::field::display(&remote.fmt_short()));
                info!(?i, "accepted");
                let mut stream = conn.accept_uni().await?;
                let data = stream.read_u8().await?;
                assert_eq!(data, 23u8);
                drop(stream);
                conn.close(42u32.into(), b"bye");
                let reason = conn.closed().await;
                info!(time=?start.elapsed(), "closed");
                match reason {
                    ConnectionError::LocallyClosed => {
                        info!(?i, time=?start.elapsed(), "closed gracefully");
                        Ok(())
                    }
                    _ => {
                        error!(?i, ?reason, time=?start.elapsed(), "FAILED at close");
                        Err(reason.into())
                    }
                }
            }
            .map(move |res| (i, res))
            .instrument(error_span!("conn", i, remote = tracing::field::Empty)),
        );
    }
    while let Some(res) = tasks.join_next().await {
        let (i, res) = res.expect("accept conn task panicked");
        if res.is_err() {
            error!(i, ?res, "FAILED at accept conn");
        }
        res?;
    }

    Ok(())
}
