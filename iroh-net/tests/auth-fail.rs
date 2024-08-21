use std::time::Instant;

use anyhow::Result;
use iroh_net::{
    endpoint::get_remote_node_id,
    key::SecretKey,
    relay::{RelayMap, RelayUrl},
    Endpoint, NodeAddr, NodeId,
};
use quinn::ConnectionError;
use tokio::task::JoinSet;
use tracing::{error, info};

const ALPN: &[u8] = b"foo";

#[tokio::test(flavor = "multi_thread")]
async fn auth_fail() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let (relay_map, relay_url, relay_server) = iroh_net::test_utils::run_relay_server().await?;

    let connects_count = 1;
    let accepts_count = 1;

    info!("starting run with 2 endpoints and {connects_count} conns/endpoint");

    let ((ep1, node1, addr1), (ep2, node2, addr2)) = tokio::try_join!(
        create_endpoint(1, relay_map.clone(), relay_url.clone()),
        create_endpoint(2, relay_map.clone(), relay_url.clone())
    )?;

    ep1.add_node_addr(addr2)?;
    ep2.add_node_addr(addr1)?;

    let start = Instant::now();
    let mut tasks = JoinSet::new();
    tasks.spawn(accept_loop(ep1.clone(), accepts_count));
    tasks.spawn(accept_loop(ep2.clone(), accepts_count));

    tasks.spawn(connect_loop(ep1.clone(), node2, connects_count));
    tasks.spawn(connect_loop(ep2.clone(), node1, connects_count));

    while let Some(res) = tasks.join_next().await {
        res.expect("task panicked").expect("task failed");
    }

    info!(time=?start.elapsed(), "all tasks finished");
    relay_server.shutdown().await?;
    Ok(())
}

async fn create_endpoint(
    id: u8,
    relay_map: RelayMap,
    relay_url: RelayUrl,
) -> anyhow::Result<(Endpoint, NodeId, NodeAddr)> {
    let secret_key = SecretKey::from_bytes(&[id; 32]);
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(iroh_net::relay::RelayMode::Custom(relay_map))
        .insecure_skip_relay_cert_verify(true)
        .bind(0)
        .await?;
    let node_id = endpoint.node_id();
    let addr = NodeAddr::new(node_id).with_relay_url(relay_url);
    let ipv4 = endpoint.bound_sockets().0;
    info!(node_id=%node_id.fmt_short(), ?ipv4, "bound endpoint");
    Ok((endpoint, node_id, addr))
}

async fn connect_loop(endpoint: Endpoint, node_id: NodeId, count: usize) -> Result<()> {
    for i in 0..count {
        let endpoint = endpoint.clone();
        let fut = async move {
            info!(me=%endpoint.node_id().fmt_short(), peer=%node_id.fmt_short(), ?i, "connect start");
            let conn = endpoint.connect_by_node_id(node_id, ALPN).await?;
            info!(me=%endpoint.node_id().fmt_short(), peer=%node_id.fmt_short(), ?i, "connect established");
            let reason = conn.closed().await;
            match reason {
                ConnectionError::ApplicationClosed(reason) if reason.error_code == 42u32.into() => {
                    info!(me=%endpoint.node_id().fmt_short(), peer=%node_id.fmt_short(), i, "connect closed");
                    Result::<_, anyhow::Error>::Ok(())
                }
                _ => {
                    error!(?i, ?reason, "FAILED at close");
                    Err(reason.into())
                }
            }
        };
        fut.await.expect("connect future failed");
    }
    Ok(())
}

async fn accept_loop(endpoint: Endpoint, count: usize) -> Result<()> {
    for i in 0..count {
        let incoming = endpoint
            .accept()
            .await
            .expect("expected incoming connection");
        let start = Instant::now();
        info!(me=%endpoint.node_id().fmt_short(), ?i, "accept incoming");
        let conn = incoming.accept()?.await?;
        let remote = get_remote_node_id(&conn)?;
        info!(me=%endpoint.node_id().fmt_short(), peer=%remote.fmt_short(), ?i, "accept established");
        conn.close(42u32.into(), b"bye");
        let reason = conn.closed().await;
        match reason {
            ConnectionError::LocallyClosed => {
                info!(me=%endpoint.node_id().fmt_short(), peer=%remote.fmt_short(), ?i, "accept closed");
            }
            _ => {
                error!(?i, ?reason, time=?start.elapsed(), "FAILED at close");
                return Err(reason.into());
            }
        }
    }

    Ok(())
}
