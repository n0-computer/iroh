use bytes::Bytes;
use futures_lite::{Stream, StreamExt};
use iroh::client::gossip::{SubscribeResponse, TopicId};
use iroh::client::Iroh;
use iroh_net::{key::SecretKey, NodeAddr};
use testresult::TestResult;
use tracing::info;

/// Spawn an iroh node in a separate thread and tokio runtime, and return
/// the address and client.
fn spawn_node() -> (NodeAddr, Iroh) {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async move {
            let secret_key = SecretKey::generate();
            let node = iroh::node::Builder::default()
                .secret_key(secret_key)
                .spawn()
                .await?;
            let addr = node.node_addr().await?;
            sender.send((addr, node.client().clone()))?;
            node.cancel_token().cancelled().await;
            anyhow::Ok(())
        })?;
        anyhow::Ok(())
    });
    receiver.recv().unwrap()
}

/// Await `n` messages from a stream of gossip events.
async fn await_messages(
    mut stream: impl Stream<Item = anyhow::Result<SubscribeResponse>> + Unpin + Send + Sync,
    n: usize,
) -> Vec<Bytes> {
    let mut res = Vec::new();
    #[allow(clippy::single_match)]
    while let Some(msg) = stream.next().await {
        match msg.unwrap() {
            SubscribeResponse::Received(msg) => {
                res.push(msg.content);
                if res.len() >= n {
                    break;
                }
            }
            _ => {}
        }
    }
    res
}

#[tokio::test]
async fn gossip_smoke() -> TestResult {
    let _ = tracing_subscriber::fmt::try_init();

    info!("--- setup");
    let (addr1, node1) = spawn_node();
    let (addr2, node2) = spawn_node();
    let gossip1 = node1.gossip();
    let gossip2 = node2.gossip();
    node1.add_node_addr(addr2.clone()).await?;
    node2.add_node_addr(addr1.clone()).await?;

    let topic = TopicId::from([0u8; 32]);
    let mut stream1 = gossip1.subscribe(topic, [addr2.node_id]).await?;

    let mut stream2 = gossip2.subscribe(topic, [addr1.node_id]).await?;

    info!("--- waiting for connection");

    // wait for neighbour discovery on both sides
    let msg = stream1.next().await.unwrap()?;
    assert!(matches!(msg, SubscribeResponse::NeighborUp(_)));
    let msg = stream2.next().await.unwrap()?;
    assert!(matches!(msg, SubscribeResponse::NeighborUp(_)));

    info!("--- broadcasting messages 1 -> 2");

    let mut expected_msgs = Vec::new();
    for i in 0..10 {
        let msg = format!("hello1 {i}");
        gossip1.broadcast(topic, msg.clone()).await?;
        expected_msgs.push(Bytes::from(msg));
    }
    let msgs = await_messages(&mut stream2, 10).await;
    assert_eq!(msgs, expected_msgs);

    info!("--- broadcasting messages 2 -> 1");

    let mut expected_msgs = Vec::new();
    for i in 0..10 {
        let msg = format!("hello2 {i}");
        gossip2.broadcast(topic, msg.clone()).await?;
        expected_msgs.push(Bytes::from(msg));
    }
    let msgs = await_messages(&mut stream1, 10).await;
    assert_eq!(msgs, expected_msgs);

    info!("--- shutting down");

    gossip1.quit(topic).await?;
    gossip2.quit(topic).await?;

    // wait for shutdown notices on both sides
    let msg = stream1.next().await.unwrap()?;
    assert!(matches!(msg, SubscribeResponse::NeighborDown(_)));
    let msg = stream2.next().await.unwrap()?;
    assert!(matches!(msg, SubscribeResponse::NeighborDown(_)));

    Ok(())
}
