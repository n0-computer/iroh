use bytes::Bytes;
use futures_lite::{Stream, StreamExt};
use futures_util::SinkExt;
use iroh::client::Iroh;
use iroh_gossip::{
    dispatcher::{Command, Event, GossipEvent},
    proto::TopicId,
};
use iroh_net::{key::SecretKey, NodeAddr};
use testresult::TestResult;
use tokio::task::JoinHandle;

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
fn await_messages(
    mut stream: impl Stream<Item = anyhow::Result<Event>> + Unpin + Send + Sync + 'static,
    n: usize,
) -> JoinHandle<Vec<Bytes>> {
    tokio::spawn(async move {
        let mut res = Vec::new();
        #[allow(clippy::single_match)]
        while let Some(msg) = stream.next().await {
            match msg.unwrap() {
                Event::Gossip(GossipEvent::Received(msg)) => {
                    res.push(msg.content);
                    if res.len() >= n {
                        break;
                    }
                }
                _ => {}
            }
        }
        res
    })
}

#[tokio::test]
async fn gossip_smoke() -> TestResult {
    let _ = tracing_subscriber::fmt::try_init();
    let (addr1, node1) = spawn_node();
    let (addr2, node2) = spawn_node();
    let gossip1 = node1.gossip();
    let gossip2 = node2.gossip();
    node1.add_node_addr(addr2.clone()).await?;
    node2.add_node_addr(addr1.clone()).await?;
    let topic = TopicId::from([0u8; 32]);
    let (mut sink1, _stream1) = gossip1.subscribe(topic, [addr2.node_id]).await?;
    let (_sink2, stream2) = gossip2.subscribe(topic, [addr1.node_id]).await?;
    sink1.send(Command::Broadcast("hello".into())).await?;
    let msgs = await_messages(stream2, 1).await?;
    assert_eq!(msgs, vec![Bytes::from("hello")]);
    Ok(())
}

#[tokio::test]
async fn gossip_drop_sink() -> TestResult {
    let _ = tracing_subscriber::fmt::try_init();
    let (addr1, node1) = spawn_node();
    let (addr2, node2) = spawn_node();
    let gossip1 = node1.gossip();
    let gossip2 = node2.gossip();
    node1.add_node_addr(addr2.clone()).await?;
    node2.add_node_addr(addr1.clone()).await?;

    let topic = TopicId::from([0u8; 32]);

    let (mut sink1, stream1) = gossip1.subscribe(topic, [addr2.node_id]).await?;
    let (sink2, stream2) = gossip2.subscribe(topic, [addr1.node_id]).await?;

    drop(stream1);
    drop(sink2);

    sink1.send(Command::Broadcast("hello".into())).await?;
    let msgs = await_messages(stream2, 1).await?;
    assert_eq!(msgs, vec![Bytes::from("hello")]);
    Ok(())
}
