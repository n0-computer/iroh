use bytes::Bytes;
use futures_lite::{Stream, StreamExt};
use futures_util::SinkExt;
use iroh::client::{gossip::SubscribeOpts, Iroh};
use iroh_gossip::{
    dispatcher::{Command, Event, GossipEvent},
    proto::TopicId,
};
use iroh_net::{key::SecretKey, NodeAddr};
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
            let addr = node.my_addr().await?;
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
async fn gossip_smoke() {
    let _ = tracing_subscriber::fmt::try_init();
    let (addr1, node1) = spawn_node();
    let (addr2, node2) = spawn_node();
    let gossip1 = node1.gossip();
    let gossip2 = node2.gossip();
    let topic = TopicId::from([0u8; 32]);
    let (mut sink1, _stream2) = gossip1
        .subscribe_with_opts(
            topic,
            SubscribeOpts {
                bootstrap: [addr2.node_id].into_iter().collect(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (_sink2, stream2) = gossip2
        .subscribe_with_opts(
            topic,
            SubscribeOpts {
                bootstrap: [addr1.node_id].into_iter().collect(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    sink1
        .send(Command::Broadcast("hello".into()))
        .await
        .unwrap();
    let msgs = await_messages(stream2, 1).await.unwrap();
    assert_eq!(msgs, vec![Bytes::from("hello")]);
}
