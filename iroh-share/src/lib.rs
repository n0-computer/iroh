use std::{collections::HashSet, path::Path, sync::Arc};

use anyhow::{bail, ensure, Result};
use async_channel::Receiver;
use async_trait::async_trait;
use cid::Cid;
use iroh_metrics::store::Metrics;
use iroh_p2p::{config, Keychain, MemoryStorage, NetworkEvent, Node};
use iroh_resolver::{
    parse_links,
    resolver::{ContentLoader, LoadedCid, Resolver, Source, IROH_STORE},
    verify_hash,
};
use iroh_rpc_client::Client;
use libp2p::{Multiaddr, PeerId};
use prometheus_client::registry::Registry;
use serde::{Deserialize, Serialize};
use tokio::{sync::Mutex, task::JoinHandle};
use tracing::{debug, error, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ticket {
    pub peer_id: PeerId,
    pub addrs: Vec<Multiaddr>,
    pub topic: String,
}

struct P2pNode {
    p2p_task: JoinHandle<()>,
    store_task: JoinHandle<()>,
    rpc: Client,
    resolver: Resolver<Loader>,
}

/// Wrapper struct to implement custom content loading
#[derive(Debug, Clone)]
struct Loader {
    client: Client,
    providers: Arc<Mutex<HashSet<PeerId>>>,
}

impl Loader {
    pub fn new(client: Client) -> Self {
        Loader {
            client,
            providers: Arc::new(Mutex::new(HashSet::new())),
        }
    }
}

#[async_trait]
impl ContentLoader for Loader {
    async fn load_cid(&self, cid: &Cid) -> Result<LoadedCid> {
        let cid = *cid;
        match self.client.store.get(cid).await {
            Ok(Some(data)) => {
                return Ok(LoadedCid {
                    data,
                    source: Source::Store(IROH_STORE),
                });
            }
            Ok(None) => {}
            Err(err) => {
                warn!("failed to fetch data from store {}: {:?}", cid, err);
            }
        }

        let providers = self.providers.lock().await.clone();
        ensure!(!providers.is_empty(), "no providers supplied");

        let bytes = self.client.p2p.fetch_bitswap(cid, providers).await?;

        // TODO: is this the right place?
        // verify cid
        let bytes_clone = bytes.clone();
        match tokio::task::spawn_blocking(move || verify_hash(&cid, &bytes_clone)).await? {
            Some(true) => {
                // all good
            }
            Some(false) => {
                bail!("invalid hash {:?}", cid.hash());
            }
            None => {
                warn!(
                    "unable to verify hash, unknown hash function {} for {}",
                    cid.hash().code(),
                    cid
                );
            }
        }

        // trigger storage in the background
        let cloned = bytes.clone();
        let rpc = self.clone();
        tokio::spawn(async move {
            let clone2 = cloned.clone();
            let links =
                tokio::task::spawn_blocking(move || parse_links(&cid, &clone2).unwrap_or_default())
                    .await
                    .unwrap_or_default();

            let len = cloned.len();
            let links_len = links.len();
            match rpc.client.store.put(cid, cloned, links).await {
                Ok(_) => debug!("stored {} ({}bytes, {}links)", cid, len, links_len),
                Err(err) => {
                    warn!("failed to store {}: {:?}", cid, err);
                }
            }
        });

        Ok(LoadedCid {
            data: bytes,
            source: Source::Bitswap,
        })
    }
}

impl P2pNode {
    pub async fn new(
        port: u16,
        rpc_p2p_port: u16,
        rpc_store_port: u16,
        db_path: &Path,
    ) -> Result<(Self, Receiver<NetworkEvent>)> {
        let rpc_p2p_addr = format!("0.0.0.0:{rpc_p2p_port}").parse().unwrap();
        let rpc_store_addr = format!("0.0.0.0:{rpc_store_port}").parse().unwrap();
        let rpc_client_config = iroh_rpc_client::Config {
            p2p_addr: rpc_p2p_addr,
            store_addr: rpc_store_addr,
            ..Default::default()
        };
        let config = config::Libp2pConfig {
            listening_multiaddr: format!("/ip4/0.0.0.0/tcp/{port}").parse().unwrap(),
            bootstrap_peers: Default::default(),
            mdns: true,
            rpc_addr: rpc_p2p_addr,
            rpc_client: rpc_client_config.clone(),
            ..Default::default()
        };

        let rpc = Client::new(&config.rpc_client).await?;
        let loader = Loader::new(rpc.clone());
        let mut prom_registry = Registry::default();
        let resolver = iroh_resolver::resolver::Resolver::new(loader, &mut prom_registry);

        let store_config = iroh_store::Config {
            path: db_path.to_path_buf(),
            rpc_addr: rpc_store_addr,
            rpc_client: rpc_client_config.clone(),
            metrics: Default::default(),
        };

        let store_metrics = Metrics::new(&mut prom_registry);
        let store = if store_config.path.exists() {
            iroh_store::Store::open(store_config, store_metrics).await?
        } else {
            iroh_store::Store::create(store_config, store_metrics).await?
        };

        let kc = Keychain::<MemoryStorage>::new();
        let mut p2p = Node::new(config, kc, &mut prom_registry).await?;
        let events = p2p.network_events();

        let p2p_task = tokio::task::spawn(async move {
            if let Err(err) = p2p.run().await {
                error!("{:?}", err);
            }
        });

        let store_task =
            tokio::spawn(async move { iroh_store::rpc::new(rpc_store_addr, store).await.unwrap() });

        Ok((
            Self {
                p2p_task,
                store_task,
                rpc,
                resolver,
            },
            events,
        ))
    }
}

impl Drop for P2pNode {
    fn drop(&mut self) {
        self.p2p_task.abort();
        self.store_task.abort();
    }
}

pub mod sender {
    use std::path::Path;
    use std::sync::atomic::AtomicU64;

    use anyhow::{Context, Result};
    use async_channel::{bounded, Receiver};
    use bytes::Bytes;
    use cid::Cid;
    use futures::channel::oneshot::{channel as oneshot, Receiver as OneShotReceiver};
    use futures::StreamExt;
    use iroh_p2p::{GossipsubEvent, NetworkEvent};
    use libp2p::gossipsub::{Sha256Topic, TopicHash};
    use libp2p::PeerId;
    use tracing::{error, info};

    use crate::P2pNode;

    use super::Ticket;

    /// The sending part of the data transfer.
    pub struct Sender {
        p2p: P2pNode,
        next_id: AtomicU64,
        gossip_events: Receiver<GossipsubEvent>,
    }

    impl Sender {
        pub async fn new(
            port: u16,
            rpc_p2p_port: u16,
            rpc_store_port: u16,
            db_path: &Path,
        ) -> Result<Self> {
            let (p2p, events) = P2pNode::new(port, rpc_p2p_port, rpc_store_port, db_path).await?;
            let (s, r) = bounded(1024);

            tokio::task::spawn(async move {
                while let Ok(event) = events.recv().await {
                    match event {
                        NetworkEvent::Gossipsub(e) => {
                            // drop events if they are not processed
                            s.try_send(e).ok();
                        }
                        _ => {}
                    }
                }
            });

            Ok(Sender {
                p2p,
                next_id: 0.into(),
                gossip_events: r,
            })
        }

        pub async fn transfer_from_data(
            &self,
            name: impl Into<String>,
            data: Bytes,
        ) -> Result<Transfer<'_>> {
            let id = self.next_id();
            let t = Sha256Topic::new(format!("iroh-share-{}", id));
            let name = name.into();

            let (s, r) = oneshot();

            let root = {
                // wrap in directory to preserve t
                let mut root_dir = iroh_resolver::unixfs_builder::DirectoryBuilder::new();
                let mut file = iroh_resolver::unixfs_builder::FileBuilder::new();
                file.name(&name).content_bytes(data);
                let file = file.build().await?;
                root_dir.add_file(file);
                let root_dir = root_dir.build().await?;
                let parts = root_dir.encode();
                tokio::pin!(parts);
                let mut root_cid = None;
                while let Some(part) = parts.next().await {
                    // TODO: store links in the store
                    let (cid, bytes) = part?;
                    root_cid = Some(cid);
                    info!("storing {:?}", cid);
                    self.p2p.rpc.store.put(cid, bytes, vec![]).await?;
                }
                root_cid.unwrap()
            };

            let gossip_events = self.gossip_events.clone();
            let topic_hash = t.hash();
            let th = topic_hash.clone();
            tokio::task::spawn(async move {
                while let Ok(event) = gossip_events.recv().await {
                    match event {
                        GossipsubEvent::Subscribed { peer_id, topic } => {
                            if topic == th {
                                s.send(peer_id).ok();
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            });

            Ok(Transfer {
                id,
                topic: topic_hash,
                sender: self,
                name,
                root,
                peer: r,
            })
        }

        fn next_id(&self) -> u64 {
            self.next_id
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        }
    }

    pub struct Transfer<'a> {
        id: u64,
        name: String,
        root: Cid,
        sender: &'a Sender,
        peer: OneShotReceiver<PeerId>,
        topic: TopicHash,
    }

    impl Transfer<'_> {
        pub async fn ticket(self) -> Result<Ticket> {
            let (peer_id, addrs) = self
                .sender
                .p2p
                .rpc
                .p2p
                .get_listening_addrs()
                .await
                .context("getting p2p info")?;

            let root = self.root.to_bytes().to_vec(); // TODO: actual root hash.
            let peer = self.peer;
            let topic = self.topic;
            let topic_string = topic.to_string();
            let rpc = self.sender.p2p.rpc.clone();

            tokio::task::spawn(async move {
                match peer.await {
                    Ok(peer_id) => {
                        println!("S: {:?} subscribed, publishing root", peer_id);
                        rpc.p2p.gossipsub_publish(topic, root.into()).await.unwrap();
                    }
                    Err(e) => {
                        error!("failed to receive root, transfer aborted: {:?}", e);
                    }
                }
            });

            Ok(Ticket {
                peer_id,
                addrs,
                topic: topic_string,
            })
        }
    }
}

pub mod receiver {
    use anyhow::{anyhow, ensure, Result};
    use async_channel::{bounded, Receiver as ChannelReceiver};
    use cid::Cid;
    use futures::StreamExt;
    use iroh_p2p::NetworkEvent;
    use iroh_resolver::resolver::Path;
    use libp2p::gossipsub::{GossipsubMessage, MessageId, TopicHash};
    use libp2p::PeerId;
    use tokio::io::AsyncReadExt;
    use tracing::warn;

    use crate::P2pNode;

    use super::Ticket;

    pub struct Receiver {
        p2p: P2pNode,
        gossip_messages: ChannelReceiver<(MessageId, PeerId, GossipsubMessage)>,
    }

    impl Receiver {
        pub async fn new(
            port: u16,
            rpc_p2p_port: u16,
            rpc_store_port: u16,
            db_path: &std::path::Path,
        ) -> Result<Self> {
            let (p2p, events) = P2pNode::new(port, rpc_p2p_port, rpc_store_port, db_path).await?;
            let (s, r) = bounded(1024);

            tokio::task::spawn(async move {
                while let Ok(event) = events.recv().await {
                    match event {
                        NetworkEvent::Gossipsub(iroh_p2p::GossipsubEvent::Message {
                            from,
                            id,
                            message,
                        }) => {
                            s.try_send((id, from, message)).ok();
                        }
                        _ => {}
                    }
                }
            });

            Ok(Receiver {
                p2p,
                gossip_messages: r,
            })
        }

        pub async fn transfer_from_ticket(&self, ticket: Ticket) -> Result<Transfer<'_>> {
            // Connect to the sender
            self.p2p
                .rpc
                .p2p
                .connect(ticket.peer_id, ticket.addrs.clone())
                .await?;
            self.p2p
                .rpc
                .p2p
                .gossipsub_add_explicit_peer(ticket.peer_id)
                .await?;
            let topic = TopicHash::from_raw(&ticket.topic);
            self.p2p.rpc.p2p.gossipsub_subscribe(topic.clone()).await?;
            let gossip_messages = self.gossip_messages.clone();
            let expected_sender = ticket.peer_id;
            let resolver = self.p2p.resolver.clone();
            let (s, r) = bounded(1024);

            // add provider
            resolver
                .loader()
                .providers
                .lock()
                .await
                .insert(expected_sender);

            tokio::task::spawn(async move {
                while let Ok((_id, from, message)) = gossip_messages.recv().await {
                    if from == expected_sender {
                        match Cid::try_from(message.data) {
                            Ok(root) => {
                                println!("R: got root {:?}, from: {:?}", root, from);
                                // TODO: resolve recursively
                                let results = resolver.resolve_recursive(
                                    iroh_resolver::resolver::Path::from_cid(root),
                                );
                                tokio::pin!(results);
                                while let Some(res) = results.next().await {
                                    s.send(res).await.unwrap();
                                }
                            }
                            Err(err) => {
                                warn!("got unexpected message from {}: {:?}", from, err);
                            }
                        }
                    } else {
                        warn!("got message from unexpected sender: {:?}", from);
                    }
                }
            });

            Ok(Transfer {
                receiver: self,
                ticket,
                topic,
                data_receiver: r,
            })
        }
    }

    pub struct Transfer<'a> {
        ticket: Ticket,
        receiver: &'a Receiver,
        topic: TopicHash,
        data_receiver: ChannelReceiver<Result<iroh_resolver::resolver::Out>>,
    }

    impl Transfer<'_> {
        pub async fn recv(&self) -> Result<Data> {
            // TODO: load not just the root
            let res = self.data_receiver.recv().await??;
            // TODO: notification
            // we expect unixfs
            let files: Vec<_> = res
                .unixfs_read_dir()
                .ok_or_else(|| anyhow!("unexpected data format"))?
                .collect::<Result<_>>()?;
            ensure!(files.len() == 1, "expected only one file to be sent");
            let file = &files[0];
            let name = file.name.map(Into::into).unwrap_or_default();

            // grab the actual file
            let file_res = self
                .receiver
                .p2p
                .resolver
                .resolve(Path::from_cid(file.cid))
                .await?;

            let mut reader = file_res.pretty(self.receiver.p2p.rpc.clone(), Default::default());
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await?;

            Ok(Data { name, bytes })
        }
    }

    pub struct Data {
        name: String,
        bytes: Vec<u8>,
    }

    impl Data {
        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn bytes(&self) -> &[u8] {
            &self.bytes
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use anyhow::{Context, Result};
    use bytes::Bytes;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    use receiver as r;
    use sender as s;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_transfer() -> Result<()> {
        tracing_subscriber::registry()
            .with(fmt::layer().pretty())
            .with(EnvFilter::from_default_env())
            .init();

        let sender_dir = tempfile::tempdir().unwrap();
        let sender_db = sender_dir.path().join("db");

        let sender = s::Sender::new(9990, 5550, 5560, &sender_db)
            .await
            .context("s:new")?;
        let bytes = Bytes::from(vec![1u8; 5 * 1024]);
        let sender_transfer = sender
            .transfer_from_data("foo.jpg", bytes.clone())
            .await
            .context("s: transfer")?;
        let ticket = sender_transfer.ticket().await.context("s: ticket")?;

        // the ticket is serialized, shared with the receiver and deserialized there
        let receiver_dir = tempfile::tempdir().unwrap();
        let receiver_db = receiver_dir.path().join("db");
        let receiver = r::Receiver::new(9991, 5551, 5561, &receiver_db)
            .await
            .context("r: new")?;

        // tries to discover the sender, and receive the root
        let receiver_transfer = receiver
            .transfer_from_ticket(ticket)
            .await
            .context("r: transfer")?;

        tokio::time::sleep(Duration::from_secs(1)).await;

        let data = receiver_transfer.recv().await.context("r: recv")?;
        assert_eq!(data.bytes(), &bytes);
        assert_eq!(data.name(), "foo.jpg");

        Ok(())
    }
}
