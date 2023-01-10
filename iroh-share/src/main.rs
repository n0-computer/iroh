use std::path::PathBuf;

use anyhow::{anyhow, ensure, Result};
use clap::{Parser, Subcommand};
use futures::stream::StreamExt;
use iroh_p2p::GossipsubEvent;
use iroh_share::{ReceiverMessage, SenderMessage, Ticket};
use iroh_unixfs::chunker::ChunkerConfig;
use rand::Rng;
use tracing::{debug, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use iroh_api::{IpfsPath, UnixfsConfig, UnixfsEntry, DEFAULT_CHUNKS_SIZE};
use libp2p::gossipsub::Sha256Topic;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Sends data
    #[clap(arg_required_else_help = true)]
    Send {
        /// The data to send
        path: PathBuf,
    },
    /// Receives data
    #[clap(arg_required_else_help = true)]
    Receive {
        /// The encoded ticket string
        ticket: String,
        /// Where to write the received data to
        #[clap(long)]
        out: Option<PathBuf>,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer().pretty())
        .with(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    match args.command {
        Commands::Send { path } => {
            println!("Sending: {}", path.display());

            ensure!(path.exists(), "provided file or directory does not exist");
            ensure!(
                path.is_file() || path.is_dir(),
                "currently only supports files or directories"
            );

            // TODO: allow db specification
            let sender_dir = tempfile::tempdir().unwrap();
            let sender_db = sender_dir.path().join("db");

            println!("Starting up Iroh services...");
            let iroh = iroh_share::build_iroh(9990, &sender_db).await?;
            let entry = UnixfsEntry::from_path(
                &path,
                UnixfsConfig {
                    wrap: true,
                    chunker: Some(ChunkerConfig::Fixed(DEFAULT_CHUNKS_SIZE)),
                },
            )
            .await?;

            let mut progress = iroh.api().add_stream(entry).await?;
            let mut root = None;
            let mut num_parts = 0;
            while let Some(ev) = progress.next().await {
                let (cid, _) = ev?;
                root = Some(cid);
                num_parts += 1;
            }

            let root = root.unwrap();

            let id: u64 = rand::thread_rng().gen();
            let topic_hash = Sha256Topic::new(format!("iroh-share-{id}")).hash();
            let th = topic_hash.clone();

            let (done_sender, done_receiver) = futures::channel::oneshot::channel();

            let mut events = iroh.api().p2p()?.subscribe(topic_hash.to_string()).await?;
            let p2p = iroh.api().p2p()?;
            let gossip_task_source = tokio::task::spawn(async move {
                let mut current_peer = None;
                while let Some(Ok(e)) = events.next().await {
                    match e {
                        GossipsubEvent::Subscribed { peer_id, topic } => {
                            if topic == th && current_peer.is_none() {
                                info!("connected to {}", peer_id);
                                current_peer = Some(peer_id);

                                let start =
                                    bincode::serialize(&SenderMessage::Start { root, num_parts })
                                        .expect("serialize failure");
                                p2p.publish(topic.to_string(), start.into()).await.unwrap();
                            }
                        }
                        GossipsubEvent::Message { from, message, .. } => {
                            println!("received message from {}", from);
                            debug!("received message from {}", from);
                            if let Some(current_peer) = current_peer {
                                if from == current_peer {
                                    match bincode::deserialize(&message.data) {
                                        Ok(ReceiverMessage::FinishOk) => {
                                            println!("finished transfer");
                                            info!("finished transfer");
                                            done_sender.send(Ok(())).ok();
                                            break;
                                        }
                                        Ok(ReceiverMessage::FinishError(err)) => {
                                            println!("transfer failed: {}", err);
                                            info!("transfer failed: {}", err);
                                            done_sender.send(Err(anyhow!("{}", err))).ok();
                                            break;
                                        }
                                        Err(err) => {
                                            warn!("unexpected message: {:?}", err);
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            });

            let peer_id = iroh.api().p2p()?.peer_id().await?;
            let addrs = iroh.api().p2p()?.addrs().await?;
            info!("Available addrs: {:?}", addrs);

            let ticket = Ticket {
                peer_id,
                addrs,
                topic: topic_hash.to_string(),
            };

            let ticket_bytes = ticket.as_bytes();
            let ticket_str = multibase::encode(multibase::Base::Base64, &ticket_bytes);
            println!("Ticket:\n{ticket_str}\n");
            done_receiver.await??;
            iroh.stop().await?;
            gossip_task_source.await?;
        }
        Commands::Receive { ticket, out } => {
            println!("Receiving");

            let (_, ticket_bytes) = multibase::decode(ticket)?;
            let ticket = Ticket::from_bytes(&ticket_bytes)?;

            let sender_dir = tempfile::tempdir().unwrap();
            let sender_db = sender_dir.path().join("db");

            let port = 9991;
            let iroh = iroh_share::build_iroh(port, &sender_db).await?;
            let addrs = ticket.addrs.clone();
            iroh.api().p2p()?.connect(ticket.peer_id, addrs).await?;
            iroh.api().p2p()?.add_pubsub_peer(ticket.peer_id).await?;
            let mut events = iroh.api().p2p()?.subscribe(ticket.topic.clone()).await?;

            let (root_sender, root_receiver) = futures::channel::oneshot::channel();
            let expected_sender = ticket.peer_id;
            let gossipsub_task_source = tokio::task::spawn(async move {
                let mut root_sender = Some(root_sender);

                while let Some(Ok(ev)) = events.next().await {
                    if let GossipsubEvent::Message { from, message, .. } = ev {
                        if from == expected_sender {
                            match bincode::deserialize(&message.data) {
                                Ok(SenderMessage::Start { root, .. }) => {
                                    if let Some(root_sender) = root_sender.take() {
                                        root_sender.send(root).ok();
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
                }
            });
            let root = root_receiver.await?;
            let mut peers = std::collections::HashSet::new();
            peers.insert(expected_sender);
            let ipfs_path = IpfsPath::from_cid(root);
            match iroh.api().get_from(&ipfs_path, peers) {
                Ok(blocks) => {
                    let mut out_dir = std::env::current_dir()?;
                    if let Some(out) = out {
                        out_dir = out_dir.join(out);
                    }
                    println!("want to save to {:#?}", out_dir);
                    let msg =
                        match iroh_api::fs::write_get_stream(&ipfs_path, blocks, Some(&out_dir))
                            .await
                        {
                            Ok(p) => {
                                println!("Received all data, written to: {}", p.to_str().unwrap());
                                ReceiverMessage::FinishOk
                            }
                            Err(err) => {
                                println!("Error saving file(s): {err}");
                                ReceiverMessage::FinishError(err.to_string())
                            }
                        };
                    iroh.api()
                        .p2p()?
                        .publish(
                            ticket.topic.clone(),
                            bincode::serialize(&msg)
                                .expect("failed to serialize message")
                                .into(),
                        )
                        .await
                        .ok();
                }
                Err(e) => {
                    let msg = ReceiverMessage::FinishError(e.to_string());
                    iroh.api()
                        .p2p()?
                        .publish(
                            ticket.topic.clone(),
                            bincode::serialize(&msg)
                                .expect("failed to serialize message")
                                .into(),
                        )
                        .await
                        .ok();
                    println!("error with transfer {}", e);
                }
            }

            iroh.stop().await?;
            gossipsub_task_source.await?;
        }
    }

    Ok(())
}
