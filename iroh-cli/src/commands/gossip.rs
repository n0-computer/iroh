use anyhow::{Context, Result};
use bao_tree::blake3;
use clap::{ArgGroup, Subcommand};
use futures_lite::StreamExt;
use iroh::client::gossip::{SubscribeOpts, TopicId};
use iroh::client::Iroh;
use iroh::net::NodeId;

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum GossipCommands {
    /// Subscribe to a topic
    #[command(group(
        ArgGroup::new("input")
            .required(true)
            .args(&["topic", "raw_topic"])
    ))]
    Subscribe {
        /// Topic string to subscribe to.
        ///
        /// This will be hashed with BLAKE3 to get the actual topic ID.
        #[clap(long)]
        topic: Option<String>,
        /// The raw topic to subscribe to as hex. Needs to be 32 bytes, i.e. 64 hex characters.
        #[clap(long)]
        raw_topic: Option<String>,
        bootstrap: Vec<NodeId>,
        #[clap(long, short)]
        verbose: bool,
    },
    /// Broadcast this message.
    #[command(group(
        ArgGroup::new("input")
            .required(true)
            .args(&["topic", "raw_topic"])
    ))]
    Broadcast {
        /// Topic string to subscribe to.
        ///
        /// This will be hashed with BLAKE3 to get the actual topic ID.
        #[clap(long)]
        topic: Option<String>,
        /// The raw topic to subscribe to as hex. Needs to be 32 bytes, i.e. 64 hex characters.
        #[clap(long)]
        raw_topic: Option<String>,
        /// The message to send.
        message: String,
    },
    /// Broadcast this message to neighbours.
    #[command(group(
        ArgGroup::new("input")
            .required(true)
            .args(&["topic", "raw_topic"])
    ))]
    BroadcastNeighbours {
        /// Topic string to subscribe to.
        ///
        /// This will be hashed with BLAKE3 to get the actual topic ID.
        #[clap(long)]
        topic: Option<String>,
        /// The raw topic to subscribe to as hex. Needs to be 32 bytes, i.e. 64 hex characters.
        #[clap(long)]
        raw_topic: Option<String>,
        /// The message to send.
        message: String,
    },
    /// Remove all subscriptions
    #[command(group(
        ArgGroup::new("input")
            .required(true)
            .args(&["topic", "raw_topic"])
    ))]
    Quit {
        /// Topic string to subscribe to.
        ///
        /// This will be hashed with BLAKE3 to get the actual topic ID.
        #[clap(long)]
        topic: Option<String>,
        /// The raw topic to subscribe to as hex. Needs to be 32 bytes, i.e. 64 hex characters.
        #[clap(long)]
        raw_topic: Option<String>,
    },
}

impl GossipCommands {
    pub async fn run(self, iroh: &Iroh) -> Result<()> {
        match self {
            Self::Subscribe {
                topic,
                raw_topic,
                bootstrap,
                verbose,
            } => {
                let bootstrap = bootstrap.into_iter().collect();
                let topic = generate_topic(topic, raw_topic)?;

                // blake3::hash(topic.as_ref()).into();
                let opts = SubscribeOpts {
                    bootstrap,
                    subscription_capacity: 1024,
                };

                let mut stream = iroh.gossip().subscribe_with_opts(topic, opts).await?;
                loop {
                    tokio::select! {
                        res = stream.next() => {
                            let event = res.context("gossip stream ended")?.context("failed to read gossip stream")?;
                            if verbose {
                                println!("{:?}", event);
                            } else if let iroh::client::gossip::SubscribeResponse::Received(msg) = event {
                                println!("{:?}", msg.content);
                            }
                        }
                    }
                }
            }
            Self::Broadcast {
                topic,
                raw_topic,
                message,
            } => {
                let topic = generate_topic(topic, raw_topic)?;
                iroh.gossip().broadcast(topic, message).await?;
            }
            Self::BroadcastNeighbours {
                topic,
                raw_topic,
                message,
            } => {
                let topic = generate_topic(topic, raw_topic)?;
                iroh.gossip().broadcast_neighbours(topic, message).await?;
            }
            Self::Quit { topic, raw_topic } => {
                let topic = generate_topic(topic, raw_topic)?;
                iroh.gossip().quit(topic).await?;
            }
        }
        Ok(())
    }
}

fn generate_topic(topic: Option<String>, raw_topic: Option<String>) -> Result<TopicId> {
    match (topic, raw_topic) {
        (Some(topic), None) => Ok(blake3::hash(topic.as_bytes()).into()),
        (None, Some(raw_topic)) => {
            let mut slice = [0; 32];
            hex::decode_to_slice(raw_topic, &mut slice).context("failed to decode raw topic")?;
            Ok(slice.into())
        }
        _ => anyhow::bail!("either topic or raw_topic must be provided"),
    }
}
