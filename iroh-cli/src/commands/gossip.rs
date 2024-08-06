use anyhow::{Context, Result};
use bao_tree::blake3;
use clap::{ArgGroup, Subcommand};
use futures_lite::StreamExt;
use futures_util::SinkExt;
use iroh::client::gossip::SubscribeOpts;
use iroh::client::Iroh;
use iroh::net::NodeId;
use tokio::io::AsyncBufReadExt;

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
                let topic = match (topic, raw_topic) {
                    (Some(topic), None) => blake3::hash(topic.as_bytes()).into(),
                    (None, Some(raw_topic)) => {
                        let mut slice = [0; 32];
                        hex::decode_to_slice(raw_topic, &mut slice)
                            .context("failed to decode raw topic")?;
                        slice.into()
                    }
                    _ => anyhow::bail!("either topic or raw_topic must be provided"),
                };
                // blake3::hash(topic.as_ref()).into();
                let opts = SubscribeOpts {
                    bootstrap,
                    subscription_capacity: 1024,
                };

                let (mut sink, mut stream) = iroh.gossip().subscribe_with_opts(topic, opts).await?;
                let mut input_lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
                loop {
                    tokio::select! {
                        line = input_lines.next_line() => {
                            let line = line.context("failed to read from stdin")?;
                            if let Some(line) = line {
                                sink.send(iroh_gossip::net::Command::Broadcast(line.into())).await?;
                            } else {
                                break;
                            }
                        }
                        res = stream.next() => {
                            let res = res.context("gossip stream ended")?.context("failed to read gossip stream")?;
                            match res {
                                iroh_gossip::net::Event::Gossip(event) => {
                                    if verbose {
                                        println!("{:?}", event);
                                    } else if let iroh_gossip::net::GossipEvent::Received(iroh_gossip::net::Message { content, .. }) = event {
                                        println!("{:?}", content);
                                    }
                                }
                                iroh_gossip::net::Event::Lagged => {
                                    anyhow::bail!("gossip stream lagged");
                                }
                            };
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
