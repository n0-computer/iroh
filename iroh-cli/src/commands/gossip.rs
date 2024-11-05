//! Define the gossiping subcommands.

use std::str::FromStr as _;

use anyhow::{Context, Result};
use bao_tree::blake3;
use clap::{ArgGroup, Subcommand};
use futures_lite::StreamExt;
use futures_util::SinkExt;
use iroh::client::gossip::SubscribeOpts;
use iroh::{client::Iroh, net::NodeId};
use tokio::io::AsyncBufReadExt;

/// Commands to manage gossiping.
#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum GossipCommands {
    /// Subscribe to a gossip topic
    #[command(
        long_about = r#"Subscribe to a gossip topic

Example usage:

    $ iroh gossip subscribe --topic test --start

This will print the current node's id. Open another terminal
or another machine and you can join the same topic:

    # on another machine/terminal
    $ iroh gossip subscribe --topic test <other node_id> --start

Any lines entered in stdin will be sent to the given topic
and received messages will be printed to stdout line-by-line.

The process waits for Ctrl+C to exit."#,
        group(
            ArgGroup::new("input")
                .required(true)
                .args(&["topic", "raw_topic"])
        )
    )]
    Subscribe {
        /// The topic to subscribe to.
        ///
        /// This will be hashed with BLAKE3 to get the actual topic ID.
        #[clap(long)]
        topic: Option<String>,
        /// The raw topic to subscribe to as hex. Needs to be 32 bytes, i.e. 64 hex characters.
        #[clap(long)]
        raw_topic: Option<String>,
        /// The set of nodes that are also part of the gossip swarm to bootstrap with.
        ///
        /// If empty, this will bootstrap a new swarm. Running the command will print
        /// the node's `NodeId`, which can be used as the bootstrap argument in other nodes.
        bootstrap: Vec<String>,
        /// If enabled, all gossip events will be printed, including neighbor up/down events.
        #[clap(long, short)]
        verbose: bool,
    },
}

impl GossipCommands {
    /// Runs the gossip command given the iroh client.
    pub async fn run(self, iroh: &Iroh) -> Result<()> {
        match self {
            Self::Subscribe {
                topic,
                raw_topic,
                bootstrap,
                verbose,
            } => {
                let bootstrap = bootstrap
                    .into_iter()
                    .map(|node_id| NodeId::from_str(&node_id).map_err(|e| {
                        anyhow::anyhow!("Failed to parse bootstrap node id \"{node_id}\": {e}\nMust be a valid base32-encoded iroh node id.")
                    }))
                    .collect::<Result<_, _>>()?;

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
