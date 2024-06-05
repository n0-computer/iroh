use anyhow::{Context, Result};
use bao_tree::blake3;
use clap::Subcommand;
use futures_lite::StreamExt;
use futures_util::SinkExt;
use iroh::client::{Iroh, RpcService};
use iroh::net::NodeId;
use quic_rpc::ServiceConnection;
use tokio::io::AsyncBufReadExt;

#[derive(Subcommand, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum GossipCommands {
    /// Subscribe to a topic
    Subscribe {
        #[clap(long)]
        topic: String,
        bootstrap: Vec<NodeId>,
        #[clap(long, short)]
        verbose: bool,
    },
}

impl GossipCommands {
    pub async fn run<C>(self, iroh: &Iroh<C>) -> Result<()>
    where
        C: ServiceConnection<RpcService>,
    {
        match self {
            Self::Subscribe {
                topic,
                bootstrap,
                verbose,
            } => {
                let bootstrap = bootstrap.into_iter().collect();
                let topic = blake3::hash(topic.as_ref()).into();

                let (mut sink, mut stream) = iroh.gossip.subscribe(topic, bootstrap).await?;
                let mut input_lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
                loop {
                    tokio::select! {
                        line = input_lines.next_line() => {
                            let line = line.context("failed to read from stdin")?;
                            if let Some(line) = line {
                                sink.send(iroh_gossip::dispatcher::Command::Broadcast(line.into())).await?;
                            } else {
                                break;
                            }
                        }
                        res = stream.next() => {
                            let res = res.context("gossip stream ended")?.context("failed to read gossip stream")?;
                            match res {
                                iroh_gossip::dispatcher::Event::Gossip(event) => {
                                    if verbose {
                                        println!("{:?}", event);
                                    } else if let iroh_gossip::dispatcher::GossipEvent::Received(iroh_gossip::dispatcher::Message { content, .. }) = event {
                                        println!("{:?}", content);
                                    }
                                }
                                iroh_gossip::dispatcher::Event::Lagged => {
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
