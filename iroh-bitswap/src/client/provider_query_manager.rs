use std::{collections::HashSet, sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use cid::Cid;
use futures::{stream::FuturesUnordered, StreamExt};
use iroh_metrics::{bitswap::BitswapMetrics, core::MRecorder, inc};
use libp2p::PeerId;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::warn;

use crate::network::Network;

// TODO: limit requested providers
// const MAX_PROVIDERS: usize = 10;
const MAX_IN_PROCESS_REQUESTS: usize = 6;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
enum Message {
    NewProvider {
        cid: Cid,
        response: async_channel::Sender<Result<PeerId>>,
    },
}

/// Manages requests to find more providers for blocks for bitsaqp sessions.
#[derive(Debug, Clone)]
pub struct ProviderQueryManager {
    sender: async_channel::Sender<Message>,
    workers: Arc<Vec<JoinHandle<()>>>,
}

impl ProviderQueryManager {
    pub async fn new(network: Network) -> Self {
        // Use a larger buffer to avoid blocking on this too much.
        let (provider_query_message_s, provider_query_message_r) = async_channel::bounded(1024);
        let mut workers = Vec::new();

        for _i in 0..MAX_IN_PROCESS_REQUESTS {
            let network = network.clone();
            let provider_query_message_r = provider_query_message_r.clone();

            workers.push(tokio::task::spawn(async move {
                run(network, provider_query_message_r).await
            }));
        }

        ProviderQueryManager {
            sender: provider_query_message_s,
            workers: Arc::new(workers),
        }
    }

    pub async fn stop(self) -> Result<()> {
        let workers = Arc::try_unwrap(self.workers)
            .map_err(|_| anyhow!("provider query manager refs not shutdown"))?;

        drop(self.sender);

        let results = futures::future::join_all(workers.into_iter().map(|worker| async move {
            worker.await.map_err(|e| anyhow!("worker panic: {:?}", e))?;
            Ok::<(), anyhow::Error>(())
        }))
        .await;

        for r in results {
            r?;
        }

        Ok(())
    }

    /// Retrieve providers and make sure they are dialable.
    pub async fn find_providers_async(
        &self,
        cid: &Cid,
    ) -> Result<async_channel::Receiver<Result<PeerId>>> {
        let (s, r) = async_channel::bounded(10);

        self.sender
            .send(Message::NewProvider {
                cid: *cid,
                response: s,
            })
            .await?;

        Ok(r)
    }
}

async fn run(network: Network, receiver: async_channel::Receiver<Message>) {
    loop {
        while let Ok(msg) = receiver.recv().await {
            let mut worker = None;
            match msg {
                Message::NewProvider { cid, response } => {
                    inc!(BitswapMetrics::ProviderQueryCreated);
                    match network.find_providers(cid).await {
                        Ok(providers_r) => {
                            worker = Some(tokio::task::spawn(find_provider(
                                network.clone(),
                                response,
                                providers_r,
                            )));
                        }
                        Err(err) => {
                            inc!(BitswapMetrics::ProviderQueryError);
                            if let Err(err) = response.send(Err(err)).await {
                                warn!("response channel error: {:?}", err);
                            }
                        }
                    }
                }
            }

            if let Some(worker) = worker {
                if let Err(err) = worker.await {
                    warn!("worker shutdown failed: {:?}", err);
                }
            }
        }
    }
}

async fn find_provider(
    network: Network,
    response: async_channel::Sender<Result<PeerId>>,
    mut receiver: mpsc::Receiver<std::result::Result<HashSet<PeerId>, String>>,
) {
    while let Some(providers) = receiver.recv().await {
        match providers {
            Ok(new_providers) => {
                let futures = FuturesUnordered::new();
                for provider in new_providers {
                    let response = response.clone();
                    let network = network.clone();
                    futures.push(async move {
                        if network.dial(provider, DEFAULT_TIMEOUT).await.is_ok() {
                            let _ = response.send(Ok(provider)).await;
                        }
                    });
                }
                let _ = futures.collect::<Vec<()>>().await;
            }
            Err(err) => {
                // single provider call failed just move on
                warn!("provider error: {:?}", err);
                continue;
            }
        }
    }
}
