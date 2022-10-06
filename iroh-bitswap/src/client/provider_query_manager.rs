use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use cid::Cid;
use libp2p::PeerId;
use tokio::{sync::oneshot, task::JoinHandle};
use tracing::warn;

use crate::network::Network;

// TODO: limit requested providers
// const MAX_PROVIDERS: usize = 10;
const MAX_IN_PROCESS_REQUESTS: usize = 6;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
enum ProviderQueryMessage {
    NewProvider {
        cid: Cid,
        response: async_channel::Sender<Result<PeerId>>,
    },
}

/// Manages requests to find more providers for blocks for bitsaqp sessions.
#[derive(Debug, Clone)]
pub struct ProviderQueryManager {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    provider_query_messages: async_channel::Sender<ProviderQueryMessage>,
    workers: Vec<(JoinHandle<()>, oneshot::Sender<()>)>,
}

impl ProviderQueryManager {
    pub async fn new(network: Network) -> Self {
        // Use a larger buffer to avoid blocking on this too much.
        let (provider_query_message_s, provider_query_message_r) = async_channel::bounded(1024);
        let mut workers = Vec::new();
        let find_provider_timeout = DEFAULT_TIMEOUT;

        let rt = tokio::runtime::Handle::current();
        for _i in 0..MAX_IN_PROCESS_REQUESTS {
            let (closer_s, mut closer_r) = oneshot::channel();
            let network = network.clone();
            let provider_query_message_r = provider_query_message_r.clone();

            let worker = rt.spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut closer_r => {
                            // Shutdown
                            break;
                        }
                        msg = provider_query_message_r.recv() => {
                            match msg {
                                Ok(ProviderQueryMessage::NewProvider { cid, response }) => {
                                   match network.find_providers(cid) {
                                        Ok(mut providers_r) => {
                                            loop {
                                                tokio::select! {
                                                    _ = &mut closer_r => {
                                                        // Closing, break the both loops
                                                        return;
                                                    }
                                                    providers = providers_r.recv() => {
                                                        match providers {
                                                            Some(Ok(providers)) => {
                                                                // TODO: parallelize?
                                                                for provider in providers {
                                                                    if network.dial(provider, find_provider_timeout).is_ok() {
                                                                        if let Err(err) = response.send(Ok(provider)).await {
                                                                            warn!("response channel error: {:?}", err);
                                                                            break;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            Some(Err(err)) => {
                                                                // single provider call failed just move on
                                                                warn!("provider error: {:?}", err);
                                                                continue;
                                                            }
                                                            None => {
                                                                // provider channel is gone
                                                                drop(response);
                                                                break;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Err(err) => {
                                            if let Err(err) = response.send(Err(err)).await {
                                                warn!("response channel error: {:?}", err);
                                            }
                                        }
                                    }
                                }
                                Err(err) => {
                                    warn!("input channel: {:?}", err);
                                    break;
                                }
                            }
                        }
                    }
                }
            });
            workers.push((worker, closer_s));
        }

        ProviderQueryManager {
            inner: Arc::new(Inner {
                provider_query_messages: provider_query_message_s,
                workers,
            }),
        }
    }

    pub async fn stop(self) -> Result<()> {
        let inner = Arc::try_unwrap(self.inner)
            .map_err(|_| anyhow!("provider query manager refs not shutdown"))?;

        let results = futures::future::join_all(inner.workers.into_iter().map(
            |(worker, closer)| async move {
                closer
                    .send(())
                    .map_err(|e| anyhow!("failed to send close"))?;
                worker.await.map_err(|e| anyhow!("worker panic: {:?}", e))?;
                Ok::<(), anyhow::Error>(())
            },
        ))
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
        let (s, r) = async_channel::bounded(8);

        self.inner
            .provider_query_messages
            .send(ProviderQueryMessage::NewProvider {
                cid: *cid,
                response: s,
            })
            .await?;

        Ok(r)
    }
}
