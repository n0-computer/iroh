use std::{sync::Arc, thread::JoinHandle, time::Duration};

use anyhow::Result;
use cid::Cid;
use crossbeam::channel::{Receiver, Sender};
use libp2p::PeerId;
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
        response: Sender<Result<PeerId>>,
    },
}

/// Manages requests to find more providers for blocks for bitsaqp sessions.
#[derive(Debug, Clone)]
pub struct ProviderQueryManager {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    provider_query_messages: Sender<ProviderQueryMessage>,
    workers: Vec<(JoinHandle<()>, Sender<()>)>,
}

impl ProviderQueryManager {
    pub fn new(network: Network) -> Self {
        // Use a larger buffer to avoid blocking on this too much.
        let (provider_query_message_s, provider_query_message_r) =
            crossbeam::channel::bounded(1024);
        let mut workers = Vec::new();
        let find_provider_timeout = DEFAULT_TIMEOUT;

        for _i in 0..MAX_IN_PROCESS_REQUESTS {
            let (closer_s, closer_r) = crossbeam::channel::bounded(1);
            let network = network.clone();
            let provider_query_message_r = provider_query_message_r.clone();

            let worker = std::thread::spawn(move || {
                loop {
                    crossbeam::channel::select! {
                        recv(closer_r) -> _ => {
                            break;
                        }
                        recv(provider_query_message_r) -> msg => {
                            match msg {
                                Ok(ProviderQueryMessage::NewProvider { cid, response }) => {
                                   match network.find_providers(cid) {
                                        Ok(providers_r) => {
                                            loop {
                                                crossbeam::channel::select! {
                                                    recv(closer_r) -> _ => {
                                                        // Closing, break the both loops
                                                        return;
                                                    }
                                                    recv(providers_r) -> providers => {
                                                        match providers {
                                                            Ok(Ok(providers)) => {
                                                                // TODO: parallelize?
                                                                for provider in providers {
                                                                    if network.dial(provider, find_provider_timeout).is_ok() {
                                                                        if let Err(err) = response.send(Ok(provider)) {
                                                                            warn!("response channel error: {:?}", err);
                                                                            break;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            Ok(Err(err)) => {
                                                                // single provider call failed just move on
                                                                warn!("provider error: {:?}", err);
                                                                continue;
                                                            }
                                                            Err(_) => {
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
                                            if let Err(err) = response.send(Err(err)) {
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

    /// Retrieve providers and make sure they are dialable.
    pub fn find_providers_async(&self, cid: &Cid) -> Result<Receiver<Result<PeerId>>> {
        let (s, r) = crossbeam::channel::bounded(8);

        self.inner
            .provider_query_messages
            .send(ProviderQueryMessage::NewProvider {
                cid: *cid,
                response: s,
            })?;

        Ok(r)
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        while let Some((worker, closer)) = self.workers.pop() {
            closer.send(()).ok();
            worker.join().expect("worker paniced");
        }
    }
}
