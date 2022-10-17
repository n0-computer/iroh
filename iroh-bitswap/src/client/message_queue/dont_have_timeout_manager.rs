use std::{
    fmt::Debug,
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::{AHashMap, AHashSet};
use anyhow::Result;
use cid::Cid;
use derivative::Derivative;
use iroh_metrics::core::MRecorder;
use iroh_metrics::{bitswap::BitswapMetrics, inc};
use libp2p::PeerId;
use tokio::{
    sync::{oneshot, Mutex},
    task::JoinHandle,
};
use tracing::debug;

use crate::{client::peer_manager::DontHaveTimeout, network::Network};

/// Used to simulate a DONT_HAVE when communicating with a peer
/// whose Bitswap client doesn't support the DONT_HAVE response
/// or it takes too long to respond.
const DONT_HAVE_TIMEOUT: Duration = Duration::from_secs(5);

const MAX_EXPECTED_WANT_PROCESS_TIME: Duration = Duration::from_secs(2);

const MAX_TIMEOUT: Duration = Duration::from_secs(7);

/// Multiplied by the average ping time to get an upper bound on
/// how long we expect to wait for a peer's response to arrive.
const PING_LATENCY_MULTIPLIER: f64 = 3.0;

/// Alpha supplied to the message latency EWMA.
const MESSAGE_LATENCY_ALPHA: f64 = 0.5;
/// To give a margin for error, the timeout is calculated as
/// messageLatencyMultiplier * message latency
const MESSAGE_LATENCY_MULTIPLIER: f64 = 2.0;

/// Keeps track of a want that has been sent and we are waiting for a response
/// or for a timeout to expire.
#[derive(Debug, Clone)]
struct PendingWant {
    cid: Cid,
    active: bool,
    sent: Instant,
}

#[derive(Debug)]
pub struct DontHaveTimeoutManager {
    max_timeout: Duration,
    message_latency_multiplier: f64,
    worker: Option<(
        async_channel::Sender<()>,
        oneshot::Sender<()>,
        JoinHandle<()>,
    )>,
    inner: Arc<Mutex<Inner>>,
}

#[derive(Derivative)]
#[derivative(Debug)]
struct Inner {
    /// The target peer we are tracking.
    target: PeerId,
    active_wants: AHashMap<Cid, PendingWant>,
    /// Queue of wants from oldest to newest.
    want_queue: Vec<PendingWant>,
    timeout: Duration,
    /// Ewma of message latency
    message_latency: LatencyEwma,
    #[derivative(Debug = "ignore")]
    on_dont_have_timeout: Arc<dyn DontHaveTimeout>,
}

impl DontHaveTimeoutManager {
    pub async fn new(target: PeerId, on_dont_have_timeout: Arc<dyn DontHaveTimeout>) -> Self {
        let inner = Arc::new(Mutex::new(Inner {
            target,
            timeout: DONT_HAVE_TIMEOUT,
            active_wants: Default::default(),
            want_queue: Default::default(),
            message_latency: LatencyEwma {
                alpha: MESSAGE_LATENCY_ALPHA,
                samples: 0,
                latency: Duration::default(),
            },
            on_dont_have_timeout,
        }));

        DontHaveTimeoutManager {
            max_timeout: MAX_TIMEOUT,
            message_latency_multiplier: MESSAGE_LATENCY_MULTIPLIER,
            inner,
            worker: None,
        }
    }

    pub async fn start(&mut self, network: Network) {
        // already running
        if self.worker.is_some() {
            return;
        }
        let (closer_s, mut closer_r) = oneshot::channel();

        // measure ping latency
        let i = self.inner.clone();
        let (trigger_s, trigger_r) = async_channel::bounded(16);
        let ts = trigger_s.clone();
        let target = i.lock().await.target;
        let worker = tokio::task::spawn(async move {
            let inner = i;

            tokio::select! {
                biased;
                _ = &mut closer_r => {
                    // shutdown
                    return;
                }
                ping = network.ping(&target) => {
                    match ping {
                        Ok(latency) => {
                            let inner = &mut *inner.lock().await;
                            if inner.message_latency.samples == 0 {
                                inner.timeout = calculate_timeout_from_ping_latency(
                                    latency,
                                    MAX_EXPECTED_WANT_PROCESS_TIME,
                                    PING_LATENCY_MULTIPLIER,
                                    MAX_TIMEOUT,
                                );

                                // update timeouts
                                ts.send(()).await.ok();
                            }
                        }
                        Err(_err) => {
                            // we leave the default timeout
                        }
                    }
                }
            }

            let delay = tokio::time::sleep(DONT_HAVE_TIMEOUT);
            tokio::pin!(delay);

            loop {
                inc!(BitswapMetrics::DontHaveTimeoutLoopTick);
                tokio::select! {
                    biased;
                    _ = &mut closer_r => {
                        // Shutdown
                        break;
                    }
                    _ = trigger_r.recv() => {
                        if let Some(next) = inner.lock().await.check_for_timeouts().await {
                            delay.as_mut().reset(tokio::time::Instant::now() + next);
                        }
                    }
                    _ = &mut delay => {
                        if let Some(next) = inner.lock().await.check_for_timeouts().await {
                            delay.as_mut().reset(tokio::time::Instant::now() + next);
                        } else {
                            delay.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(60 * 5));
                        }
                    }
                }
            }
        });

        self.worker = Some((trigger_s, closer_s, worker));
    }

    pub async fn stop(self) -> Result<()> {
        if let Some((_, closer, worker)) = self.worker {
            if closer.send(()).is_ok() {
                worker.await?;
            }
        }
        Ok(())
    }

    /// Called when we receive a response from the peer. It is the time between
    /// sending a request and receiving the corresponding response.
    pub async fn update_message_latency(&self, elapsed: Duration) {
        let inner = &mut *self.inner.lock().await;

        // Update the message latency and the timeout
        inner.message_latency.update(elapsed);
        let old_timeout = inner.timeout;
        inner.timeout = calculate_timeout_from_message_latency(
            inner.message_latency.latency,
            self.message_latency_multiplier,
            self.max_timeout,
        );

        // If the timeout has decreased
        if inner.timeout < old_timeout {
            // Check if after changing the timeout there are any pending wants
            // that are now over the timeout
            self.trigger().await;
        }
    }

    /// Adds the given keys that will expire if not cancelled before the timeout.
    pub async fn add_pending(&self, pending: &[Cid]) {
        if pending.is_empty() {
            return;
        }

        let start = Instant::now();
        let inner = &mut *self.inner.lock().await;
        debug!(
            "dh:{}: add pending: {:?}",
            inner.target,
            pending.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );

        let queue_was_empty = inner.active_wants.is_empty();

        for cid in pending {
            if !inner.active_wants.contains_key(cid) {
                let pw = PendingWant {
                    cid: *cid,
                    sent: start,
                    active: true,
                };
                inner.active_wants.insert(*cid, pw.clone());
                inner.want_queue.push(pw);
            }
        }

        // If there was alread an earlier pending item in the queue, timeouts
        // are already scheduled. Otherwise start a timeout check.
        if queue_was_empty {
            self.trigger().await;
        }
    }

    async fn trigger(&self) {
        if let Some((trigger, _, _)) = self.worker.as_ref() {
            let _ = trigger.send(()).await;
        }
    }

    /// Called when we receive a response for a key.
    pub async fn cancel_pending(&self, cancels: &AHashSet<Cid>) {
        let inner = &mut *self.inner.lock().await;

        for cid in cancels {
            if let Some(pw) = inner.active_wants.get_mut(cid) {
                pw.active = false;
                inner.active_wants.remove(cid);
            }
        }
    }
}

impl Inner {
    /// Checks pending wants to see if any are over the timeout.
    async fn check_for_timeouts(&mut self) -> Option<Duration> {
        if self.want_queue.is_empty() {
            return None;
        }
        debug!(
            "check_for_timeouts: {} ({})",
            self.target,
            self.want_queue.len()
        );

        // Figure out which of the blocks that were wanted were not received within
        // the timeout.

        let mut expired = Vec::new();
        while let Some(pw) = self.want_queue.pop() {
            // If the want is still active
            if pw.active {
                if pw.sent.elapsed() < self.timeout {
                    // Ordered from earliest to latest, so break on the first
                    // not expired entry.
                    break;
                }

                // Append to the expired list.
                expired.push(pw.cid);
                // Remove from active wants.
                self.active_wants.remove(&pw.cid);
            }
        }

        // Fire timeout
        if !expired.is_empty() {
            self.fire_timeout(expired).await;
        }

        // Schedule the next check for the moment when the oldest pending want will timeout.
        if let Some(oldest) = self.want_queue.first() {
            let oldest_start = oldest.sent;
            // TODO: verify this is  correct
            let until = (oldest_start + self.timeout) - Instant::now();

            debug!("next timeout {}s", until.as_secs_f32());
            return Some(until);
        }

        None
    }

    /// Triggers on_dont_have_timeout with matching keys.
    async fn fire_timeout(&self, pending: Vec<Cid>) {
        debug!(
            "timeout: {:?}",
            pending.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
        (self.on_dont_have_timeout)(self.target, pending).await;
    }
}

/// Tracks the EWMA of a message latency.
#[derive(Debug)]
struct LatencyEwma {
    alpha: f64,
    samples: u64,
    latency: Duration,
}

impl LatencyEwma {
    fn update(&mut self, elapsed: Duration) {
        self.samples += 1;

        // Initially set alpha to be 1.0 / <num samples>
        let mut alpha = 1.0 / self.samples as f64;
        if alpha < self.alpha {
            // Once we have enough samples, clamp alpha.
            alpha = self.alpha;
        }
        self.latency = Duration::from_secs_f64(
            elapsed.as_secs_f64() * alpha + (1. - alpha) * self.latency.as_secs_f64(),
        );
    }
}

fn calculate_timeout_from_message_latency(
    message_latency: Duration,
    message_latency_multiplier: f64,
    max_timeout: Duration,
) -> Duration {
    let timeout =
        Duration::from_secs_f64(message_latency.as_secs_f64() * message_latency_multiplier);

    if timeout > max_timeout {
        return max_timeout;
    }

    timeout
}

fn calculate_timeout_from_ping_latency(
    latency: Duration,
    max_expected_want_process_time: Duration,
    ping_latency_multiplier: f64,
    max_timeout: Duration,
) -> Duration {
    // The maximum expected time for a response is the expected time to process the
    // want + (latency * multiplier).
    // The multiplier is to provide some padding for variable latency.
    let timeout = Duration::from_secs_f64(
        max_expected_want_process_time.as_secs_f64()
            + ping_latency_multiplier * latency.as_secs_f64(),
    );
    if timeout > max_timeout {
        return max_timeout;
    }

    timeout
}
