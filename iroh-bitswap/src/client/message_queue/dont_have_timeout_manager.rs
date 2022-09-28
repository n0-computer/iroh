use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use ahash::{AHashMap, AHashSet};
use anyhow::{anyhow, Result};
use cid::Cid;
use crossbeam::channel::Sender;
use libp2p::PeerId;
use tracing::warn;

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

#[derive(Clone)]
pub struct DontHaveTimeoutManager {
    /// The target peer we are tracking.
    target: PeerId,
    default_timeout: Duration,
    max_timeout: Duration,
    ping_latency_multiplier: f64,
    message_latency_multiplier: f64,
    max_expected_want_process_time: Duration,
    inner: Arc<Mutex<Inner>>,
    on_dont_have_timeout: Arc<dyn DontHaveTimeout>,
}

impl Debug for DontHaveTimeoutManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DontHaveTimeoutManager")
            .field("target", &self.target)
            .field("default_timeout", &self.default_timeout)
            .field("max_timeout", &self.max_timeout)
            .field("ping_latency_multiplier", &self.ping_latency_multiplier)
            .field(
                "messaeg_latency_multiplier",
                &self.message_latency_multiplier,
            )
            .field(
                "max_expected_want_process_time",
                &self.max_expected_want_process_time,
            )
            .field("inner", &self.inner)
            .field("on_dont_have_timeout", &"Box<Fn>")
            .finish()
    }
}

#[derive(Debug)]
struct Inner {
    active_wants: AHashMap<Cid, PendingWant>,
    /// Queue of wants from oldest to newest.
    want_queue: Vec<PendingWant>,
    timeout: Duration,
    /// Ewma of message latency
    message_latency: LatencyEwma,
    check_for_timeouts_timer: Option<(JoinHandle<()>, Sender<()>)>,
    worker: Option<JoinHandle<()>>,
}

impl DontHaveTimeoutManager {
    pub fn new(
        target: PeerId,
        network: Network,
        on_dont_have_timeout: Arc<dyn DontHaveTimeout>,
    ) -> Self {
        let inner = Arc::new(Mutex::new(Inner {
            timeout: DONT_HAVE_TIMEOUT,
            active_wants: Default::default(),
            want_queue: Default::default(),
            message_latency: LatencyEwma {
                alpha: MESSAGE_LATENCY_ALPHA,
                samples: 0,
                latency: Duration::default(),
            },
            check_for_timeouts_timer: None,
            worker: None,
        }));

        // TODO: store latencies somewhere central and retrieve them here

        // measure ping latency
        let i = inner.clone();
        let worker = std::thread::spawn(move || {
            // TODO: add abort method

            match network.ping(&target) {
                Ok(latency) => {
                    let inner = &mut *i.lock().unwrap();
                    if inner.message_latency.samples == 0 {
                        inner.timeout = calculate_timeout_from_ping_latency(
                            latency,
                            MAX_EXPECTED_WANT_PROCESS_TIME,
                            PING_LATENCY_MULTIPLIER,
                            MAX_TIMEOUT,
                        );

                        // update timeouts
                        inner.check_for_timeouts();
                    }
                }
                Err(err) => {
                    warn!("failed to ping {}: {:?}", target, err);
                    // we leave the default timeout
                }
            }
        });

        {
            inner.lock().unwrap().worker = Some(worker);
        }

        DontHaveTimeoutManager {
            target,
            default_timeout: DONT_HAVE_TIMEOUT,
            max_timeout: MAX_TIMEOUT,
            ping_latency_multiplier: PING_LATENCY_MULTIPLIER,
            message_latency_multiplier: MESSAGE_LATENCY_MULTIPLIER,
            max_expected_want_process_time: MAX_EXPECTED_WANT_PROCESS_TIME,
            inner,
            on_dont_have_timeout,
        }
    }

    pub fn shutdown(self) -> Result<()> {
        let inner = &mut *self.inner.lock().unwrap();
        if let Some((worker, closer)) = inner.check_for_timeouts_timer.take() {
            closer.send(()).ok();
            worker
                .join()
                .map_err(|e| anyhow!("failed to shutdown timer worker: {:?}", e))?;
        }
        if let Some(worker) = inner.worker.take() {
            worker
                .join()
                .map_err(|e| anyhow!("failed to shutdown worker: {:?}", e))?;
        }
        Ok(())
    }

    /// Called when we receive a response from the peer. It is the time between
    /// sending a request and receiving the corresponding response.
    pub fn update_message_latency(&self, elapsed: Duration) {
        let inner = &mut *self.inner.lock().unwrap();

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
            inner.check_for_timeouts();
        }
    }

    /// Adds the given keys that will expire if not cancelled before the timeout.
    pub fn add_pending(&self, pending: &[Cid]) {
        if pending.is_empty() {
            return;
        }

        let start = Instant::now();
        let inner = &mut *self.inner.lock().unwrap();
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
            inner.check_for_timeouts();
        }
    }

    /// Called when we receive a response for a key.
    pub fn cancel_pending(&self, cancels: &AHashSet<Cid>) {
        let inner = &mut *self.inner.lock().unwrap();

        for cid in cancels {
            if let Some(pw) = inner.active_wants.get_mut(cid) {
                pw.active = false;
                inner.active_wants.remove(cid);
            }
        }
    }

    /// Triggers on_dont_have_timeout with matching keys.
    fn fire_timeout(&self, pending: &[Cid]) {
        (self.on_dont_have_timeout)(&self.target, pending);

        todo!()
    }
}

impl Inner {
    /// Checks pending wants to see if any are over the timeout.
    fn check_for_timeouts(&mut self) {
        if self.want_queue.is_empty() {
            return;
        }

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
            // TODO
        }

        // Schedule the next check for the moment when the oldest pending want will timeout.
        if let Some(oldest) = self.want_queue.first() {
            let oldest_start = oldest.sent;
            // TODO: verify this is  correct
            let until = (oldest_start + self.timeout) - Instant::now();

            if let Some((worker, cancel)) = self.check_for_timeouts_timer.take() {
                cancel.send(()).ok();
                worker.join().unwrap();
            }

            let timer = crossbeam::channel::after(until);
            let (cancel_s, cancel_r) = crossbeam::channel::bounded(1);
            let worker = std::thread::spawn(move || loop {
                crossbeam::channel::select! {
                    recv(cancel_r) -> _ => {
                        break;
                    }
                    recv(timer) -> _ => {
                        // TODO
                        // self.check_for_timeouts();
                    }
                }
            });

            self.check_for_timeouts_timer = Some((worker, cancel_s));
        }
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
