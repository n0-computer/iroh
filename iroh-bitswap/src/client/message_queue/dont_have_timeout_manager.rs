use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use ahash::{AHashMap, AHashSet};
use cid::Cid;
use libp2p::PeerId;

use crate::network::Network;

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

#[derive(Debug, Clone)]
pub struct DontHaveTimeoutManager {
    /// The target peer we are tracking.
    target: PeerId,
    network: Network,
    default_timeout: Duration,
    max_timeout: Duration,
    ping_latency_multiplier: f64,
    message_latency_multiplier: f64,
    max_expected_want_process_time: Duration,
    inner: Arc<RwLock<Inner>>,
}

#[derive(Debug)]
struct Inner {
    active_wants: AHashMap<Cid, PendingWant>,
    /// Queue of wants from oldest to newest.
    want_queue: Vec<PendingWant>,
    timeout: Duration,
    /// Ewma of message latency
    message_latency: LatencyEwma,
}

impl DontHaveTimeoutManager {
    pub fn new(target: PeerId, network: Network) -> Self {
        let inner = Arc::new(RwLock::new(Inner {
            timeout: DONT_HAVE_TIMEOUT,
            active_wants: Default::default(),
            want_queue: Default::default(),
            message_latency: LatencyEwma {
                alpha: MESSAGE_LATENCY_ALPHA,
                samples: 0,
                latency: Duration::default(),
            },
        }));

        // measure ping latency
        let worker = std::thread::spawn(move || {
            // TODO
        });

        DontHaveTimeoutManager {
            target,
            network,
            default_timeout: DONT_HAVE_TIMEOUT,
            max_timeout: MAX_TIMEOUT,
            ping_latency_multiplier: PING_LATENCY_MULTIPLIER,
            message_latency_multiplier: MESSAGE_LATENCY_MULTIPLIER,
            max_expected_want_process_time: MAX_EXPECTED_WANT_PROCESS_TIME,
            inner,
        }
    }

    pub fn add_pending(&self, wants: &[Cid]) {
        todo!()
    }

    pub fn cancel_pending(&self, cancels: &AHashSet<Cid>) {
        todo!()
    }

    pub fn update_message_latency(&self, latency: Duration) {
        todo!()
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
