#![cfg(test)]
// WIP
#![allow(unused)]
use std::task::{Context, Poll};

use iroh_gossip::net::util::Timers;

use super::*;

#[derive(Default)]
struct TestingDialer {
    /// Peers that are being dialed.
    dialing: HashSet<PublicKey>,
    /// Queue of dials. The `bool` indicates if the dial will be successful.
    dial_futs: delay_queue::DelayQueue<(PublicKey, bool)>,
}

impl Dialer for TestingDialer {
    type Connection = PublicKey;

    fn queue_dial(&mut self, peer_id: PublicKey) {
        // for now assume every dial works
        if self.dialing.insert(peer_id) {
            self.dial_futs
                .insert((peer_id, true), std::time::Duration::from_millis(300));
        }
    }

    fn pending_count(&self) -> usize {
        self.dialing.len()
    }

    fn is_pending(&self, peer: &PublicKey) -> bool {
        self.dialing.contains(peer)
    }
}

impl futures::Stream for TestingDialer {
    type Item = (PublicKey, anyhow::Result<PublicKey>);

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.dial_futs.poll_expired(cx) {
            Poll::Ready(Some(expired)) => {
                let (peer, report_ok) = expired.into_inner();
                let result = report_ok
                    .then_some(peer)
                    .ok_or_else(|| anyhow::anyhow!("dialing test set to fail"));
                Poll::Ready(Some((peer, result)))
            }
            _ => Poll::Pending,
        }
    }
}

#[derive(Default)]
struct TestingGetter {
    /// Number in the [0, 100] range indicating how often should requests fail.
    failure_rate: u8,
    /// History of requests performed by the [`Getter`] and if they were successful.
    request_history: Vec<(DownloadKind, PublicKey, bool)>,
}

impl Getter for TestingGetter {
    // since for testing we don't need a real connection, just keep track of what peer is the
    // request being sent to
    type Connection = PublicKey;

    fn get(&mut self, kind: DownloadKind, peer: PublicKey) -> GetFut {
        // for now, every download is successful
        self.request_history.push((kind.clone(), peer, true));
        async move {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            Ok(())
        }
        .boxed_local()
    }
}

impl<G: Getter<Connection = D::Connection>, R: AvailabilityRegistry, D: Dialer> Service<G, R, D> {
    /// Checks the various invariants the service must maintain
    #[track_caller]
    pub(super) fn check_consistency_invariants(&self) {
        self.chech_concurrency_limits();
        self.check_active_request_count();
        self.check_scheduled_requests_consistency();
    }

    /// Checks concurrency limits are maintained.
    #[track_caller]
    fn chech_concurrency_limits(&self) {
        // check the total number of active requests to ensure it stays within the limit
        let active_requests = self.current_requests.len();
        assert!(!self
            .concurrency_limits
            .at_requests_capacity(active_requests));

        // check that the open and dialing peers don't exceed the connection capacity
        assert!(!self.at_connections_capacity());

        // check the active requests per peer don't exceed the limit
        for info in self.peers.values() {
            assert!(!self
                .concurrency_limits
                .peer_at_request_capacity(info.active_requests()))
        }
    }

    /// Checks that the count of active requests per peer is consistent with the active requests,
    /// and that active request are consistent with download futures
    #[track_caller]
    fn check_active_request_count(&self) {
        // check that the count of futures we are polling for downloads is consistent with the
        // number of requests
        assert_eq!(
            self.in_progress_downloads.len(),
            self.current_requests.len()
        );
        /// check that the count of requests per peer matches the number of requests that have that
        /// peer as active
        let mut real_count: HashMap<PublicKey, usize> = HashMap::with_capacity(self.peers.len());
        for req_info in self.current_requests.values() {
            // nothing like some classic word count
            *real_count.entry(req_info.peer).or_default() += 1;
        }
        for (peer, info) in self.peers.iter() {
            assert_eq!(
                info.active_requests(),
                real_count.get(peer).copied().unwrap_or_default()
            )
        }
    }

    /// Checks that the scheduled requests match the queue that handles their delays.
    #[track_caller]
    fn check_scheduled_requests_consistency(&self) {
        assert_eq!(
            self.scheduled_requests.len(),
            self.scheduled_request_queue.len()
        );
    }

    /// Check that peers queued to be disconnected are consistent with peers considered idle.
    #[track_caller]
    fn check_idle_peer_consistency(&self) {
        let idle_peers = self
            .peers
            .values()
            .filter(|info| info.active_requests() == 0)
            .count();
        assert_eq!(self.goodbye_peer_queue.len(), idle_peers);
    }
}

/// Tests that receiving a download request and performing it doesn't explode.
#[tokio::test]
async fn smoke_test() -> anyhow::Result<()> {
    let testing_dialer = TestingDialer::default();
    let testing_getter = TestingGetter::default();
    let availabiliy_registry = Registry::default();
    let concurrency_limits = ConcurrencyLimits::default();

    let (msg_tx, msg_rx) = mpsc::channel(super::SERVICE_CHANNEL_CAPACITY);

    let mut service = Service::new(
        testing_getter,
        availabiliy_registry,
        testing_dialer,
        concurrency_limits,
        msg_rx,
    );

    let service_handle = tokio::spawn(async move { service.run().await });

    // send a request and make sure the peer is requested the corresponding download
    // check that the requester receives the result
    // msg_tx.s
    Ok(())
}
