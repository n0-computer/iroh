#![cfg(test)]
// WIP
#![allow(unused)]
use std::{
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::anyhow;
use iroh_gossip::net::util::Timers;
use iroh_net::key::SecretKey;
use parking_lot::RwLock;

use super::*;

#[derive(Default)]
struct TestingDialerInner {
    /// Peers that are being dialed.
    dialing: HashSet<PublicKey>,
    /// Queue of dials. The `bool` indicates if the dial will be successful.
    dial_futs: delay_queue::DelayQueue<(PublicKey, bool)>,
    /// History of attempted dials.
    dial_history: Vec<PublicKey>,
}

#[derive(Default, derive_more::Deref, Clone)]
struct TestingDialer(Arc<RwLock<TestingDialerInner>>);

impl Dialer for TestingDialer {
    type Connection = PublicKey;

    fn queue_dial(&mut self, peer_id: PublicKey) {
        let mut inner = self.0.write();
        inner.dial_history.push(peer_id);
        // for now assume every dial works
        if inner.dialing.insert(peer_id) {
            inner
                .dial_futs
                .insert((peer_id, true), std::time::Duration::from_millis(300));
        }
    }

    fn pending_count(&self) -> usize {
        self.0.read().dialing.len()
    }

    fn is_pending(&self, peer: &PublicKey) -> bool {
        self.0.read().dialing.contains(peer)
    }
}

impl futures::Stream for TestingDialer {
    type Item = (PublicKey, anyhow::Result<PublicKey>);

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.0.write().dial_futs.poll_expired(cx) {
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
struct TestingGetterInner {
    /// Number in the [0, 100] range indicating how often should requests fail.
    failure_rate: u8,
    /// History of requests performed by the [`Getter`] and if they were successful.
    request_history: Vec<(DownloadKind, PublicKey, bool)>,
}

#[derive(Default, derive_more::Deref, Clone)]
struct TestingGetter(Arc<RwLock<TestingGetterInner>>);

impl Getter for TestingGetter {
    // since for testing we don't need a real connection, just keep track of what peer is the
    // request being sent to
    type Connection = PublicKey;

    fn get(&mut self, kind: DownloadKind, peer: PublicKey) -> GetFut {
        // for now, every download is successful
        self.0
            .write()
            .request_history
            .push((kind.clone(), peer, true));
        async move {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            Ok(())
        }
        .boxed_local()
    }
}

/// Tests that receiving a download request and performing it doesn't explode.
#[tokio::test]
async fn smoke_test() -> anyhow::Result<()> {
    // let _guard = iroh_test::logging::setup();

    let testing_dialer = TestingDialer::default();
    let testing_getter = TestingGetter::default();
    let availabiliy_registry = Registry::default();
    let concurrency_limits = ConcurrencyLimits::default();

    let (msg_tx, msg_rx) = mpsc::channel(super::SERVICE_CHANNEL_CAPACITY);

    {
        let testing_dialer = testing_dialer.clone();
        let testing_getter = testing_getter.clone();

        iroh_bytes::util::runtime::Handle::from_currrent(1)?
            .local_pool()
            .spawn_pinned(move || async move {
                // we want to see the logs of the service
                let _guard = iroh_test::logging::setup();

                let mut service = Service::new(
                    testing_getter,
                    availabiliy_registry,
                    testing_dialer,
                    concurrency_limits,
                    msg_rx,
                );
                service.run().await
            });
    }

    // send a request and make sure the peer is requested the corresponding download
    // check that the requester receives the result
    let peer = SecretKey::generate().public();
    let hash = Hash::new([0u8; 32]);
    let (d_tx, d_rx) = oneshot::channel();
    let id = 0;
    let kind = DownloadKind::Blob { hash };
    msg_tx
        .send(Message::Queue {
            kind: kind.clone(),
            id,
            sender: d_tx,
            peers: vec![peer],
        })
        .await;
    // wait for the download result to be reported
    d_rx.await?.map_err(|()| anyhow!("download failed"))?;
    // verify that the peer was dialed
    assert_eq!(testing_dialer.0.read().dial_history, vec![peer]);
    assert_eq!(
        testing_getter.0.read().request_history,
        vec![(kind, peer, true)]
    );

    Ok(())
}
