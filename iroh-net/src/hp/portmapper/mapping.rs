use std::{net::SocketAddrV4, num::NonZeroU16, pin::Pin, task::Poll};

use futures::Future;
use std::time::Duration;
use tokio::{sync::watch, time};
use tracing::trace;

// This is an implementation detail to facilitate testing.
pub(super) trait Mapping: std::fmt::Debug + Unpin {
    fn external(&self) -> SocketAddrV4;
}

impl Mapping for super::upnp::Mapping {
    fn external(&self) -> SocketAddrV4 {
        self.external()
    }
}

/// Models the lifetime of an active mapping.
#[derive(Debug)]
struct ActiveMapping<M> {
    mapping: M,
    deadline: Pin<Box<time::Sleep>>,
    expire_after: bool,
}

impl<M> ActiveMapping<M> {
    fn new(mapping: M) -> Self {
        ActiveMapping {
            mapping,
            deadline: Box::pin(time::sleep(Duration::from_secs(3))),
            expire_after: false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Event {
    Renew { external_port: NonZeroU16 },
    Expired { external_port: NonZeroU16 },
}
/// Holds the current mapping value and ensures that any change is reported accordingly.
#[derive(derive_more::Debug)]
pub(super) struct CurrentMapping<M = super::upnp::Mapping> {
    /// Active port mapping.
    mapping: Option<ActiveMapping<M>>,
    /// A [`watch::Sender`] that keeps the latest external address for subscribers to changes.
    address_tx: watch::Sender<Option<SocketAddrV4>>,
    /// Waker to ensure this is polled when needed.
    #[debug(skip)]
    waker: Option<std::task::Waker>,
}

impl<M: Mapping> CurrentMapping<M> {
    /// Creates a new [`CurrentMapping`] and returns the watcher over it's external address.
    pub(super) fn new() -> (Self, watch::Receiver<Option<SocketAddrV4>>) {
        let (address_tx, address_rx) = watch::channel(None);
        let wrapper = CurrentMapping {
            mapping: None,
            address_tx,
            waker: None,
        };
        (wrapper, address_rx)
    }

    /// Updates the mapping, informing of any changes to the external address. The old mapping is
    /// returned.
    pub(super) fn update(&mut self, mapping: Option<M>) -> Option<M> {
        trace!("New port mapping {mapping:?}");
        let maybe_external_addr = mapping.as_ref().map(|mapping| mapping.external());
        let old_mapping = std::mem::replace(&mut self.mapping, mapping.map(ActiveMapping::new))
            .map(|mapping| mapping.mapping);
        // mapping changed
        // TODO(@divma): maybe only wake if mapping is some
        if let Some(waker) = &self.waker {
            waker.wake_by_ref()
        }
        self.address_tx.send_if_modified(|old_addr| {
            // replace the value always, as it could have different internal values
            let old_addr = std::mem::replace(old_addr, maybe_external_addr);
            // inform only if this produces a different external address
            old_addr != maybe_external_addr
        });
        old_mapping
    }

    fn poll(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Event> {
        // grab the waker if needed
        if let Some(waker) = &self.waker {
            if waker.will_wake(cx.waker()) {
                self.waker = Some(cx.waker().clone());
            }
        } else {
            self.waker = Some(cx.waker().clone());
        }

        // poll the mapping deadlines to keep the state up to date
        if let Some(ActiveMapping {
            mapping,
            deadline,
            expire_after,
        }) = &mut self.mapping
        {
            if deadline.as_mut().poll(cx).is_ready() {
                // TODO(@divma): I'm actually not sure about this but sounds ilogical
                let external_port = mapping
                    .external()
                    .port()
                    .try_into()
                    .expect("external address can never be zero");
                // check if the deadline means the mapping is expired or due for renewal
                return if *expire_after {
                    self.update(None);
                    trace!("mapping expired");
                    Poll::Ready(Event::Expired { external_port })
                } else {
                    // mapping is due for renewal
                    *deadline = Box::pin(time::sleep(Duration::from_secs(3)));
                    *expire_after = true;
                    trace!("due for renewal");
                    Poll::Ready(Event::Renew { external_port })
                };
            }
        }
        Poll::Pending
    }
}

impl<M: Mapping> futures::Stream for CurrentMapping<M> {
    type Item = Event;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.as_mut().poll(cx).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    // for testing a mapping is simply an address
    impl Mapping for SocketAddrV4 {
        fn external(&self) -> SocketAddrV4 {
            self.clone()
        }
    }

    const TEST_PORT_U16: u16 = 9586;
    const TEST_PORT: NonZeroU16 = // SAFETY: it's clearly non zero
        unsafe { NonZeroU16::new_unchecked(TEST_PORT_U16) };
    const TEST_MAPPING: SocketAddrV4 =
        SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, TEST_PORT_U16);

    #[tokio::test]
    #[ntest::timeout(7000)] // 3 seconds for renewal, 3 seconds for expiry, 1 to.. be kind?
    async fn it_works() {
        let (mut c, mut watcher) = CurrentMapping::<SocketAddrV4>::new();
        let now = std::time::Instant::now();
        c.update(Some(TEST_MAPPING));

        // 1) check that changes are reported as soon as needed
        time::timeout(Duration::from_millis(10), watcher.changed())
            .await
            .expect("change is as immediate as it can be.")
            .expect("sender is alive");
        assert_eq!(*watcher.borrow_and_update(), Some(TEST_MAPPING));

        // 2) test that the mapping being due for renewal is reported in a timely matter
        let event = c.next().await.expect("Renewal is reported");
        // check that the event is the correct type
        assert_eq!(
            event,
            Event::Renew {
                external_port: TEST_PORT
            }
        );
        // check it's reported not before not after it should
        // TODO(@divma): using hardcoded 3 everywhere
        assert_eq!(now.elapsed().as_secs(), 3);
        // check renewal does not produce a change
        assert!(!watcher.has_changed().unwrap());

        // 3) test that the mapping being expired is reported in a timely matter
        let event = c.next().await.expect("Expiry is reported");
        // check that the event is the correct type
        assert_eq!(
            event,
            Event::Expired {
                external_port: TEST_PORT
            }
        );
        // TODO(@divma): using hardcoded 3 everywhere (renew deadline + expiry deadline)
        assert_eq!(now.elapsed().as_secs(), 6);
        // check that the change is reported
        time::timeout(Duration::from_millis(10), watcher.changed())
            .await
            .expect("change is as immediate as it can be.")
            .expect("sender is alive");
        assert!(watcher.borrow_and_update().is_none());
    }
}
