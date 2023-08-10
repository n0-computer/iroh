//! Holds the current mapping value and ensures that any change is reported accordingly.

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroU16,
    pin::Pin,
    task::Poll,
};

use futures::Future;
use iroh_metrics::inc;
use std::time::Duration;
use tokio::{sync::watch, time};
use tracing::{debug, trace};

/// This is an implementation detail to facilitate testing.
pub(super) trait Mapping: std::fmt::Debug + Unpin {
    fn external(&self) -> (Ipv4Addr, NonZeroU16);
    /// Half the lifetime of a mapping. This is used to calculate when a mapping should be renewed.
    fn half_lifetime(&self) -> Duration;
}

impl Mapping for super::mapping::Mapping {
    fn external(&self) -> (Ipv4Addr, NonZeroU16) {
        super::mapping::PortMapped::external(self)
    }
    fn half_lifetime(&self) -> Duration {
        super::mapping::PortMapped::half_lifetime(self)
    }
}

/// Models the lifetime of an active mapping.
#[derive(Debug)]
struct ActiveMapping<M> {
    mapping: M,
    deadline: Pin<Box<time::Sleep>>,
    expire_after: bool,
}

impl<M: Mapping> ActiveMapping<M> {
    fn new(mapping: M) -> Self {
        let deadline = Box::pin(time::sleep(mapping.half_lifetime()));
        ActiveMapping {
            mapping,
            deadline,
            expire_after: false,
        }
    }
}

/// Events in the lifetime of the mapping.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Event {
    /// On this event, the mapping is halfway through its lifetime and should be renewed.
    Renew {
        external_ip: Ipv4Addr,
        external_port: NonZeroU16,
    },
    /// Mapping has expired.
    Expired {
        external_ip: Ipv4Addr,
        external_port: NonZeroU16,
    },
}

/// Holds the current mapping value and ensures that any change is reported accordingly.
#[derive(derive_more::Debug)]
pub(super) struct CurrentMapping<M = super::mapping::Mapping> {
    /// Active port mapping.
    mapping: Option<ActiveMapping<M>>,
    /// A [`watch::Sender`] that keeps the latest external address for subscribers to changes.
    address_tx: watch::Sender<Option<SocketAddrV4>>,
    /// Waker to ensure this is polled when needed.
    #[debug(skip)]
    waker: Option<std::task::Waker>,
}

impl<M: Mapping> CurrentMapping<M> {
    /// Creates a new [`CurrentMapping`] and returns the watcher over its external address.
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
        debug!("new port mapping {mapping:?}");
        let maybe_external_addr = mapping.as_ref().map(|mapping| {
            let (ip, port) = mapping.external();
            SocketAddrV4::new(ip, port.into())
        });
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
            let update = old_addr != maybe_external_addr;
            if update {
                inc!(super::Metrics, external_address_updated);
            };
            update
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
                let (external_ip, external_port) = mapping.external();
                // check if the deadline means the mapping is expired or due for renewal
                return if *expire_after {
                    trace!("mapping expired {mapping:?}");
                    self.update(None);
                    Poll::Ready(Event::Expired {
                        external_ip,
                        external_port,
                    })
                } else {
                    // mapping is due for renewal
                    *deadline = Box::pin(time::sleep(mapping.half_lifetime()));
                    *expire_after = true;
                    trace!("due for renewal {mapping:?}");
                    Poll::Ready(Event::Renew {
                        external_ip,
                        external_port,
                    })
                };
            }
        }
        Poll::Pending
    }

    pub(crate) fn external(&self) -> Option<(Ipv4Addr, NonZeroU16)> {
        self.mapping
            .as_ref()
            .map(|mapping| mapping.mapping.external())
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

    // for testing a mapping is simply an ip, port pair
    type M = (Ipv4Addr, NonZeroU16);

    const TEST_PORT: NonZeroU16 = // SAFETY: it's clearly non zero
        unsafe { NonZeroU16::new_unchecked(9586) };
    const TEST_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::LOCALHOST;
    const HALF_LIFETIME_SECS: u64 = 1;

    impl Mapping for M {
        fn external(&self) -> M {
            *self
        }
        fn half_lifetime(&self) -> Duration {
            Duration::from_secs(HALF_LIFETIME_SECS)
        }
    }

    #[tokio::test]
    #[ntest::timeout(2500)]
    async fn report_renew_expire_report() {
        let (mut c, mut watcher) = CurrentMapping::<M>::new();
        let now = std::time::Instant::now();
        c.update(Some((TEST_IP, TEST_PORT)));

        // 1) check that changes are reported as soon as needed
        time::timeout(Duration::from_millis(10), watcher.changed())
            .await
            .expect("change is as immediate as it can be.")
            .expect("sender is alive");
        let addr = watcher.borrow_and_update().unwrap();
        assert_eq!(addr.ip(), &TEST_IP);
        assert_eq!(addr.port(), Into::<u16>::into(TEST_PORT));

        // 2) test that the mapping being due for renewal is reported in a timely matter
        let event = c.next().await.expect("Renewal is reported");
        // check that the event is the correct type
        assert_eq!(
            event,
            Event::Renew {
                external_ip: TEST_IP,
                external_port: TEST_PORT
            }
        );
        // check it's reported not before not after it should
        assert_eq!(now.elapsed().as_secs(), HALF_LIFETIME_SECS);
        // check renewal does not produce a change
        assert!(!watcher.has_changed().unwrap());

        // 3) test that the mapping being expired is reported in a timely matter
        let event = c.next().await.expect("Expiry is reported");
        // check that the event is the correct type
        assert_eq!(
            event,
            Event::Expired {
                external_ip: TEST_IP,
                external_port: TEST_PORT
            }
        );
        assert_eq!(now.elapsed().as_secs(), 2 * HALF_LIFETIME_SECS);
        // check that the change is reported
        time::timeout(Duration::from_millis(10), watcher.changed())
            .await
            .expect("change is as immediate as it can be.")
            .expect("sender is alive");
        assert!(watcher.borrow_and_update().is_none());
    }
}
