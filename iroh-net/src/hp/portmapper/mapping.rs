use std::{net::SocketAddrV4, num::NonZeroU16, pin::Pin, task::Poll};

use futures::Future;
use std::time::Duration;
use tokio::{sync::watch, time};
use tracing::trace;

use super::upnp;

#[derive(Debug)]
enum State {
    /// No active mapping.
    None,
    /// Mapping is active.
    Active {
        mapping: upnp::Mapping,
        deadline: Pin<Box<time::Sleep>>,
        /// Whether the mapping should be considered expired after `deadline`.
        expire_after: bool,
    },
}

impl State {
    pub fn new(mapping: Option<upnp::Mapping>) -> Self {
        match mapping {
            Some(mapping) => State::Active {
                mapping,
                deadline: Box::pin(time::sleep(Duration::from_secs(3))),
                expire_after: false,
            },
            None => State::None,
        }
    }

    pub fn replace(&mut self, mapping: Option<upnp::Mapping>) -> Option<upnp::Mapping> {
        let old_mapping = std::mem::replace(self, State::new(mapping));
        match old_mapping {
            State::None => None,
            State::Active { mapping, .. } => Some(mapping),
        }
    }
}

pub(super) enum Event {
    Renew { external_port: NonZeroU16 },
    Expired { external_port: NonZeroU16 },
}
/// Holds the current mapping value and ensures that any change is reported accordingly.
#[derive(Debug)]
pub(super) struct CurrentMapping {
    /// Active port mapping.
    mapping: State,
    /// A [`watch::Sender`] that keeps the latest external address for subscribers to changes.
    address_tx: watch::Sender<Option<SocketAddrV4>>,
}

impl CurrentMapping {
    /// Creates a new [`CurrentMapping`] and returns the watcher over it's external address.
    pub(super) fn new(
        mapping: Option<upnp::Mapping>,
    ) -> (Self, watch::Receiver<Option<SocketAddrV4>>) {
        let maybe_external_addr = mapping.as_ref().map(|mapping| mapping.external());
        let (address_tx, address_rx) = watch::channel(maybe_external_addr);
        let mapping = State::new(mapping);
        let wrapper = CurrentMapping {
            mapping,
            address_tx,
        };
        (wrapper, address_rx)
    }

    /// Updates the mapping, informing of any changes to the external address. The old mapping is
    /// returned.
    pub(super) fn update(&mut self, mapping: Option<upnp::Mapping>) -> Option<upnp::Mapping> {
        trace!("New port mapping {mapping:?}");
        let maybe_external_addr = mapping.as_ref().map(|mapping| mapping.external());
        let old_mapping = self.mapping.replace(mapping);
        self.address_tx.send_if_modified(|old_addr| {
            // replace the value always, as it could have different internal values
            let old_addr = std::mem::replace(old_addr, maybe_external_addr);
            // inform only if this produces a different external address
            old_addr != maybe_external_addr
        });
        old_mapping
    }

    fn poll(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Event> {
        // poll the mapping deadlines to keep the state up to date
        if let State::Active {
            mapping,
            deadline,
            expire_after,
        } = &mut self.mapping
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
                    Poll::Ready(Event::Expired { external_port })
                } else {
                    // mapping is due for renewal
                    // TODO(@divma): this sleep needs to be polled. Gotta add a waker
                    *deadline = Box::pin(time::sleep(Duration::from_secs(3)));
                    *expire_after = true;
                    Poll::Ready(Event::Renew { external_port })
                };
            }
        }
        Poll::Pending
    }
}

impl futures::Stream for CurrentMapping {
    type Item = Event;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.as_mut().poll(cx).map(Some)
    }
}
