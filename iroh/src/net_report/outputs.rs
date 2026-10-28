//! Published values and subscriptions to changes in those values.

use std::{
    net::{SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use iroh_base::RelayUrl;
use n0_watcher::{Direct, Watchable};

#[cfg(any(test, feature = "unstable-net-report"))]
use super::Report;
use super::interfaces::NetworkState;

/// Our public addresses, as the relays see them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct PublicAddrs {
    /// Our public IPv4 address.
    pub(crate) v4: Option<PublicAddr<SocketAddrV4>>,
    /// Our public IPv6 address.
    pub(crate) v6: Option<PublicAddr<SocketAddrV6>>,
}

/// A public address of one address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublicAddr<A> {
    /// The address and port the relays see us coming from.
    pub(crate) addr: A,
    /// Whether the address differs per destination.
    ///
    /// This is the case behind a NAT with endpoint-dependent mapping. Peers
    /// then cannot use the address we learned from a relay. `false` until two
    /// relays have reported an address.
    pub(crate) varies_by_dest: bool,
}

/// What the net report publishes for the rest of iroh.
///
/// Subscribers wake when a value changes. The outputs exist before the net
/// report starts, so components created earlier can subscribe to them.
#[derive(Debug, Clone, Default)]
pub(crate) struct Outputs {
    /// Local addresses and network change notifications.
    pub(super) network_state: Watchable<NetworkState>,
    /// Our public addresses.
    pub(super) public_addrs: Watchable<PublicAddrs>,
    /// The relay to use as home relay.
    ///
    /// `None` until the net report has picked one. After that it only ever
    /// changes to another relay.
    pub(super) home_relay: Watchable<Option<RelayUrl>>,
    /// The full report, for debugging.
    #[cfg(any(test, feature = "unstable-net-report"))]
    pub(super) report: Watchable<Option<Report>>,
}

impl Outputs {
    /// Watches our public addresses.
    #[cfg(test)]
    pub(super) fn public_addrs(&self) -> Direct<PublicAddrs> {
        self.public_addrs.watch()
    }

    /// Returns whether IPv6 works, as far as we know.
    ///
    /// That is the case once a relay has seen us over IPv6.
    pub(crate) fn has_ipv6(&self) -> bool {
        self.public_addrs.get().v6.is_some()
    }

    /// Watches the relay to use as home relay.
    pub(crate) fn home_relay(&self) -> Direct<Option<RelayUrl>> {
        self.home_relay.watch()
    }

    /// Watches the full report.
    #[cfg(any(test, feature = "unstable-net-report"))]
    pub(crate) fn report(&self) -> Direct<Option<Report>> {
        self.report.watch()
    }
}

/// The output changes the socket needs to act on.
#[derive(Debug)]
pub(crate) enum Update {
    AddressesChanged,
    NetworkChanged {
        is_major: bool,
    },
    NetworkReady {
        is_major: bool,
        hint: Arc<dyn noq::NetworkChangeHint + Send + Sync>,
    },
}
