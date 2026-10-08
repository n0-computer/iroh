//! Interface monitoring and the network state published to consumers.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use n0_future::time::{Duration, Instant};
use n0_watcher::{Direct, Disconnected, Watchable, Watcher};
#[cfg(not(wasm_browser))]
use netwatch::interfaces::IpNet;
use netwatch::netmon;
use rustc_hash::FxHashSet;
use tracing::{Level, error, event};

use super::qad::AddrFamily;
use crate::socket::mapped_addrs::MultipathMappedAddr;

const NETWORK_CHANGE_TIMEOUT: Duration = Duration::from_secs(5);

/// Owns the interface monitor and its subscription.
#[derive(Debug)]
pub(super) struct Interfaces {
    monitor: Option<netmon::Monitor>,
    watcher: Direct<netmon::State>,
    state: Arc<netmon::State>,
    pending: Option<Instant>,
}

impl Interfaces {
    pub(super) async fn new() -> Result<Self, netmon::Error> {
        let monitor = netmon::Monitor::new().await?;
        let mut watcher = monitor.interface_state();
        let state = Arc::new(watcher.get());
        Ok(Self {
            monitor: Some(monitor),
            watcher,
            state,
            pending: None,
        })
    }

    #[cfg(test)]
    pub(super) fn from_watcher(mut watcher: Direct<netmon::State>) -> Self {
        let state = Arc::new(watcher.get());
        Self {
            monitor: None,
            watcher,
            state,
            pending: None,
        }
    }

    pub(super) async fn network_change(&self) {
        if let Some(monitor) = &self.monitor {
            monitor.network_change().await.ok();
        }
    }

    pub(super) async fn updated(&mut self) -> Result<bool, Disconnected> {
        let state = self.watcher.updated().await?;
        let is_major = state.is_major_change(&self.state);
        self.state = Arc::new(state);
        Ok(is_major)
    }

    pub(super) fn has_family(&self, family: AddrFamily) -> bool {
        match family {
            AddrFamily::V4 => self.state.have_v4,
            AddrFamily::V6 => self.state.have_v6,
        }
    }

    pub(super) fn publish_initial(&self, output: &Watchable<NetworkState>) {
        let mut network = output.get();
        network.interfaces = Some(self.state.clone());
        output.set(network).ok();
    }

    pub(super) fn publish_change(&mut self, is_major: bool, output: &Watchable<NetworkState>) {
        event!(target: "iroh::_events::link_change", Level::DEBUG, state = ?self.state, is_major);
        let mut network = output.get();
        network.interfaces = Some(self.state.clone());
        network.changes.record(is_major);
        // A new change invalidates readiness for the previous network.
        network.ready = None;
        if network.has_usable_network() {
            self.pending = None;
            network.ready = Some(network.changes);
        } else {
            // Further changes keep the original fallback deadline. Major changes
            // remain recorded in the generation until the client consumes readiness.
            self.pending
                .get_or_insert(Instant::now() + NETWORK_CHANGE_TIMEOUT);
        }
        output.set(network).ok();
    }

    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.pending
    }

    pub(super) fn on_timer(&mut self, now: Instant, output: &Watchable<NetworkState>) {
        if self.pending.is_some_and(|deadline| deadline <= now) {
            let mut network = output.get();
            network.ready = Some(network.changes);
            self.pending = None;
            output.set(network).ok();
        }
    }
}

/// Counts changes so a slow subscriber still observes major changes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Changes {
    total: u64,
    major: u64,
}

impl Changes {
    fn record(&mut self, is_major: bool) {
        self.total += 1;
        self.major += u64::from(is_major);
    }

    /// Whether anything changed since `previous`, and whether it was major.
    pub(super) fn since(self, previous: Self) -> Option<bool> {
        (self.total != previous.total).then_some(self.major != previous.major)
    }
}

/// Local addresses and notifications derived from the interface monitor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct NetworkState {
    interfaces: Option<Arc<netmon::State>>,
    /// Changes requiring transport rebinding and refreshed direct addresses.
    pub(super) changes: Changes,
    /// The current change generation, once ready to be propagated to QUIC.
    pub(super) ready: Option<Changes>,
}

impl NetworkState {
    fn has_usable_network(&self) -> bool {
        #[cfg(target_family = "wasm")]
        {
            true
        }
        #[cfg(not(target_family = "wasm"))]
        {
            self.interfaces.as_ref().is_some_and(|state| {
                state.default_route_interface.is_some() && (state.have_v4 || state.have_v6)
            })
        }
    }

    /// A QUIC recovery hint derived from the current local addresses.
    pub(super) fn hint(&self) -> Arc<dyn noq::NetworkChangeHint + Send + Sync> {
        let local_addrs = self
            .interfaces
            .as_ref()
            .map(|state| {
                state
                    .local_addresses
                    .regular
                    .iter()
                    .chain(&state.local_addresses.loopback)
                    .copied()
                    .collect()
            })
            .unwrap_or_default();
        Arc::new(Hint { local_addrs })
    }

    /// Expands unspecified bind addresses and filters deprecated addresses.
    #[cfg(not(wasm_browser))]
    pub(super) fn local_addresses(
        &self,
        bound_local: &[(SocketAddr, SocketAddr)],
        include_loopback: bool,
    ) -> Vec<SocketAddr> {
        let Some(state) = &self.interfaces else {
            return Vec::new();
        };
        let v4_port = bound_local.iter().find_map(|(_, addr)| {
            (addr.is_ipv4() && addr.ip().is_unspecified()).then_some(addr.port())
        });
        let v6_port = bound_local.iter().find_map(|(_, addr)| {
            (addr.is_ipv6() && addr.ip().is_unspecified()).then_some(addr.port())
        });
        let ips = if state.local_addresses.regular.is_empty() && include_loopback {
            &state.local_addresses.loopback
        } else {
            &state.local_addresses.regular
        };
        ips.iter()
            .filter_map(|ip| {
                let port = if ip.is_ipv4() { v4_port } else { v6_port }?;
                Some(SocketAddr::new(*ip, port))
            })
            .chain(
                bound_local
                    .iter()
                    .filter_map(|(bound, local)| (!bound.ip().is_unspecified()).then_some(*local)),
            )
            .filter(|addr| !is_deprecated(state, addr.ip()))
            .collect()
    }
}

/// Whether an interface marks this IPv6 address as deprecated.
#[cfg(not(wasm_browser))]
fn is_deprecated(state: &netmon::State, ip: IpAddr) -> bool {
    state.interfaces.values()
        .flat_map(|interface| interface.addrs())
        .any(|addr| matches!(addr, IpNet::V6 { net, flags, .. } if net.addr() == ip && flags.deprecated))
}

/// Determines which existing QUIC paths can recover after a network change.
#[derive(Debug)]
struct Hint {
    local_addrs: FxHashSet<IpAddr>,
}

impl noq::NetworkChangeHint for Hint {
    fn is_path_recoverable(&self, _path_id: noq::PathId, path: noq_proto::FourTuple) -> bool {
        match MultipathMappedAddr::from(path.remote()) {
            MultipathMappedAddr::Mixed(_) => {
                error!("A mixed address can not be used for network changes");
                false
            }
            // The relay actor reconnects transparently; its addresses stay the same.
            MultipathMappedAddr::Relay(_) => true,
            MultipathMappedAddr::Ip(_) => path
                .local_ip()
                .is_none_or(|ip| self.local_addrs.contains(&ip)),
            MultipathMappedAddr::Custom(_) => false,
        }
    }
}
