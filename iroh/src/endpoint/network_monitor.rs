//! The endpoint's view of the local network.
//!
//! An endpoint needs to know which IP addresses the host has and when they change. By
//! default it watches the operating system for this. A [`NetworkMonitor`] replaces that
//! source, see [`Builder::network_monitor`].
//!
//! [`Builder::network_monitor`]: crate::endpoint::Builder::network_monitor

use std::{fmt::Debug, net::IpAddr, sync::Arc};

use n0_error::{e, stack_error};
use n0_future::boxed::{BoxFuture, BoxStream};
use n0_watcher::Watcher;
use netwatch::netmon;

/// The source of the endpoint's knowledge about the local network.
///
/// Everything the endpoint knows about local interfaces comes from here: the local
/// addresses offered to peers as direct addresses, which existing paths can survive a
/// network change, and whether there is a network to probe at all.
///
/// [`DefaultNetworkMonitor`] watches the operating system. To change what the endpoint
/// sees, wrap it and edit the states it produces. An application which owns a TUN device
/// can remove that device's addresses, so the endpoint never offers them to peers and
/// never keeps a path on them:
///
/// ```
/// use std::net::IpAddr;
///
/// use iroh::endpoint::{DefaultNetworkMonitor, NetworkChange, NetworkMonitor, NetworkState};
/// use n0_future::{
///     StreamExt,
///     boxed::{BoxFuture, BoxStream},
/// };
///
/// #[derive(Debug)]
/// struct WithoutTun {
///     inner: DefaultNetworkMonitor,
///     tun_addr: IpAddr,
/// }
///
/// impl NetworkMonitor for WithoutTun {
///     fn state(&self) -> NetworkState {
///         let mut state = self.inner.state();
///         state.addrs.retain(|addr| addr.ip != self.tun_addr);
///         state
///     }
///
///     fn changes(&self) -> BoxStream<NetworkChange> {
///         let tun_addr = self.tun_addr;
///         Box::pin(self.inner.changes().map(move |mut change| {
///             change.state.addrs.retain(|addr| addr.ip != tun_addr);
///             change
///         }))
///     }
///
///     fn network_change(&self) -> BoxFuture<()> {
///         self.inner.network_change()
///     }
/// }
/// ```
pub trait NetworkMonitor: Debug + Send + Sync + 'static {
    /// Returns the current state of the local network.
    fn state(&self) -> NetworkState;

    /// Returns a stream of changes to the local network.
    ///
    /// The stream does not yield the current state, only changes after this call. Every
    /// item is acted upon, even if its state equals the previous one. This allows
    /// forcing the endpoint to re-evaluate its paths for changes it can not observe
    /// itself, like a change in routing policy.
    fn changes(&self) -> BoxStream<NetworkChange>;

    /// Tells the monitor the network might have changed.
    ///
    /// Called for [`Endpoint::network_change`]. The monitor should check for changes and
    /// emit them on the [`Self::changes`] streams.
    ///
    /// [`Endpoint::network_change`]: crate::Endpoint::network_change
    fn network_change(&self) -> BoxFuture<()>;
}

/// A change to the local network, emitted by a [`NetworkMonitor`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NetworkChange {
    /// The state of the local network after the change.
    pub state: NetworkState,
    /// Whether existing sockets and connections are likely broken.
    ///
    /// A major change, like a different default route, makes the endpoint rebind its
    /// sockets and re-establish its relay connection. A minor change only updates the
    /// direct addresses and re-validates paths.
    pub is_major: bool,
}

impl NetworkChange {
    /// Creates a new change to `state`.
    pub fn new(state: NetworkState, is_major: bool) -> Self {
        Self { state, is_major }
    }
}

/// The state of the local network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkState {
    /// The IP addresses assigned to the host's network interfaces.
    pub addrs: Vec<LocalAddr>,
    /// Whether a default route exists.
    pub has_default_route: bool,
    /// Whether an IPv4 address exists which might provide connectivity.
    pub have_v4: bool,
    /// Whether an IPv6 address exists which might provide connectivity.
    pub have_v6: bool,
}

impl NetworkState {
    /// Whether there is a default route and an address which might provide connectivity.
    pub(crate) fn is_usable(&self) -> bool {
        self.has_default_route && (self.have_v4 || self.have_v6)
    }

    /// Whether `ip` is a known and deprecated local address.
    pub(crate) fn is_deprecated(&self, ip: IpAddr) -> bool {
        self.addrs
            .iter()
            .any(|addr| addr.ip == ip && addr.is_deprecated)
    }
}

/// An IP address assigned to a local network interface.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LocalAddr {
    /// The address.
    pub ip: IpAddr,
    /// Whether the address is deprecated and must not be used for new paths.
    ///
    /// This is the IPv6 notion of a deprecated address, see [RFC 4862].
    ///
    /// [RFC 4862]: https://www.rfc-editor.org/rfc/rfc4862#section-5.5.4
    pub is_deprecated: bool,
}

impl LocalAddr {
    /// Creates a new address which is not deprecated.
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            is_deprecated: false,
        }
    }
}

/// The [`NetworkMonitor`] used by default, it watches the operating system.
#[derive(Debug, Clone)]
pub struct DefaultNetworkMonitor {
    monitor: Arc<netmon::Monitor>,
}

/// Error for [`DefaultNetworkMonitor::new`].
#[stack_error(derive, add_meta)]
#[error("failed to watch the local network")]
pub struct NetworkMonitorError {
    source: netmon::Error,
}

impl DefaultNetworkMonitor {
    /// Starts watching the local network.
    pub async fn new() -> Result<Self, NetworkMonitorError> {
        let monitor = netmon::Monitor::new()
            .await
            .map_err(|err| e!(NetworkMonitorError, err))?;
        Ok(Self {
            monitor: Arc::new(monitor),
        })
    }
}

impl NetworkMonitor for DefaultNetworkMonitor {
    fn state(&self) -> NetworkState {
        NetworkState::from(&self.monitor.interface_state().get())
    }

    fn changes(&self) -> BoxStream<NetworkChange> {
        let mut watcher = self.monitor.interface_state();
        let current = watcher.get();
        Box::pin(n0_future::stream::unfold(
            (watcher, current),
            |(mut watcher, previous)| async move {
                let state = watcher.updated().await.ok()?;
                let change = NetworkChange {
                    state: NetworkState::from(&state),
                    is_major: state.is_major_change(&previous),
                };
                Some((change, (watcher, state)))
            },
        ))
    }

    fn network_change(&self) -> BoxFuture<()> {
        let monitor = self.monitor.clone();
        Box::pin(async move {
            monitor.network_change().await.ok();
        })
    }
}

impl From<&netmon::State> for NetworkState {
    fn from(state: &netmon::State) -> Self {
        #[cfg(not(wasm_browser))]
        let addrs = {
            use netwatch::interfaces::IpNet;

            let is_deprecated = |ip: IpAddr| {
                state
                    .interfaces
                    .values()
                    .flat_map(|interface| interface.addrs())
                    .any(|net| match net {
                        IpNet::V4(_) => false,
                        IpNet::V6 { net, flags, .. } => net.addr() == ip && flags.deprecated,
                    })
            };
            let local = &state.local_addresses;
            local
                .regular
                .iter()
                .chain(&local.loopback)
                .map(|ip| LocalAddr {
                    ip: *ip,
                    is_deprecated: is_deprecated(*ip),
                })
                .collect()
        };
        #[cfg(wasm_browser)]
        let addrs = Vec::new();

        Self {
            addrs,
            has_default_route: state.default_route_interface.is_some(),
            have_v4: state.have_v4,
            have_v6: state.have_v6,
        }
    }
}

#[cfg(all(test, with_crypto_provider))]
mod tests {
    use std::{
        collections::BTreeSet,
        net::Ipv4Addr,
        sync::{Arc, Mutex},
    };

    use n0_error::{Result, StdResultExt};
    use n0_future::{StreamExt, time};
    use n0_tracing_test::traced_test;
    use tokio::sync::broadcast;

    use super::*;
    use crate::{Endpoint, endpoint::presets};

    /// A monitor reporting whatever the test tells it to.
    #[derive(Debug, Clone)]
    struct TestMonitor {
        state: Arc<Mutex<NetworkState>>,
        changes: broadcast::Sender<NetworkChange>,
    }

    impl TestMonitor {
        fn new(ips: &[Ipv4Addr]) -> Self {
            Self {
                state: Arc::new(Mutex::new(test_state(ips))),
                changes: broadcast::channel(8).0,
            }
        }

        fn set(&self, ips: &[Ipv4Addr]) {
            let state = test_state(ips);
            *self.state.lock().expect("poisoned") = state.clone();
            self.changes.send(NetworkChange::new(state, false)).ok();
        }
    }

    impl NetworkMonitor for TestMonitor {
        fn state(&self) -> NetworkState {
            self.state.lock().expect("poisoned").clone()
        }

        fn changes(&self) -> BoxStream<NetworkChange> {
            let rx = self.changes.subscribe();
            Box::pin(n0_future::stream::unfold(rx, |mut rx| async move {
                let change = rx.recv().await.ok()?;
                Some((change, rx))
            }))
        }

        fn network_change(&self) -> BoxFuture<()> {
            Box::pin(async {})
        }
    }

    fn test_state(ips: &[Ipv4Addr]) -> NetworkState {
        NetworkState {
            addrs: ips.iter().map(|ip| LocalAddr::new((*ip).into())).collect(),
            has_default_route: true,
            have_v4: true,
            have_v6: false,
        }
    }

    /// Waits until the endpoint's direct addresses contain exactly `expected` from the
    /// test network.
    async fn wait_for_test_ips(ep: &Endpoint, expected: &[Ipv4Addr]) -> Result {
        let expected: BTreeSet<IpAddr> = expected.iter().map(|ip| (*ip).into()).collect();
        let mut addrs = ep.watch_addr().stream();
        time::timeout(time::Duration::from_secs(10), async {
            while let Some(addr) = addrs.next().await {
                let ips: BTreeSet<IpAddr> = addr
                    .ip_addrs()
                    .map(|addr| addr.ip())
                    .filter(|ip| TEST_NET.contains(ip))
                    .collect();
                if ips == expected {
                    break;
                }
            }
        })
        .await
        .anyerr()
    }

    /// TEST-NET-1 from RFC 5737, never assigned to a real interface.
    const TEST_NET: ipnet::IpNet =
        ipnet::IpNet::V4(ipnet::Ipv4Net::new_assert(Ipv4Addr::new(192, 0, 2, 0), 24));

    #[tokio::test]
    #[traced_test]
    async fn direct_addrs_follow_the_monitor() -> Result {
        let kept = Ipv4Addr::new(192, 0, 2, 1);
        let removed = Ipv4Addr::new(192, 0, 2, 2);
        let added = Ipv4Addr::new(192, 0, 2, 3);

        let monitor = TestMonitor::new(&[kept, removed]);
        let ep = Endpoint::builder(presets::Minimal)
            .network_monitor(monitor.clone())
            .bind()
            .await?;
        wait_for_test_ips(&ep, &[kept, removed]).await?;

        monitor.set(&[kept, added]);
        wait_for_test_ips(&ep, &[kept, added]).await?;

        ep.close().await;
        Ok(())
    }

    /// Wraps the default monitor and hides every address for which `hide` returns true.
    #[derive(Debug)]
    struct Hiding {
        inner: DefaultNetworkMonitor,
        hide: fn(IpAddr) -> bool,
    }

    impl NetworkMonitor for Hiding {
        fn state(&self) -> NetworkState {
            let mut state = self.inner.state();
            state.addrs.retain(|addr| !(self.hide)(addr.ip));
            state
        }

        fn changes(&self) -> BoxStream<NetworkChange> {
            let hide = self.hide;
            Box::pin(self.inner.changes().map(move |mut change| {
                change.state.addrs.retain(|addr| !hide(addr.ip));
                change
            }))
        }

        fn network_change(&self) -> BoxFuture<()> {
            self.inner.network_change()
        }
    }

    /// The use case of an application owning a TUN device: wrap the default monitor and
    /// hide some of the host's real addresses.
    #[tokio::test]
    #[traced_test]
    async fn wrapped_default_monitor_hides_addresses() -> Result {
        let ep = Endpoint::builder(presets::Minimal).bind().await?;
        assert!(ep.addr().ip_addrs().count() > 0, "host has no addresses");
        ep.close().await;

        let monitor = Hiding {
            inner: DefaultNetworkMonitor::new().await?,
            hide: |_ip| true,
        };
        let ep = Endpoint::builder(presets::Minimal)
            .network_monitor(monitor)
            .bind()
            .await?;
        assert_eq!(ep.addr().ip_addrs().count(), 0);
        ep.close().await;
        Ok(())
    }
}
