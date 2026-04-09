//! Uplink switch tests.
//!
//! Each test verifies that an iroh connection survives a network change on one
//! side: the switching device replugs from one router to another, and we verify
//! that a new direct path is established and data flows over it.
//!
//! We test every combination of:
//! - which side switches (client or server)
//! - which IP families are involved (v4, v6, dual-stack)
//!
//! The non-switching side is always behind a dual-stack Home NAT, so it is
//! reachable on both address families regardless of what the switcher does.

use std::time::Duration;

use iroh::{TransportAddr, endpoint::Side};
use n0_error::{Result, StackResultExt};
use n0_tracing_test::traced_test;
use patchbay::{IpSupport, RouterPreset};
use testdir::testdir;
use tracing::info;

use crate::util::{Pair, PathWatcherExt, lab_with_relay, ping_accept, ping_open};

/// Describes which IP family transition the switching side makes.
///
/// Each variant determines the router presets for the "from" and "to" routers.
/// For example, [`V4ToV6`](Self::V4ToV6) starts the switcher behind a v4-only
/// Home NAT and replugs to a v6-only ISP router.
#[derive(Debug, Clone, Copy)]
enum SwitchKind {
    V4ToV4,
    V4ToV6,
    V6ToV4,
    V6ToV6,
    DualToDual,
}

impl SwitchKind {
    /// Returns the `(preset, ip_support)` pairs for the "from" and "to" routers.
    fn router_configs(self) -> ((RouterPreset, IpSupport), (RouterPreset, IpSupport)) {
        use IpSupport::*;
        use RouterPreset::*;
        match self {
            Self::V4ToV4 => ((Home, V4Only), (Home, V4Only)),
            Self::V4ToV6 => ((Home, V4Only), (IspV6, V6Only)),
            Self::V6ToV4 => ((IspV6, V6Only), (Home, V4Only)),
            Self::V6ToV6 => ((IspV6, V6Only), (IspV6, V6Only)),
            Self::DualToDual => ((Home, DualStack), (Home, DualStack)),
        }
    }

    /// Checks whether the selected path has changed as expected after the switch.
    ///
    /// For cross-family switches (v4-to-v6, v6-to-v4), we verify the new path
    /// uses the target address family. For same-family switches, we verify the
    /// remote address changed (different NAT, different public IP).
    fn path_switched(self, first: &TransportAddr, new: &TransportAddr) -> bool {
        match self {
            Self::V4ToV6 => matches!(new, TransportAddr::Ip(a) if a.ip().is_ipv6()),
            Self::V6ToV4 => matches!(new, TransportAddr::Ip(a) if a.ip().is_ipv4()),
            _ => matches!(new, TransportAddr::Ip(_)) && new != first,
        }
    }
}

/// Builds the lab topology and runs a single uplink switch test.
///
/// The topology has three routers:
/// - "observer": dual-stack Home NAT for the non-switching side
/// - "from": the switching side's initial router (determined by `kind`)
/// - "to": the router the switching side replugs to (determined by `kind`)
///
/// After both sides holepunch and exchange a ping, the switching side replugs
/// from "from" to "to". The observer waits for the selected path to change,
/// then both sides exchange another ping to confirm the new path works.
async fn run_switch_uplink(switching_side: Side, kind: SwitchKind) -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let timeout = Duration::from_secs(30);

    let observer_id = lab
        .add_router("observer")
        .preset(RouterPreset::Home)
        .ip_support(IpSupport::DualStack)
        .build()
        .await?
        .id();

    let ((from_preset, from_ip), (to_preset, to_ip)) = kind.router_configs();
    let from_id = lab
        .add_router("from")
        .preset(from_preset)
        .ip_support(from_ip)
        .build()
        .await?
        .id();
    let to_id = lab
        .add_router("to")
        .preset(to_preset)
        .ip_support(to_ip)
        .build()
        .await?
        .id();

    let (server_uplink, client_uplink) = match switching_side {
        Side::Client => (observer_id, from_id),
        Side::Server => (from_id, observer_id),
    };
    let server = lab
        .add_device("server")
        .uplink(server_uplink)
        .build()
        .await?;
    let client = lab
        .add_device("client")
        .uplink(client_uplink)
        .build()
        .await?;

    info!(?switching_side, ?kind, "switch uplink test start");

    /// The switching side: holepunches, pings, replugs to a new router, pings again.
    ///
    /// Waits for the peer to close the connection after the second ping succeeds.
    async fn do_switch(
        dev: patchbay::Device,
        conn: iroh::endpoint::Connection,
        timeout: Duration,
        to_id: patchbay::NodeId,
    ) -> Result {
        let mut paths = conn.paths();
        paths.wait_ip(timeout).await.context("initial holepunch")?;
        ping_accept(&conn, timeout)
            .await
            .context("ping_accept before switch")?;
        // TODO(Frando): Without this sleep, some of the server-side tests fail.
        // Exact reason not yet known, but things are very timing-sensitive atm.
        tokio::time::sleep(Duration::from_secs(1)).await;
        dev.replug_iface("eth0", to_id).await?;
        ping_accept(&conn, timeout)
            .await
            .context("ping_accept after switch")?;
        conn.closed().await;
        Ok(())
    }

    /// The observing side: holepunches, pings, waits for the path to change, pings again.
    ///
    /// After the switching side replugs, the observer sees the selected path change
    /// to match the expected address family (or a new address for same-family switches).
    /// Closes the connection after the second ping succeeds.
    async fn do_observe(
        conn: iroh::endpoint::Connection,
        timeout: Duration,
        kind: SwitchKind,
    ) -> Result {
        let mut paths = conn.paths();
        let first = paths.wait_ip(timeout).await.context("initial holepunch")?;
        ping_open(&conn, timeout)
            .await
            .context("ping_open before switch")?;
        paths
            .wait_selected(timeout, |p| {
                kind.path_switched(&first.remote_addr(), &p.remote_addr())
            })
            .await
            .context("path did not switch")?;
        ping_open(&conn, timeout)
            .await
            .context("ping_open after switch")?;
        conn.close(0u32.into(), b"bye");
        Ok(())
    }

    let pair = Pair::new(relay_map);
    let pair = match switching_side {
        Side::Client => pair
            .server(server, async move |_dev, _ep, conn| {
                do_observe(conn, timeout, kind).await
            })
            .client(client, async move |dev, _ep, conn| {
                do_switch(dev, conn, timeout, to_id).await
            }),
        Side::Server => pair
            .server(server, async move |dev, _ep, conn| {
                do_switch(dev, conn, timeout, to_id).await
            })
            .client(client, async move |_dev, _ep, conn| {
                do_observe(conn, timeout, kind).await
            }),
    };
    pair.run().await?;

    guard.ok();
    Ok(())
}

// --- Client switches uplink ---

#[tokio::test]
#[traced_test]
async fn switch_client_v4_to_v4() -> Result {
    run_switch_uplink(Side::Client, SwitchKind::V4ToV4).await
}

#[tokio::test]
#[traced_test]
async fn switch_client_v4_to_v6() -> Result {
    run_switch_uplink(Side::Client, SwitchKind::V4ToV6).await
}

#[tokio::test]
#[traced_test]
async fn switch_client_v6_to_v4() -> Result {
    run_switch_uplink(Side::Client, SwitchKind::V6ToV4).await
}

#[tokio::test]
#[traced_test]
async fn switch_client_v6_to_v6() -> Result {
    run_switch_uplink(Side::Client, SwitchKind::V6ToV6).await
}

#[tokio::test]
#[traced_test]
async fn switch_client_dual_to_dual() -> Result {
    run_switch_uplink(Side::Client, SwitchKind::DualToDual).await
}

// --- Server switches uplink ---

#[tokio::test]
#[traced_test]
async fn switch_server_v4_to_v4() -> Result {
    run_switch_uplink(Side::Server, SwitchKind::V4ToV4).await
}

#[tokio::test]
#[traced_test]
async fn switch_server_v4_to_v6() -> Result {
    run_switch_uplink(Side::Server, SwitchKind::V4ToV6).await
}

#[tokio::test]
#[traced_test]
async fn switch_server_v6_to_v4() -> Result {
    run_switch_uplink(Side::Server, SwitchKind::V6ToV4).await
}

#[tokio::test]
#[traced_test]
async fn switch_server_v6_to_v6() -> Result {
    run_switch_uplink(Side::Server, SwitchKind::V6ToV6).await
}

#[tokio::test]
#[traced_test]
async fn switch_server_dual_to_dual() -> Result {
    run_switch_uplink(Side::Server, SwitchKind::DualToDual).await
}
