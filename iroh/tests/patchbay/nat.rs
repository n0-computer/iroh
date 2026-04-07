//! NAT traversal matrix tests.
//!
//! Tests holepunching across combinations of NAT types (None, Home, Corporate).
//!
//! - None: no NAT, publicly routable
//! - Home: endpoint-independent mapping (EIM), address-and-port-dependent
//!   filtering (APDF), port-preserving (typical home router)
//! - Corporate: endpoint-dependent mapping (EDM), APDF, random ports per
//!   destination (enterprise firewall, cloud NAT)
//!
//! Every test expects a direct path to be established. Tests where holepunching
//! is not yet working are marked `#[ignore]`.

use std::time::Duration;

use iroh::endpoint::ConnectionType;
use n0_error::{Result, StackResultExt};
use n0_tracing_test::traced_test;
use patchbay::{Nat, NatConfig, NatFiltering, NatMapping};
use testdir::testdir;
use tracing::info;

use super::util::{lab_with_relay, Pair, PathWatcherExt};
use crate::util::{ping_accept, ping_open};

enum NatKind {
    /// No NAT. The device has a publicly routable address.
    None,
    /// Most permissive NAT.
    ///
    /// Typical of consumer routers with UPnP or static port forwarding.
    ///
    /// RFC 4787: Endpoint-Independent Mapping, Endpoint-Independent Filtering (EIM/EIF).
    /// RFC 3489: Full Cone NAT.
    Easiest,
    /// Moderately restrictive NAT.
    ///
    /// The external mapping is stable across destinations, but inbound packets are filtered
    /// by source address and port. Common in home routers without UPnP.
    ///
    /// RFC 4787: Endpoint-Independent Mapping, Address-and-Port-Dependent Filtering (EIM/APDF).
    /// RFC 3489: Port Restricted Cone NAT.
    Easy,
    /// Most restrictive NAT.
    ///
    /// Each destination gets a different external mapping, and inbound packets are filtered
    /// by source address and port. Holepunching between two Hard NATs is usually not possible
    /// or only with port guessing via birthday paradox.
    /// Typical of corporate firewalls and carrier-grade NAT (CGN).
    ///
    /// RFC 4787: Endpoint-Dependent Mapping, Address-and-Port-Dependent Filtering (EDM/APDF).
    /// RFC 3489: Symmetric NAT.
    Hard,
}

impl From<NatKind> for Nat {
    fn from(value: NatKind) -> Self {
        let (mapping, filtering) = match value {
            NatKind::None => return Nat::None,
            NatKind::Easiest => (
                NatMapping::EndpointIndependent,
                NatFiltering::EndpointIndependent,
            ),
            NatKind::Easy => (
                NatMapping::EndpointIndependent,
                NatFiltering::AddressAndPortDependent,
            ),
            NatKind::Hard => (
                NatMapping::EndpointDependent,
                NatFiltering::AddressAndPortDependent,
            ),
        };
        Nat::Custom(NatConfig {
            mapping,
            filtering,
            timeouts: Default::default(),
            hairpin: false,
        })
    }
}

async fn run_nat_holepunch(nat_server: NatKind, nat_client: NatKind) -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let router_server = lab
        .add_router("nat_server")
        .nat(nat_server.into())
        .build()
        .await?;
    let router_client = lab
        .add_router("nat_client")
        .nat(nat_client.into())
        .build()
        .await?;
    let server = lab
        .add_device("server")
        .uplink(router_server.id())
        .build()
        .await?;
    let client = lab
        .add_device("client")
        .uplink(router_client.id())
        .build()
        .await?;

    let timeout = Duration::from_secs(15);
    Pair::new(relay_map)
        .server(server, async move |_dev, ep, conn| {
            let mut paths = ep.conn_type(conn.remote_node_id()?)?;
            // assert!(
            //     matches!(paths.selected(), ConnectionType::Relay(_)),
            //     "connection started relayed"
            // );
            paths
                .wait_ip(timeout)
                .await
                .context("holepunch to direct")?;
            info!("connection became direct");
            ping_accept(&conn, timeout).await?;
            conn.closed().await;
            Ok(())
        })
        .client(client, async move |_dev, ep, conn| {
            let mut paths = ep.conn_type(conn.remote_node_id()?)?;
            // assert!(
            //     matches!(paths.selected(), ConnectionType::Relay(_)),
            //     "connection started relayed"
            // );
            paths
                .wait_ip(timeout)
                .await
                .context("holepunch to direct")?;
            info!("connection became direct");
            ping_open(&conn, timeout).await?;
            conn.close(0u32.into(), b"bye");
            Ok(())
        })
        .run()
        .await?;

    guard.ok();
    Ok(())
}

// None x *

#[tokio::test]
#[traced_test]
async fn nat_none_x_none() -> Result {
    run_nat_holepunch(NatKind::None, NatKind::None).await
}

#[tokio::test]
#[traced_test]
async fn nat_none_x_easiest() -> Result {
    run_nat_holepunch(NatKind::None, NatKind::Easiest).await
}

#[tokio::test]
#[traced_test]
async fn nat_none_x_easy() -> Result {
    run_nat_holepunch(NatKind::None, NatKind::Easy).await
}

#[tokio::test]
#[traced_test]
async fn nat_none_x_hard() -> Result {
    run_nat_holepunch(NatKind::None, NatKind::Hard).await
}

// Easiest x *

#[tokio::test]
#[traced_test]
async fn nat_easiest_x_none() -> Result {
    run_nat_holepunch(NatKind::Easiest, NatKind::None).await
}

#[tokio::test]
#[traced_test]
async fn nat_easiest_x_easiest() -> Result {
    run_nat_holepunch(NatKind::Easiest, NatKind::Easiest).await
}

#[tokio::test]
#[traced_test]
async fn nat_easiest_x_easy() -> Result {
    run_nat_holepunch(NatKind::Easiest, NatKind::Easy).await
}

#[tokio::test]
#[traced_test]
async fn nat_easiest_x_hard() -> Result {
    run_nat_holepunch(NatKind::Easiest, NatKind::Hard).await
}

// Easy x *

#[tokio::test]
#[traced_test]
async fn nat_easy_x_none() -> Result {
    run_nat_holepunch(NatKind::Easy, NatKind::None).await
}

#[tokio::test]
#[traced_test]
async fn nat_easy_x_easiest() -> Result {
    run_nat_holepunch(NatKind::Easy, NatKind::Easiest).await
}

#[tokio::test]
#[traced_test]
async fn nat_easy_x_easy() -> Result {
    run_nat_holepunch(NatKind::Easy, NatKind::Easy).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing (and likely can't without port guessing)"]
async fn nat_easy_x_hard() -> Result {
    run_nat_holepunch(NatKind::Easy, NatKind::Hard).await
}

// Hard x *

#[tokio::test]
#[traced_test]
async fn nat_hard_x_none() -> Result {
    run_nat_holepunch(NatKind::Hard, NatKind::None).await
}

#[tokio::test]
#[traced_test]
async fn nat_hard_x_easiest() -> Result {
    run_nat_holepunch(NatKind::Hard, NatKind::Easiest).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing (and likely can't without port guessing)"]
async fn nat_hard_x_easy() -> Result {
    run_nat_holepunch(NatKind::Hard, NatKind::Easy).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing (and likely can't without port guessing)"]
async fn nat_hard_x_hard() -> Result {
    run_nat_holepunch(NatKind::Hard, NatKind::Hard).await
}
