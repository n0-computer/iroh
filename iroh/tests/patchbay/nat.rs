//! NAT traversal matrix tests.
//!
//! Tests holepunching across combinations of the upstream [`patchbay::Nat`]
//! behavior tiers:
//!
//! - `None`: no NAT, publicly routable.
//! - `Open`: endpoint-independent mapping (EIM), endpoint-independent
//!   filtering (EIF); RFC 3489 full cone. Typical of routers with UPnP or
//!   static port forwarding.
//! - `Moderate`: EIM, address-and-port-dependent filtering (APDF); RFC 3489
//!   port-restricted cone. The typical home router.
//! - `Strict`: endpoint-dependent mapping (EDM) with random ports, APDF; RFC
//!   3489 symmetric. Holepunching between two `Strict` NATs requires a relay.
//!
//! Every test expects a direct path to be established. Tests where holepunching
//! is not yet working are marked `#[ignore]`.

use std::time::Duration;

use n0_error::{Result, StackResultExt};
use n0_tracing_test::traced_test;
use patchbay::Nat;
use testdir::testdir;
use tracing::info;

use super::util::{Pair, PathConnectionExt, lab_with_relay};
use crate::util::{is_relayed, ping_accept, ping_open};

async fn run_nat_holepunch(nat_server: Nat, nat_client: Nat) -> Result {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let router_server = lab.add_router("nat_server").nat(nat_server).build().await?;
    let router_client = lab.add_router("nat_client").nat(nat_client).build().await?;
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
        .server(server, async move |_dev, _ep, conn| {
            assert!(is_relayed(&conn), "connection started relayed");
            conn.wait_ip(timeout).await.context("holepunch to direct")?;
            info!("connection became direct");
            ping_accept(&conn, timeout).await?;
            conn.closed().await;
            Ok(())
        })
        .client(client, async move |_dev, _ep, conn| {
            assert!(is_relayed(&conn), "connection started relayed");
            conn.wait_ip(timeout).await.context("holepunch to direct")?;
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
    run_nat_holepunch(Nat::None, Nat::None).await
}

#[tokio::test]
#[traced_test]
async fn nat_none_x_open() -> Result {
    run_nat_holepunch(Nat::None, Nat::Open).await
}

#[tokio::test]
#[traced_test]
async fn nat_none_x_moderate() -> Result {
    run_nat_holepunch(Nat::None, Nat::Moderate).await
}

#[tokio::test]
#[traced_test]
async fn nat_none_x_strict() -> Result {
    run_nat_holepunch(Nat::None, Nat::Strict).await
}

// Open x *

#[tokio::test]
#[traced_test]
async fn nat_open_x_none() -> Result {
    run_nat_holepunch(Nat::Open, Nat::None).await
}

#[tokio::test]
#[traced_test]
async fn nat_open_x_open() -> Result {
    run_nat_holepunch(Nat::Open, Nat::Open).await
}

#[tokio::test]
#[traced_test]
async fn nat_open_x_moderate() -> Result {
    run_nat_holepunch(Nat::Open, Nat::Moderate).await
}

#[tokio::test]
#[traced_test]
async fn nat_open_x_strict() -> Result {
    run_nat_holepunch(Nat::Open, Nat::Strict).await
}

// Moderate x *

#[tokio::test]
#[traced_test]
async fn nat_moderate_x_none() -> Result {
    run_nat_holepunch(Nat::Moderate, Nat::None).await
}

#[tokio::test]
#[traced_test]
async fn nat_moderate_x_open() -> Result {
    run_nat_holepunch(Nat::Moderate, Nat::Open).await
}

#[tokio::test]
#[traced_test]
async fn nat_moderate_x_moderate() -> Result {
    run_nat_holepunch(Nat::Moderate, Nat::Moderate).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing (and likely can't without port guessing)"]
async fn nat_moderate_x_strict() -> Result {
    run_nat_holepunch(Nat::Moderate, Nat::Strict).await
}

// Strict x *

#[tokio::test]
#[traced_test]
async fn nat_strict_x_none() -> Result {
    run_nat_holepunch(Nat::Strict, Nat::None).await
}

#[tokio::test]
#[traced_test]
async fn nat_strict_x_open() -> Result {
    run_nat_holepunch(Nat::Strict, Nat::Open).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing (and likely can't without port guessing)"]
async fn nat_strict_x_moderate() -> Result {
    run_nat_holepunch(Nat::Strict, Nat::Moderate).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing (and likely can't without port guessing)"]
async fn nat_strict_x_strict() -> Result {
    run_nat_holepunch(Nat::Strict, Nat::Strict).await
}
