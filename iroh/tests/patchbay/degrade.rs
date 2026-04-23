//! Degradation ladder: find where holepunching breaks under worsening conditions

use std::time::Duration;

use iroh::endpoint::Side;
use n0_error::{Result, StackResultExt, StdResultExt};
use n0_tracing_test::traced_test;
use patchbay::{LinkCondition, LinkDirection, LinkLimits, Nat};
use testdir::testdir;
use tracing::info;

use super::util::{Pair, PathWatcherExt, lab_with_relay, ping_accept, ping_open};

/// Increasingly degraded link conditions applied to one side of the connection.
///
/// Each level adds more latency, loss, and reordering. The levels are tested
/// individually for both server-side and client-side impairment.
const DEGRADE_LEVELS: &[LinkLimits] = &[
    // 0: mild - good wifi
    LinkLimits {
        latency_ms: 10,
        jitter_ms: 5,
        loss_pct: 0.5,
        reorder_pct: 0.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    },
    // 1: poor - bad wifi or 3G
    LinkLimits {
        latency_ms: 100,
        jitter_ms: 30,
        loss_pct: 3.0,
        reorder_pct: 3.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    },
    // 2: bad - congested 3G
    LinkLimits {
        latency_ms: 200,
        jitter_ms: 60,
        loss_pct: 5.0,
        reorder_pct: 5.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    },
    // 3: terrible - barely usable
    LinkLimits {
        latency_ms: 300,
        jitter_ms: 80,
        loss_pct: 8.0,
        reorder_pct: 8.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    },
    // 4: extreme - GEO satellite with heavy loss
    LinkLimits {
        latency_ms: 500,
        jitter_ms: 100,
        loss_pct: 12.0,
        reorder_pct: 12.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    },
    // 5: absurd - stress test
    LinkLimits {
        latency_ms: 800,
        jitter_ms: 200,
        loss_pct: 20.0,
        reorder_pct: 20.0,
        rate_kbit: 0,
        duplicate_pct: 0.0,
        corrupt_pct: 0.0,
    },
];

/// Runs a single degradation level.
///
/// Creates two devices behind Home NATs, applies the given [`LinkLimits`] to
/// `impaired_side`, then attempts to holepunch and ping. Returns the
/// [`TestGuard`] on success so the caller can mark it as passed.
async fn run_degrade_level(impaired_side: Side, level: usize) -> Result<()> {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Home).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Home).build().await?;
    let timeout = Duration::from_secs(20 + level as u64 * 10);

    let limits = DEGRADE_LEVELS[level];
    let link_condition = LinkCondition::Manual(limits);

    let server = lab
        .add_device("server")
        .iface("eth0", nat1.id())
        .build()
        .await?;
    let client = lab
        .add_device("client")
        .iface("eth0", nat2.id())
        .build()
        .await?;
    let impaired_device = match impaired_side {
        Side::Client => &client,
        Side::Server => &server,
    };
    impaired_device
        .iface("eth0")
        .unwrap()
        .set_condition(link_condition, LinkDirection::Both)
        .await?;

    info!(?impaired_side, ?limits, %level, ?timeout, "degrade test start");

    let result = tokio::time::timeout(
        timeout,
        Pair::new(relay_map)
            .server(server, async move |_dev, _ep, conn| {
                ping_accept(&conn, timeout).await.context("ping_accept")?;
                conn.closed().await;
                Ok(())
            })
            .client(client, async move |_dev, _ep, conn| {
                let mut paths = conn.paths();
                info!("waiting for connection to become direct");
                paths
                    .wait_ip(timeout)
                    .await
                    .context("holepunch to direct")?;
                info!("direct path established, sending ping");
                ping_open(&conn, timeout).await.context("ping_open")?;
                info!("ping complete");
                conn.close(0u32.into(), b"bye");
                Ok(())
            })
            .run(),
    )
    .await
    .std_context("pair timed out")
    .flatten();

    match &result {
        Ok(()) => tracing::event!(
            target: "test::_events::ladder_pass",
            tracing::Level::INFO,
            level,
            latency_ms = limits.latency_ms,
            loss_pct = limits.loss_pct,
            reorder_pct = limits.reorder_pct,
            impaired_side = ?impaired_side,
            "PASSED",
        ),
        Err(err) => tracing::event!(
            target: "test::_events::ladder_fail",
            tracing::Level::WARN,
            level,
            latency_ms = limits.latency_ms,
            loss_pct = limits.loss_pct,
            reorder_pct = limits.reorder_pct,
            impaired_side = ?impaired_side,
            error = format!("{err:#}"),
            "FAILED",
        ),
    }

    result?;
    guard.ok();
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn degrade_server_0_mild() -> Result {
    run_degrade_level(Side::Server, 0).await
}

#[tokio::test]
#[traced_test]
async fn degrade_server_1_poor() -> Result {
    run_degrade_level(Side::Server, 1).await
}

#[tokio::test]
#[traced_test]
async fn degrade_server_2_bad() -> Result {
    run_degrade_level(Side::Server, 2).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing reliably"]
async fn degrade_server_3_terrible() -> Result {
    run_degrade_level(Side::Server, 3).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing reliably"]
async fn degrade_server_4_extreme() -> Result {
    run_degrade_level(Side::Server, 4).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing reliably"]
async fn degrade_server_5_absurd() -> Result {
    run_degrade_level(Side::Server, 5).await
}

#[tokio::test]
#[traced_test]
async fn degrade_client_0_mild() -> Result {
    run_degrade_level(Side::Client, 0).await
}

#[tokio::test]
#[traced_test]
async fn degrade_client_1_poor() -> Result {
    run_degrade_level(Side::Client, 1).await
}

#[tokio::test]
#[traced_test]
async fn degrade_client_2_bad() -> Result {
    run_degrade_level(Side::Client, 2).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing reliably"]
async fn degrade_client_3_terrible() -> Result {
    run_degrade_level(Side::Client, 3).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing reliably"]
async fn degrade_client_4_extreme() -> Result {
    run_degrade_level(Side::Client, 4).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing reliably"]
async fn degrade_client_5_absurd() -> Result {
    run_degrade_level(Side::Client, 5).await
}
