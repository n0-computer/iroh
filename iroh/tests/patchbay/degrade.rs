//! Degradation ladder: find where holepunching breaks under worsening conditions

use std::time::Duration;

use iroh::endpoint::Side;
use n0_error::{Result, StackResultExt, StdResultExt};
use n0_tracing_test::traced_test;
use patchbay::{LinkCondition, LinkDirection, Nat};
use testdir::testdir;
use tracing::info;

use super::util::{Pair, PathConnectionExt, lab_with_relay, ping_accept, ping_open};

/// A ladder of increasingly degraded real-world links, used to find where
/// hole-punching breaks.
///
/// Each rung models a plausible last-mile scenario rather than a synthetic
/// ramp. Loss is bursty (Gilbert-Elliott), the way real radio links drop
/// packets in fades and handovers, rather than independent per-packet loss, and
/// the mean burst grows as conditions worsen. Every rung is bandwidth-capped
/// with a buffer sized to its round-trip time (via [`rtt_ms`]), so queueing
/// delay and congestion loss appear as they do on a real bottleneck.
///
/// The first rungs walk through common degraded links, from good wifi to a
/// congested cellular connection, with loss rates that track measured medians:
/// good LTE and wifi sit under 1 %, cell-edge and congested links reach a few
/// percent. The last three cover distinct extremes: a geostationary satellite
/// (defined by its ~600 ms round trip), a barely-usable link at the edge of
/// coverage, and an absurd stress case past what any real link sustains, there
/// to find the point where the connection gives up entirely. Reordering, which
/// real links rarely exhibit above a fraction of a percent, is dropped.
///
/// [`rtt_ms`]: patchbay::LinkCondition::rtt_ms
const DEGRADE_LEVELS: &[LinkCondition] = &[
    // 0: good home wifi, 5 GHz, close to the access point.
    LinkCondition::new()
        .rate_mbit(100)
        .rtt_ms(16)
        .bursty_loss(0.1)
        .label("good-wifi"),
    // 1: congested 2.4 GHz wifi, interference and distance.
    LinkCondition::new()
        .rate_mbit(25)
        .rtt_ms(40)
        .jitter_ms(12)
        .loss_pct(1.0)
        .loss_burst_pkts(6)
        .label("congested-wifi"),
    // 2: LTE at the cell edge, weak signal.
    LinkCondition::new()
        .rate_mbit(8)
        .rtt_ms(90)
        .jitter_ms(15)
        .loss_pct(2.0)
        .loss_burst_pkts(8)
        .label("weak-4g"),
    // 3: degraded 3G, deep buffers (bufferbloat).
    LinkCondition::new()
        .rate_mbit(3)
        .rtt_ms(200)
        .jitter_ms(30)
        .loss_pct(3.0)
        .loss_burst_pkts(10)
        .label("slow-3g"),
    // 4: oversubscribed cellular under load, heavy bufferbloat.
    LinkCondition::new()
        .rate_kbit(1500)
        .rtt_ms(300)
        .jitter_ms(40)
        .loss_pct(5.0)
        .loss_burst_pkts(12)
        .label("congested-cellular"),
    // 5: a very bad cellular link, such as a moving vehicle in poor coverage:
    // low bandwidth, high latency, and heavy bursty loss.
    LinkCondition::new()
        .rate_kbit(800)
        .rtt_ms(450)
        .jitter_ms(60)
        .loss_pct(8.0)
        .loss_burst_pkts(20)
        .label("very-bad-cellular"),
    // 6: geostationary satellite (Viasat / HughesNet class). The ~600 ms round
    // trip is the defining impairment; loss stays modest.
    LinkCondition::new()
        .rate_mbit(25)
        .rtt_ms(600)
        .jitter_ms(40)
        .loss_pct(1.5)
        .loss_burst_pkts(6)
        .label("satellite"),
    // 7: barely-usable cellular or wifi at the edge of coverage. Low bandwidth,
    // heavy bufferbloat, and long loss bursts.
    LinkCondition::new()
        .rate_kbit(500)
        .rtt_ms(450)
        .jitter_ms(80)
        .loss_pct(12.0)
        .loss_burst_pkts(25)
        .label("barely-usable"),
    // 8: absurd stress case, past what any real link sustains, to find where the
    // connection gives up entirely.
    LinkCondition::new()
        .rate_kbit(256)
        .rtt_ms(800)
        .jitter_ms(150)
        .loss_pct(25.0)
        .loss_burst_pkts(40)
        .label("absurd"),
];

/// Runs a single degradation level.
///
/// Creates two devices behind Home NATs, applies the given [`LinkCondition`] to
/// `impaired_side`, then attempts to holepunch and ping. Returns the
/// [`TestGuard`] on success so the caller can mark it as passed.
async fn run_degrade_level(impaired_side: Side, level: usize) -> Result<()> {
    let (lab, relay_map, _relay_guard, guard) = lab_with_relay(testdir!()).await?;
    let nat1 = lab.add_router("nat1").nat(Nat::Moderate).build().await?;
    let nat2 = lab.add_router("nat2").nat(Nat::Moderate).build().await?;
    let timeout = Duration::from_secs(20 + level as u64 * 10);

    let limits = DEGRADE_LEVELS[level];

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
        .set_condition(limits, LinkDirection::Both)
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
                info!("waiting for connection to become direct");
                conn.wait_ip(timeout).await.context("holepunch to direct")?;
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
            loss_burst_pkts = ?limits.loss_burst_pkts,
            impaired_side = ?impaired_side,
            "PASSED",
        ),
        Err(err) => tracing::event!(
            target: "test::_events::ladder_fail",
            tracing::Level::WARN,
            level,
            latency_ms = limits.latency_ms,
            loss_pct = limits.loss_pct,
            loss_burst_pkts = ?limits.loss_burst_pkts,
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
async fn degrade_server_good_wifi() -> Result {
    run_degrade_level(Side::Server, 0).await
}

#[tokio::test]
#[traced_test]
async fn degrade_server_congested_wifi() -> Result {
    run_degrade_level(Side::Server, 1).await
}

#[tokio::test]
#[traced_test]
async fn degrade_server_weak_4g() -> Result {
    run_degrade_level(Side::Server, 2).await
}

#[tokio::test]
#[traced_test]
async fn degrade_server_slow_3g() -> Result {
    run_degrade_level(Side::Server, 3).await
}

// Still too flaky.
// #[tokio::test]
// #[traced_test]
// async fn degrade_server_congested_cellular() -> Result {
//     run_degrade_level(Side::Server, 4).await
// }

#[tokio::test]
#[traced_test]
async fn degrade_server_very_bad_cellular() -> Result {
    run_degrade_level(Side::Server, 5).await
}

#[tokio::test]
#[traced_test]
async fn degrade_server_satellite() -> Result {
    run_degrade_level(Side::Server, 6).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing"]
async fn degrade_server_barely_usable() -> Result {
    run_degrade_level(Side::Server, 7).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing"]
async fn degrade_server_absurd() -> Result {
    run_degrade_level(Side::Server, 8).await
}

#[tokio::test]
#[traced_test]
async fn degrade_client_good_wifi() -> Result {
    run_degrade_level(Side::Client, 0).await
}

#[tokio::test]
#[traced_test]
async fn degrade_client_congested_wifi() -> Result {
    run_degrade_level(Side::Client, 1).await
}

#[tokio::test]
#[traced_test]
async fn degrade_client_weak_4g() -> Result {
    run_degrade_level(Side::Client, 2).await
}

#[tokio::test]
#[traced_test]
async fn degrade_client_slow_3g() -> Result {
    run_degrade_level(Side::Client, 3).await
}

#[tokio::test]
#[traced_test]
async fn degrade_client_congested_cellular() -> Result {
    run_degrade_level(Side::Client, 4).await
}

#[tokio::test]
#[traced_test]
async fn degrade_client_very_bad_cellular() -> Result {
    run_degrade_level(Side::Client, 5).await
}

#[tokio::test]
#[traced_test]
async fn degrade_client_satellite() -> Result {
    run_degrade_level(Side::Client, 6).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing"]
async fn degrade_client_barely_usable() -> Result {
    run_degrade_level(Side::Client, 7).await
}

#[tokio::test]
#[traced_test]
#[ignore = "not yet passing"]
async fn degrade_client_absurd() -> Result {
    run_degrade_level(Side::Client, 8).await
}
