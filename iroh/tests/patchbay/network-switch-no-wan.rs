//! Local address advertisement across network changes without relay connectivity.
//!
//! Originally introduced as regression coverage for
//! <https://github.com/n0-computer/iroh/issues/4588>.

use std::{net::IpAddr, time::Duration};

use iroh::{Endpoint, EndpointAddr, RelayMode, Watcher, endpoint::presets};
use n0_error::{Result, StackResultExt, StdResultExt, anyerr};
use n0_future::StreamExt;
use n0_tracing_test::traced_test;
use patchbay::{Lab, RouterPreset};
use testdir::testdir;
use tracing::info;

/// A device moving between local networks without a relay or internet access.
///
/// When it switches networks, the endpoint should advertise its new address and
/// stop advertising the old one. We switch twice to check that this keeps working
/// after the first change.
///
/// Prior to a regression, this test failed by timing out the 8 second limit of
/// switching to a new direct path, because it would only recover after the ~26-second
/// periodic re-stun.
#[tokio::test]
#[traced_test]
async fn lan_switch_advertises_new_addr_without_relay() -> Result {
    let (lab, _guard) = Lab::for_test(testdir!()).await?;

    let lan_a = lab
        .add_router("lan-a")
        .preset(RouterPreset::Home)
        .build()
        .await?
        .id();
    let lan_b = lab
        .add_router("lan-b")
        .preset(RouterPreset::Home)
        .build()
        .await?
        .id();
    let lan_c = lab
        .add_router("lan-c")
        .preset(RouterPreset::Home)
        .build()
        .await?
        .id();
    let device = lab.add_device("device").uplink(lan_a).build().await?;

    let task = device.spawn(move |dev| async move {
        let ep = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;

        let result = async {
            let ip_a = IpAddr::V4(dev.ip().expect("device has IPv4 on lan-a"));
            wait_addr(&ep, |addr| addr.ip_addrs().any(|a| a.ip() == ip_a))
                .await
                .context("initial address advertisement")?;

            dev.iface("eth0")
                .expect("eth0")
                .replug(lan_b)
                .await
                .context("switch to lan-b")?;
            let ip_b = IpAddr::V4(dev.ip().expect("device has IPv4 on lan-b"));
            info!(?ip_b, "switched to lan-b");
            wait_addr(&ep, |addr| {
                addr.ip_addrs().any(|a| a.ip() == ip_b) && !addr.ip_addrs().any(|a| a.ip() == ip_a)
            })
            .await
            .context("address advertisement after switch to lan-b")?;

            dev.iface("eth0")
                .expect("eth0")
                .replug(lan_c)
                .await
                .context("switch to lan-c")?;
            let ip_c = IpAddr::V4(dev.ip().expect("device has IPv4 on lan-c"));
            info!(?ip_c, "switched to lan-c");
            wait_addr(&ep, |addr| {
                addr.ip_addrs().any(|a| a.ip() == ip_c)
                    && !addr.ip_addrs().any(|a| a.ip() == ip_a || a.ip() == ip_b)
            })
            .await
            .context("address advertisement after switch to lan-c")?;
            Ok::<(), n0_error::AnyError>(())
        }
        .await;

        ep.close().await;
        result
    })?;

    task.await
        .map_err(|err| anyerr!("device task panicked: {err}"))??;
    Ok(())
}

async fn wait_addr(ep: &Endpoint, matches: impl Fn(&EndpointAddr) -> bool) -> Result {
    // Stay below the periodic refresh interval so it cannot mask a missed link change.
    tokio::time::timeout(Duration::from_secs(8), async {
        let mut stream = ep.watch_addr().stream();
        while let Some(addr) = stream.next().await {
            info!(?addr, "advertised addresses");
            if matches(&addr) {
                return Ok(());
            }
        }
        Err(anyerr!("address stream ended"))
    })
    .await
    .std_context("timed out waiting for address advertisement")?
}
