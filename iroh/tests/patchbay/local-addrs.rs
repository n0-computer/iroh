//! Local address tests.
//!
//! An endpoint must advertise its local addresses as soon as the network
//! changes, also when it has no relays and thus no net report results. These
//! are regression tests for <https://github.com/n0-computer/iroh/issues/4588>.

use std::{net::IpAddr, time::Duration};

use iroh::{Endpoint, RelayMap, RelayMode};
use n0_error::{Result, StdResultExt};
use n0_tracing_test::traced_test;
use patchbay::{Lab, Nat};
use testdir::testdir;
use tracing::info;

use crate::util::endpoint_builder;

/// How long a local address may take to show up in [`Endpoint::addr`].
const TIMEOUT: Duration = Duration::from_secs(5);

/// Waits until the set of advertised IP addresses satisfies `f`.
async fn wait_for_addrs(ep: &Endpoint, f: impl Fn(&[IpAddr]) -> bool) -> Result {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            let ips: Vec<IpAddr> = ep.addr().ip_addrs().map(|a| a.ip()).collect();
            if f(&ips) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .with_std_context(|_| {
        let addr = ep.addr();
        let ips: Vec<_> = addr.ip_addrs().collect();
        format!("advertised addresses did not update within {TIMEOUT:?}: {ips:?}")
    })
}

/// Binds an endpoint without relays.
async fn bind_without_relays(dev: &patchbay::Device) -> Result<Endpoint> {
    endpoint_builder(dev, RelayMap::empty())
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .anyerr()
}

/// Replugging to another LAN advertises the new local address.
#[tokio::test]
#[traced_test]
async fn local_addr_after_replug_without_relays() -> Result {
    let (lab, guard) = Lab::for_test(testdir!()).await?;
    let lan_a = lab.add_router("lan_a").nat(Nat::Moderate).build().await?;
    let lan_b = lab.add_router("lan_b").nat(Nat::Moderate).build().await?;
    let dev = lab.add_device("dev").uplink(lan_a.id()).build().await?;
    let lan_b = lan_b.id();

    let task = dev.spawn(move |dev| async move {
        let ep = bind_without_relays(&dev).await?;
        let ip_a: IpAddr = dev.ip().unwrap().into();
        wait_for_addrs(&ep, |ips| ips.contains(&ip_a)).await?;

        info!("replug to the other LAN");
        dev.iface("eth0").unwrap().replug(lan_b).await?;
        let ip_b: IpAddr = dev.iface("eth0").unwrap().ip().unwrap().into();
        wait_for_addrs(&ep, |ips| ips.contains(&ip_b) && !ips.contains(&ip_a)).await?;
        Ok::<_, n0_error::AnyError>(())
    })?;
    task.await.anyerr()??;
    guard.ok();
    Ok(())
}

/// Taking the link down drops the address, bringing it up restores it.
#[tokio::test]
#[traced_test]
async fn local_addr_after_link_down_up_without_relays() -> Result {
    let (lab, guard) = Lab::for_test(testdir!()).await?;
    let lan = lab.add_router("lan").nat(Nat::Moderate).build().await?;
    let dev = lab.add_device("dev").uplink(lan.id()).build().await?;

    let task = dev.spawn(move |dev| async move {
        let ep = bind_without_relays(&dev).await?;
        let ip: IpAddr = dev.ip().unwrap().into();
        wait_for_addrs(&ep, |ips| ips.contains(&ip)).await?;

        info!("link down");
        dev.iface("eth0").unwrap().link_down().await?;
        wait_for_addrs(&ep, |ips| !ips.contains(&ip)).await?;

        info!("link up");
        dev.iface("eth0").unwrap().link_up().await?;
        let ip: IpAddr = dev.iface("eth0").unwrap().ip().unwrap().into();
        wait_for_addrs(&ep, |ips| ips.contains(&ip)).await?;
        Ok::<_, n0_error::AnyError>(())
    })?;
    task.await.anyerr()??;
    guard.ok();
    Ok(())
}
