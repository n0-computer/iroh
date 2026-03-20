// ---
// NetReport tests
// ---

/// Home NAT (EIM+APDF): the most common consumer router.
/// Expect UDP v4, a NATted public address (different from the device's private IP),
/// relay reachability with measured latency, and no captive portal.
#[tokio::test]
#[traced_test]
async fn netreport_home_nat() -> Result {
    let (lab, relay_map, _relay_guard) = lab_with_relay(testdir!()).await?;
    let nat = lab.add_router("nat").nat(Nat::Home).build().await?;
    let dev = lab.add_device("dev").uplink(nat.id()).build().await?;
    let dev_ip = dev.ip().expect("device has IPv4");
    let report = run_net_report(dev, relay_map).await?;
    assert!(report.udp_v4, "expected UDP v4 through home NAT");
    let global_v4 = report.global_v4.expect("expected global IPv4 address");
    assert_ne!(
        *global_v4.ip(),
        dev_ip,
        "global IP should differ from device private IP behind NAT"
    );
    let relay = report
        .preferred_relay
        .expect("expected relay to be reachable");
    assert!(
        report.relay_latency.iter().any(|(_, url, _)| *url == relay),
        "expected latency data for preferred relay"
    );
    Ok(())
}

/// Corporate (symmetric) NAT: produces a different external port
/// per destination. Holepunching requires relay, but relay should be reachable.
#[tokio::test]
#[traced_test]
async fn netreport_corporate_nat() -> Result {
    let (lab, relay_map, _relay_guard) = lab_with_relay(testdir!()).await?;
    let nat = lab.add_router("nat").nat(Nat::Corporate).build().await?;
    let dev = lab.add_device("dev").uplink(nat.id()).build().await?;
    let dev_ip = dev.ip().expect("device has IPv4");
    let report = run_net_report(dev, relay_map).await?;
    assert!(report.udp_v4, "expected UDP v4 through corporate NAT");
    let global_v4 = report.global_v4.expect("expected global IPv4 address");
    assert_ne!(
        *global_v4.ip(),
        dev_ip,
        "global IP should differ from device private IP behind symmetric NAT"
    );
    let relay = report
        .preferred_relay
        .expect("expected relay to be reachable");
    assert!(
        report.relay_latency.iter().any(|(_, url, _)| *url == relay),
        "expected latency data for preferred relay"
    );
    Ok(())
}

/// Direct connection (no NAT). The reported global_v4 should equal the
/// device's own IP since there is no address translation.
#[tokio::test]
#[traced_test]
async fn netreport_direct() -> Result {
    let (lab, relay_map, _relay_guard) = lab_with_relay(testdir!()).await?;
    let router = lab.add_router("direct").build().await?; // Nat::None by default
    let dev = lab.add_device("dev").uplink(router.id()).build().await?;
    let dev_ip = dev.ip().expect("device has IPv4");
    let report = run_net_report(dev, relay_map).await?;
    assert!(report.udp_v4, "expected UDP v4 on direct connection");
    let global_v4 = report.global_v4.expect("expected global IPv4 address");
    assert_eq!(
        *global_v4.ip(),
        dev_ip,
        "without NAT, global IP should equal device's own IP"
    );
    let relay = report
        .preferred_relay
        .expect("expected relay to be reachable");
    assert!(
        report.relay_latency.iter().any(|(_, url, _)| *url == relay),
        "expected latency data for preferred relay"
    );
    Ok(())
}

// ---
// NetReport: additional NAT topologies
// ---

/// Full cone NAT (EIM+EIF): most permissive NAT. Port-preserving, hairpin enabled.
/// Holepunching always succeeds. Same expectations as Home NAT for net_report.
#[tokio::test]
#[traced_test]
async fn netreport_full_cone() -> Result {
    let (lab, relay_map, _relay_guard) = lab_with_relay(testdir!()).await?;
    let nat = lab.add_router("nat").nat(Nat::FullCone).build().await?;
    let dev = lab.add_device("dev").uplink(nat.id()).build().await?;
    let dev_ip = dev.ip().expect("device has IPv4");
    let report = run_net_report(dev, relay_map).await?;
    assert!(report.udp_v4, "expected UDP v4 through full cone NAT");
    let global_v4 = report.global_v4.expect("expected global IPv4 address");
    assert_ne!(
        *global_v4.ip(),
        dev_ip,
        "global IP should differ from device private IP behind NAT"
    );
    let relay = report
        .preferred_relay
        .expect("expected relay to be reachable");
    assert!(
        report.relay_latency.iter().any(|(_, url, _)| *url == relay),
        "expected latency data for preferred relay"
    );
    assert_ne!(
        report.captive_portal,
        Some(true),
        "no captive portal expected"
    );
    Ok(())
}

/// Cloud NAT (EDM+APDF): symmetric NAT with randomized ports, similar to corporate
/// but with longer UDP timeout (350s). Common in cloud providers (GCP, AWS).
#[tokio::test]
#[traced_test]
async fn netreport_cloud_nat() -> Result {
    let (lab, relay_map, _relay_guard) = lab_with_relay(testdir!()).await?;
    let nat = lab.add_router("nat").nat(Nat::CloudNat).build().await?;
    let dev = lab.add_device("dev").uplink(nat.id()).build().await?;
    let dev_ip = dev.ip().expect("device has IPv4");
    let report = run_net_report(dev, relay_map).await?;
    assert!(report.udp_v4, "expected UDP v4 through cloud NAT");
    let global_v4 = report.global_v4.expect("expected global IPv4 address");
    assert_ne!(
        *global_v4.ip(),
        dev_ip,
        "global IP should differ from device private IP behind cloud NAT"
    );
    let relay = report
        .preferred_relay
        .expect("expected relay to be reachable");
    assert!(
        report.relay_latency.iter().any(|(_, url, _)| *url == relay),
        "expected latency data for preferred relay"
    );
    assert_ne!(
        report.captive_portal,
        Some(true),
        "no captive portal expected"
    );
    Ok(())
}

/// Standalone CGNAT (EIM+EIF): carrier-grade NAT without a home router in front.
/// Common for mobile carriers. More permissive filtering than Home NAT.
#[tokio::test]
#[traced_test]
async fn netreport_cgnat() -> Result {
    let (lab, relay_map, _relay_guard) = lab_with_relay(testdir!()).await?;
    let nat = lab.add_router("nat").nat(Nat::Cgnat).build().await?;
    let dev = lab.add_device("dev").uplink(nat.id()).build().await?;
    let dev_ip = dev.ip().expect("device has IPv4");
    let report = run_net_report(dev, relay_map).await?;
    assert!(report.udp_v4, "expected UDP v4 through CGNAT");
    let global_v4 = report.global_v4.expect("expected global IPv4 address");
    assert_ne!(
        *global_v4.ip(),
        dev_ip,
        "global IP should differ from device private IP behind CGNAT"
    );
    let relay = report
        .preferred_relay
        .expect("expected relay to be reachable");
    assert!(
        report.relay_latency.iter().any(|(_, url, _)| *url == relay),
        "expected latency data for preferred relay"
    );
    assert_ne!(
        report.captive_portal,
        Some(true),
        "no captive portal expected"
    );
    Ok(())
}

// ---
// NetReport: firewall scenarios
// ---

/// Corporate firewall blocks all UDP except DNS (port 53). QAD probes fail,
/// but the relay is still reachable via HTTPS on port 443.
#[tokio::test]
#[traced_test]
async fn netreport_corporate_firewall() -> Result {
    let (lab, relay_map, _relay_guard) = lab_with_relay(testdir!()).await?;
    let fw = lab
        .add_router("fw")
        .firewall(Firewall::Corporate)
        .build()
        .await?;
    let dev = lab.add_device("dev").uplink(fw.id()).build().await?;
    let report = run_net_report(dev, relay_map).await?;
    assert!(
        !report.udp_v4,
        "UDP should be blocked by corporate firewall"
    );
    assert!(
        report.global_v4.is_none(),
        "no global IPv4 without successful QAD probes"
    );
    assert!(
        report.preferred_relay.is_some(),
        "relay should still be reachable via HTTPS (TCP 443)"
    );
    assert_ne!(
        report.captive_portal,
        Some(true),
        "no captive portal expected"
    );
    Ok(())
}

// ---
// NetReport: dual-stack / IPv6
// ---

/// Dual-stack device on a direct (no NAT) connection with a dual-stack relay.
/// Both IPv4 and IPv6 QAD probes should succeed. Without NAT, the reported
/// global addresses should match the device's own addresses.
#[tokio::test]
#[traced_test]
async fn netreport_dual_stack_direct() -> Result {
    let (lab, relay_map, _relay_guard) = lab_with_relay(testdir!()).await?;
    let router = lab
        .add_router("direct")
        .ip_support(IpSupport::DualStack)
        .build()
        .await?;
    let dev = lab.add_device("dev").uplink(router.id()).build().await?;
    let dev_ip = dev.ip().expect("device has IPv4");
    let dev_ip6 = dev.ip6().expect("device has IPv6 on dual-stack router");
    info!(%dev_ip, %dev_ip6, "dual-stack device");
    let report = run_net_report(dev, relay_map).await?;
    // v4
    assert!(report.udp_v4, "expected UDP v4 on direct dual-stack");
    let global_v4 = report.global_v4.expect("expected global IPv4 address");
    assert_eq!(
        *global_v4.ip(),
        dev_ip,
        "without NAT, global IPv4 should equal device's own IP"
    );
    // v6
    assert!(report.udp_v6, "expected UDP v6 on direct dual-stack");
    let global_v6 = report.global_v6.expect("expected global IPv6 address");
    assert_eq!(
        *global_v6.ip(),
        dev_ip6,
        "without NAT, global IPv6 should equal device's own IP"
    );
    assert!(
        report.preferred_relay.is_some(),
        "expected relay to be reachable"
    );
    assert_ne!(
        report.captive_portal,
        Some(true),
        "no captive portal expected"
    );
    Ok(())
}

/// Dual-stack device behind a home NAT with no IPv6 NAT (NatV6Mode::None).
/// IPv4 is NATted (global differs from device IP). IPv6 uses global unicast
/// directly, so the reported global IPv6 should match the device's own address.
#[tokio::test]
#[traced_test]
#[ignore = "currently broken due to bug in patchbay"]
async fn netreport_dual_stack_home_nat() -> Result {
    let (lab, relay_map, _relay_guard) = lab_with_relay(testdir!()).await?;
    let nat = lab
        .add_router("nat")
        .nat(Nat::Home)
        .ip_support(IpSupport::DualStack)
        .build()
        .await?;
    let dev = lab.add_device("dev").uplink(nat.id()).build().await?;
    let dev_ip = dev.ip().expect("device has IPv4");
    let dev_ip6 = dev.ip6().expect("device has IPv6 on dual-stack router");
    info!(%dev_ip, %dev_ip6, "dual-stack device behind home NAT");
    let report = run_net_report(dev, relay_map).await?;
    println!("{report:#?}");
    // v4 is NATted.
    assert!(report.udp_v4, "expected UDP v4 through home NAT");
    let global_v4 = report.global_v4.expect("expected global IPv4 address");
    assert_ne!(
        *global_v4.ip(),
        dev_ip,
        "global IPv4 should differ from private IP behind NAT"
    );
    // v6 passes through without translation (NatV6Mode::None = global unicast).
    assert!(report.udp_v6, "expected UDP v6 with global unicast IPv6");
    let global_v6 = report.global_v6.expect("expected global IPv6 address");
    assert_eq!(
        *global_v6.ip(),
        dev_ip6,
        "IPv6 has no NAT, global should equal device's own IP"
    );
    assert!(
        report.preferred_relay.is_some(),
        "expected relay to be reachable"
    );
    assert_ne!(
        report.captive_portal,
        Some(true),
        "no captive portal expected"
    );
    Ok(())
}

// ---
// NetReport helper
// ---

/// Bind an endpoint in `dev`'s namespace, wait for the first net report, return it.
pub async fn run_net_report(dev: Device, relay_map: RelayMap) -> Result<NetReport> {
    dev.spawn(move |dev| {
        async move {
            let endpoint = endpoint_builder(&dev, relay_map).bind().await?;
            let mut watcher = endpoint.net_report();
            let report = tokio::time::timeout(Duration::from_secs(10), watcher.initialized())
                .await
                .anyerr()?;
            endpoint.close().await;
            n0_error::Ok(report)
        }
        .instrument(error_span!("net_report"))
    })?
    .await
    .anyerr()?
}
