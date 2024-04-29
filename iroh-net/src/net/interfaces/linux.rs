//! Linux-specific network interfaces implementations.

use anyhow::{anyhow, Result};
#[cfg(not(target_os = "android"))]
use futures_util::TryStreamExt;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};

use super::DefaultRouteDetails;

pub async fn default_route() -> Option<DefaultRouteDetails> {
    let route = default_route_proc().await;
    if let Ok(route) = route {
        return route;
    }

    #[cfg(target_os = "android")]
    let res = default_route_android_ip_route().await;

    #[cfg(not(target_os = "android"))]
    let res = default_route_netlink().await;

    res.ok().flatten()
}

const PROC_NET_ROUTE_PATH: &str = "/proc/net/route";

async fn default_route_proc() -> Result<Option<DefaultRouteDetails>> {
    const ZERO_ADDR: &str = "00000000";
    let file = File::open(PROC_NET_ROUTE_PATH).await?;

    // Explicitly set capacity, this is min(4096, DEFAULT_BUF_SIZE):
    // https://github.com/google/gvisor/issues/5732
    // On a regular Linux kernel you can read the first 128 bytes of /proc/net/route,
    // then come back later to read the next 128 bytes and so on.
    //
    // In Google Cloud Run, where /proc/net/route comes from gVisor, you have to
    // read it all at once. If you read only the first few bytes then the second
    // read returns 0 bytes no matter how much originally appeared to be in the file.
    //
    // At the time of this writing (Mar 2021) Google Cloud Run has eth0 and eth1
    // with a 384 byte /proc/net/route. We allocate a large buffer to ensure we'll
    // read it all in one call.
    let reader = BufReader::with_capacity(8 * 1024, file);
    let mut lines_iter = reader.lines();
    while let Some(line) = lines_iter.next_line().await? {
        if !line.contains(ZERO_ADDR) {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        let iface = fields.next().ok_or(anyhow!("iface field missing"))?;
        let destination = fields.next().ok_or(anyhow!("destination field missing"))?;
        let mask = fields.nth(5).ok_or(anyhow!("mask field missing"))?;
        // if iface.starts_with("tailscale") || iface.starts_with("wg") {
        //     continue;
        // }
        if destination == ZERO_ADDR && mask == ZERO_ADDR {
            return Ok(Some(DefaultRouteDetails {
                interface_name: iface.to_string(),
                interface_description: Default::default(),
                interface_index: Default::default(),
            }));
        }
    }
    Ok(None)
}

/// Try find the default route by parsing the "ip route" command output.
///
/// We use this on Android where /proc/net/route can be missing entries or have locked-down
/// permissions.  See also comments in <https://github.com/tailscale/tailscale/pull/666>.
#[cfg(target_os = "android")]
pub async fn default_route_android_ip_route() -> Result<Option<DefaultRouteDetails>> {
    use tokio::process::Command;

    let output = Command::new("/system/bin/ip")
        .args(["route", "show", "table", "0"])
        .kill_on_drop(true)
        .output()
        .await?;
    let stdout = std::str::from_utf8(&output.stdout)?;
    let details = parse_android_ip_route(&stdout).map(|iface| DefaultRouteDetails {
        interface_name: iface.to_string(),
        interface_description: Default::default(),
        interface_index: Default::default(),
    });
    Ok(details)
}

/// Parses the output of the android `/system/bin/ip` command for the default route.
///
/// Searches for line like `default via 10.0.2.2. dev radio0 table 1016 proto static mtu
/// 1500`
#[cfg(any(target_os = "android", test))]
fn parse_android_ip_route(stdout: &str) -> Option<&str> {
    for line in stdout.lines() {
        if !line.starts_with("default via") {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        if let Some(_dev) = fields.find(|s: &&str| *s == "dev") {
            return fields.next();
        }
    }
    None
}

#[cfg(not(target_os = "android"))]
async fn default_route_netlink() -> Result<Option<DefaultRouteDetails>> {
    use tracing::{info_span, Instrument};

    let (connection, handle, _receiver) = rtnetlink::new_connection()?;
    let task = tokio::spawn(connection.instrument(info_span!("rtnetlink.conn")));

    let default = default_route_netlink_family(&handle, rtnetlink::IpVersion::V4).await?;
    let default = match default {
        Some(default) => Some(default),
        None => default_route_netlink_family(&handle, rtnetlink::IpVersion::V6).await?,
    };
    task.abort();
    task.await.ok();
    Ok(default.map(|(name, index)| DefaultRouteDetails {
        interface_name: name,
        interface_description: None,
        interface_index: index,
    }))
}

/// Returns the `(name, index)` of the interface for the default route.
#[cfg(not(target_os = "android"))]
async fn default_route_netlink_family(
    handle: &rtnetlink::Handle,
    family: rtnetlink::IpVersion,
) -> Result<Option<(String, u32)>> {
    let mut routes = handle.route().get(family).execute();
    while let Some(route) = routes.try_next().await? {
        if route.gateway().is_none() {
            // A default route has a gateway.
            continue;
        }
        if route.destination_prefix().is_some() {
            // A default route has no destination prefix because it needs to route all
            // destinations.
            continue;
        }
        if let Some(index) = route.output_interface() {
            if index == 0 {
                continue;
            }
            let name = iface_by_index(handle, index).await?;
            return Ok(Some((name, index)));
        }
    }
    Ok(None)
}

#[cfg(not(target_os = "android"))]
async fn iface_by_index(handle: &rtnetlink::Handle, index: u32) -> Result<String> {
    let mut links = handle.link().get().match_index(index).execute();
    let msg = links
        .try_next()
        .await?
        .ok_or_else(|| anyhow!("No netlink response"))?;

    for nla in msg.nlas {
        if let netlink_packet_route::link::nlas::Nla::IfName(name) = nla {
            return Ok(name);
        }
    }
    Err(anyhow!("Interface name not found"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_route_proc() {
        let route = default_route_proc().await.unwrap();
        // assert!(route.is_some());
        if let Some(route) = route {
            assert!(!route.interface_name.is_empty());
            assert!(route.interface_description.is_none());
            assert_eq!(route.interface_index, 0);
        }
    }

    #[test]
    fn test_parse_android_ip_route() {
        let stdout = "default via 10.0.2.2. dev radio0 table 1016 proto static mtu 1500";
        let iface = parse_android_ip_route(stdout).unwrap();
        assert_eq!(iface, "radio0");
    }

    #[tokio::test]
    #[cfg(not(target_os = "android"))]
    async fn test_default_route_netlink() {
        let route = default_route_netlink().await.unwrap();
        // assert!(route.is_some());
        if let Some(route) = route {
            assert!(!route.interface_name.is_empty());
            assert!(route.interface_index > 0);
        }
    }
}
