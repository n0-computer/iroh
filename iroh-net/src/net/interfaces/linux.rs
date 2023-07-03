//! Linux-specific network interfaces implementations.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{anyhow, Result};
#[cfg(not(target_os = "android"))]
use futures::TryStreamExt;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

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

static PROC_NET_ROUTE_ERR: AtomicBool = AtomicBool::new(false);
const PROC_NET_ROUTE_PATH: &str = "/proc/net/route";
/// The max number of lines to read from /proc/net/route looking for a default route.
const MAX_PROC_NET_ROUTE_READ: usize = 1000;

/// Parses 10.0.0.1 out of:
///
/// ```norun
/// $ cat /proc/net/route
/// Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT
/// ens18   00000000        0100000A        0003    0       0       0       00000000        0       0       0
/// ens18   0000000A        00000000        0001    0       0       0       0000FFFF        0       0       0
/// ```
pub async fn likely_home_router() -> Option<Ipv4Addr> {
    if PROC_NET_ROUTE_ERR.load(Ordering::Relaxed) {
        // If we failed to read /proc/net/route previously, don't keep trying.
        // But if we're on Android, go into the Android path.
        #[cfg(target_os = "android")]
        return likely_home_router_android();
        #[cfg(not(target_os = "android"))]
        return None;
    }
    let file = File::open(PROC_NET_ROUTE_PATH).await.ok()?;

    match parse_proc_net_home_router(file).await {
        Ok(ip) => ip,
        Err(err) => {
            tracing::debug!("failed to read /proc/net/route: {:?}", err);

            PROC_NET_ROUTE_ERR.store(true, Ordering::Relaxed);
            #[cfg(target_os = "android")]
            return likely_home_router_android();
            #[cfg(not(target_os = "android"))]
            return None;
        }
    }
}

async fn parse_proc_net_home_router<R: AsyncRead + Unpin>(source: R) -> Result<Option<Ipv4Addr>> {
    let mut line_num = 0;
    let mut reader = BufReader::new(source).lines();

    while let Some(line) = reader.next_line().await? {
        line_num += 1;

        if line_num == 1 {
            // Skip header line.
            continue;
        }
        if line_num > MAX_PROC_NET_ROUTE_READ {
            anyhow::bail!("/proc/net too long");
        }

        let mut fields = line.split_ascii_whitespace();
        let Some(gateway_hex) = fields.nth(2) else {
            continue;
        };
        let Some(flags_hex) = fields.next() else {
            continue;
        };

        let mut flags_bytes = [0u8; 2];
        if hex::decode_to_slice(flags_hex, &mut flags_bytes).is_err() {
            continue;
        }
        let flags = u16::from_be_bytes(flags_bytes);

        let mut gateway_bytes = [0u8; 4];
        if hex::decode_to_slice(gateway_hex, &mut gateway_bytes).is_err() {
            continue;
        }
        let gateway = u32::from_le_bytes(gateway_bytes);

        dbg!(gateway);
        dbg!(flags);

        if dbg!(flags & (libc::RTF_UP | libc::RTF_GATEWAY))
            != dbg!(libc::RTF_UP | libc::RTF_GATEWAY)
        {
            continue;
        }

        let ip = Ipv4Addr::from(gateway);
        if ip.is_private() {
            return Ok(Some(ip));
        }
    }
    // if errors.Is(err, errStopReading) {
    // 	err = nil
    // }
    // if err != nil {
    // 	procNetRouteErr.Store(true)
    // 	if runtime.GOOS == "android" {
    // 		return likelyHomeRouterIPAndroid()
    // 	}
    // 	log.Printf("interfaces: failed to read /proc/net/route: %v", err)
    // }
    // if ret.IsValid() {
    // 	return ret, true
    // }
    // if lineNum >= maxProcNetRouteRead {
    // 	// If we went over our line limit without finding an answer, assume
    // 	// we're a big fancy Linux router (or at least not a home system)
    // 	// and set the error bit so we stop trying this in the future (and wasting CPU).
    // 	// See https://github.com/tailscale/tailscale/issues/7621.
    // 	//
    // 	// Remember that "likelyHomeRouterIP" exists purely to find the port
    // 	// mapping service (UPnP, PMP, PCP) often present on a home router. If we hit
    // 	// the route (line) limit without finding an answer, we're unlikely to ever
    // 	// find one in the future.
    // 	procNetRouteErr.Store(true)
    // }
    Ok(None)
}

/// Android apps don't have permission to read /proc/net/route, at
/// least on Google devices and the Android emulator.
#[cfg(target_os = "android")]
async fn likely_home_router_android() -> Option<Ipv4Addr> {
    // cmd := exec.Command("/system/bin/ip", "route", "show", "table", "0")
    // out, err := cmd.StdoutPipe()
    // if err != nil {
    // 	return
    // }
    // if err := cmd.Start(); err != nil {
    // 	log.Printf("interfaces: running /system/bin/ip: %v", err)
    // 	return
    // }
    // // Search for line like "default via 10.0.2.2 dev radio0 table 1016 proto static mtu 1500 "
    // lineread.Reader(out, func(line []byte) error {
    // 	const pfx = "default via "
    // 	if !mem.HasPrefix(mem.B(line), mem.S(pfx)) {
    // 		return nil
    // 	}
    // 	line = line[len(pfx):]
    // 	sp := bytes.IndexByte(line, ' ')
    // 	if sp == -1 {
    // 		return nil
    // 	}
    // 	ipb := line[:sp]
    // 	if ip, err := netip.ParseAddr(string(ipb)); err == nil && ip.Is4() {
    // 		ret = ip
    // 		log.Printf("interfaces: found Android default route %v", ip)
    // 	}
    // 	return nil
    // })
    // cmd.Process.Kill()
    // cmd.Wait()
    // return ret, ret.IsValid()
    None
}

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
/// permissions.  See also comments in https://github.com/tailscale/tailscale/pull/666.
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
    let (connection, handle, _receiver) = rtnetlink::new_connection()?;
    let task = tokio::spawn(connection);

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

    #[tokio::test]
    async fn test_parse_proc_net_home_router() {
        let source = r#"Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT
ens18   00000000        0100000A        0003    0       0       0       00000000        0       0       0
ens18   0000000A        00000000        0001    0       0       0       0000FFFF        0       0       0
"#;

        let expected: Ipv4Addr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            parse_proc_net_home_router(std::io::Cursor::new(source))
                .await
                .unwrap()
                .unwrap(),
            expected,
        );
    }
}
