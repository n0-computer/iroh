use std::{
    net::{SocketAddr, SocketAddrV4},
    num::NonZeroU16,
    time::{Duration, Instant},
};

use anyhow::Error;
use tracing::debug;

use iroh_metrics::{inc, portmap::PortmapMetrics as Metrics};

mod upnp;

/// If a port mapping service has been seen during the last [`AVAILABILITY_TRUST_DURATION`] it
/// will not be probed again.
const AVAILABILITY_TRUST_DURATION: Duration = Duration::from_secs(60 * 10); // 10 minutes

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub pcp: bool,
    pub pmp: bool,
    pub upnp: bool,
}

/// A port mapping client.
#[derive(Default, Debug, Clone)]
pub struct Client {
    /// Local port to map.
    // TODO(@divagant-martian): This is an option to allow keeping the Default implementation over
    // this type for now.
    local_port: Option<NonZeroU16>,

    last_upnp_gateway_addr: Option<(SocketAddrV4, Instant)>,
    current_mapping: Option<upnp::Mapping>,
}

impl Client {
    pub fn new(local_port: Option<NonZeroU16>) -> Self {
        Client {
            local_port,
            last_upnp_gateway_addr: None,
            current_mapping: None,
        }
    }

    /// Releases the current mapping and clears it from the cache.
    async fn invalidate_mapping(&mut self) -> Result<(), Error> {
        if let Some(old_mapping) = self.current_mapping.take() {
            old_mapping.release().await?;
        }
        Ok(())
    }

    /// UPnP: searches for an upnp internet gateway device (a router).
    pub async fn probe(&mut self) -> Result<ProbeResult, Error> {
        let upnp = self.upnp_available_from_cache() || self.probe_upnp_available().await;

        Ok(ProbeResult {
            pcp: false,
            pmp: false,
            upnp,
        })
    }

    /// Checks if the last seen upnp gateway should still be trusted as available.
    ///
    /// Returns false otherwise, or if there is no cached gateway.
    fn upnp_available_from_cache(&self) -> bool {
        self.last_upnp_gateway_addr
            .as_ref()
            .map(|(_gateway_addr, last_probed)| {
                *last_probed + AVAILABILITY_TRUST_DURATION > Instant::now()
            })
            .unwrap_or_default()
    }

    /// Probes for UPnP gateways.
    async fn probe_upnp_available(&mut self) -> bool {
        inc!(Metrics::UpnpProbes);
        match upnp::probe_available().await {
            Ok(gateway_addr) => {
                debug!("found upnp gateway {gateway_addr}");
                let old_gateway = self
                    .last_upnp_gateway_addr
                    .replace((gateway_addr, Instant::now()));
                if let Some((old_gateway_addr, _last_seen)) = old_gateway {
                    if old_gateway_addr != gateway_addr {
                        inc!(Metrics::UpnpGatewayUpdated);
                        debug!("upnp gateway changed from {old_gateway_addr} to {gateway_addr}");
                        // TODO(@divagant-martian): tailscale does not clear the mappings here.
                        // This means the gateway has changed but we believe `self.current_mapping`
                        // is still valid.
                    }
                }
                true
            }
            Err(e) => {
                inc!(Metrics::UpnpProbesFailed);
                debug!("upnp probe failed {e}");
                // invalidate last seen gateway and time
                self.last_upnp_gateway_addr = None;
                false
            }
        }
    }

    /// Updates the local port number to which we want to port map UDP traffic.
    /// Invalidates the current mapping if any.
    pub async fn set_local_port(&mut self, local_port: NonZeroU16) {
        let local_port = Some(local_port);
        if self.local_port != local_port {
            self.local_port = local_port;
            let _ = self.invalidate_mapping().await;
        }
    }

    /// Quickly returns with our current cached portmapping, if any.
    /// If there's not one, it starts up a background goroutine to create one.
    /// If the background goroutine ends up creating one, the `on_change` hook registered with the
    /// `Client::new` constructor (if any) will fire.
    // TODO(@divagant-martian): fix docs. Also, this will probably only ever return ipv4 addresses.
    pub async fn get_cached_mapping_or_start_creating_one(&mut self) -> Option<SocketAddr> {
        // TODO(@divagant-martian): this has a lock ensure just one mapping attempt is underway
        if let Some(mapping) = &mut self.current_mapping {
            let now = Instant::now();
            if now <= mapping.good_until() {
                debug!("renewing mapping {mapping}");
                // TODO(@divagant-martian): this would go in a goroutine
                if now >= mapping.renew_after() {
                    inc!(Metrics::UpnpPortmapAttempts);
                    if let Err(e) = mapping.renew().await {
                        inc!(Metrics::UpnpPortmapFailed);
                        debug!("failed to renew port mapping {mapping}: {e}");
                    }
                }
                // port mapping is still good regardless of renewal
                Some(mapping.external().into())
            } else {
                // TODO(@divagant-martian): tailscale returns nil without clearing the mapping
                None
            }
        } else if let Some(local_port) = self.local_port {
            inc!(Metrics::UpnpPortmapAttempts);
            match upnp::Mapping::new(std::net::Ipv4Addr::LOCALHOST, local_port).await {
                Ok(mapping) => {
                    debug!("upnp port mapping created {mapping}");
                    let external = mapping.external().into();
                    self.current_mapping = Some(mapping);
                    Some(external)
                }
                Err(e) => {
                    inc!(Metrics::UpnpPortmapFailed);
                    debug!("Failed to create upnp port mapping: {e}");
                    None
                }
            }
        } else {
            debug!("No valid local port provided to create a mapping");
            None
        }
    }

    pub fn has_mapping(&self) -> bool {
        self.current_mapping
            .as_ref()
            .filter(|mapping| Instant::now() <= mapping.good_until())
            .is_some()
    }

    pub fn note_network_down(&mut self) {
        self.current_mapping = None;
    }

    pub async fn close(&mut self) {
        // TODO(@divagant-martian):
        // tailscale has a `closed` bool, which is not very pretty.
        // Easiest way to emulate this is consume self and have the owner have an Option. This does
        // bring some complexity, so maybe we can just not close (permanently) but simply clean
        // (invalidate mappings)
        //
        // The only place this is ever used is to prevent closing twice...
        let _ = self.invalidate_mapping().await;
    }
}
