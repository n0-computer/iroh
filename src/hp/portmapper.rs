use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::{Duration, Instant},
};

use anyhow::Error;
use derive_more::From;
use igd::aio as aigd;
use regex::internal::Inst;
use tracing::trace; // async internet gateway device

#[derive(Debug, Clone)]
pub struct PortMapper {}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub pcp: bool,
    pub pmp: bool,
    pub upnp: bool,
}

const UPNP_SEARCH_TIMEOUT: Duration = Duration::from_millis(250);
const AVAILABILITY_TRUST_DURATION: Duration = Duration::from_secs(60 * 10); // 10 minutes

/// A port mapping client.
#[derive(Default, Debug, Clone)]
pub struct Client {
    local_port: u16,

    last_upnp_gateway_addr: Option<(SocketAddrV4, Instant)>,
    current_mapping: Option<UpnpMapping>,
}

trait Mapping {
    /// Releases the mapping.
    fn release(self) -> &'static dyn std::future::Future<Output = Result<(), ()>>;
    /// GoodUntil will return the lease time that the mapping is valid for.
    fn good_until(&self) -> Instant;
    /// RenewAfter returns the earliest time that the mapping should be renewed.
    fn renew_after(&self) -> Instant;
    /// External indicates what port the mapping can be reached from the outside.
    fn external(&self) -> std::net::SocketAddr;
}

#[derive(Debug, Clone)]
struct UpnpMapping {
    gateway: aigd::Gateway,
    external_addr: SocketAddrV4,
    created_at: Instant,
}

impl UpnpMapping {
    async fn new(local_port: u16) -> Result<Self, Error> {
        let gateway = aigd::search_gateway(igd::SearchOptions {
            timeout: Some(UPNP_SEARCH_TIMEOUT),
            ..Default::default()
        })
        .await?;

        const PORT_MAPPING_LEASE_DURATION_SECONDS: u32 = 0;

        // TODO(@divagant-martian): this likely needs getting the interfaces
        let local_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, local_port);

        let external_addr = gateway
            .get_any_address(
                igd::PortMappingProtocol::UDP,
                local_addr,
                PORT_MAPPING_LEASE_DURATION_SECONDS,
                "iroh-portmap",
            )
            .await?;
        Ok(UpnpMapping {
            gateway,
            external_addr,
            created_at: Instant::now(),
        })
    }

    async fn release(self) -> Result<(), Error> {
        let UpnpMapping {
            gateway,
            external_addr,
            ..
        } = self;
        gateway
            .remove_port(igd::PortMappingProtocol::UDP, external_addr.port())
            .await?;
        Ok(())
    }
    // good_until will return the lease time that the mapping is valid for.
    fn good_until(&self) -> Instant {
        // assume an hour
        self.created_at + Duration::from_secs(60 * 60)
    }
    // renew_after returns the earliest time that the mapping should be renewed.
    fn renew_after(&self) -> Instant {
        // 55 minutes
        self.created_at + Duration::from_secs(60 * 55)
    }
    // external indicates what port the mapping can be reached from on the outside.
    fn external(&self) -> SocketAddrV4 {
        self.external_addr
    }
}

impl Client {
    pub fn new() -> Self {
        Self::default()
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

    /// Searchs for upnp gateways, returns whether any was found.
    ///
    /// If no gateway is found, or the gateway differs from the previously known one, removes the
    /// current mapping.
    async fn probe_upnp_available(&mut self) -> bool {
        let gateway_result = aigd::search_gateway(igd::SearchOptions {
            timeout: Some(UPNP_SEARCH_TIMEOUT),
            ..Default::default()
        })
        .await;

        match gateway_result {
            Ok(gateway) => {
                let gateway_addr = gateway.addr;
                // update the gateway and check if mappings need to be cleared.
                let old_gateway = self
                    .last_upnp_gateway_addr
                    .replace((gateway_addr, Instant::now()));
                if let Some((old_gateway_addr, _last_seen)) = old_gateway {
                    if old_gateway_addr != gateway_addr {
                        // invalidate the current mapping without attempting to release them since
                        // the gateway in which it was registered has changed.
                        self.current_mapping = None;
                    }
                }
                true
            }
            Err(e) => {
                // TODO(@divagant-martian): chech errors, we might want to not invalidate the last
                // seen time depending on this.

                // invalidate last seen gateway and time
                self.last_upnp_gateway_addr = None;
                self.invalidate_mapping().await;
                false
            }
        }
    }

    /// Releases the current mapping and clears it from the cache.
    async fn invalidate_mapping(&mut self) -> Result<(), Error> {
        if let Some(old_mapping) = self.current_mapping.take() {
            old_mapping.release().await?;
        }
        Ok(())
    }

    /// UPnP: searchs for an upnp internet gateway device (a router).
    pub async fn probe(&mut self) -> Result<ProbeResult, Error> {
        let upnp = self.upnp_available_from_cache() || self.probe_upnp_available().await;

        Ok(ProbeResult {
            pcp: false,
            pmp: false,
            upnp,
        })
    }

    /// Updates the local port number to which we want to port map UDP traffic.
    /// Invalidates the current mapping if any.
    pub async fn set_local_port(&mut self, local_port: u16) {
        // TODO(@divagant-martian): this should never be 0
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
    pub async fn get_cached_mapping_or_start_creating_one(&self) -> Option<SocketAddr> {
        // practically same as tailscale
        if let Some(mapping) = self.current_mapping {
            let now = Instant::now();
            if now <= mapping.good_until() {
                if now >= mapping.renew_after() {
                    match UpnpMapping::new(self.local_port).await {
                        Ok(mapping) => self.current_mapping = Some(mapping),
                        Err(e) => {
                            // TODO(@divagant-martian): unclear what to do here
                        }
                    }
                }
            }
        }
    }

    pub fn has_mapping(&self) -> bool {
        self.current_mapping
            .as_ref()
            .filter(|mapping| Instant::now() <= mapping.good_until())
            .is_some()
    }

    pub fn note_network_down(&self) {
        // TODO:
    }

    pub fn close(&self) {
        // TODO:
    }
}
