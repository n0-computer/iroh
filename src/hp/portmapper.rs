use std::net::SocketAddr;

use anyhow::Error;
use igd::aio as aigd;
use tracing::trace; // async internet gateway device

#[derive(Debug, Clone)]
pub struct PortMapper {}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub pcp: bool,
    pub pmp: bool,
    pub upnp: bool,
}

const UPNP_SEARCH_TIMEOUT_MILLIS: std::time::Duration = std::time::Duration::from_millis(250);

/// A port mapping client.
// TODO(@divagant-martian): in tailscale this would be a trait implemented over the individual
// protocol clients, which makes sense. Check this.
#[derive(Default, Debug, Clone)]
pub struct Client {
    upnp_gateway: Option<aigd::Gateway>,
}

impl Client {
    pub fn new() -> Self {
        Self::default()
    }

    /// UPnP: searchs for an internet gateway.
    pub async fn probe(&mut self) -> Result<ProbeResult, Error> {
        let gateway = aigd::search_gateway(igd::SearchOptions {
            timeout: Some(UPNP_SEARCH_TIMEOUT_MILLIS),
            ..Default::default()
        })
        // TODO(@divagant-martian) if this fails we likely want to invalidate the previous gateway
        // and mappings.
        .await?;
        self.upnp_gateway = Some(gateway);
        // TODO(@divagant-martian) tailscale invalidates previous mappings if the gateway changes.
        Ok(ProbeResult {
            pcp: false,
            pmp: false,
            upnp: true,
        })
    }

    /// Updates the local port number to which we want to port map UDP traffic.
    // TODO(@divagant-martian) if there is no upnp gateway this fails. Maybe add result return
    // type?
    pub async fn set_local_port(&self, local_port: u16) {
        if let Some(gateway) = &self.upnp_gateway {
            // TODO(@divagant-martian): lease duration 0 means infinite. Check recommendations/ best practices.
            // move this outside
            const PORT_MAPPING_LEASE_DURATION_SECONDS: u32 = 0;
            let local_addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, local_port);
            match gateway
                .add_any_port(
                    igd::PortMappingProtocol::UDP,
                    local_addr,
                    PORT_MAPPING_LEASE_DURATION_SECONDS,
                    "iroh",
                )
                .await
            {
                Ok(external_port) => {
                    trace!("local port {local_port} mapped to external port {external_port} using UPnP")
                }
                Err(port_mapping_error) => {
                    // TODO(@divagant-martian): will this be excesively verbose if it happens often?
                    match port_mapping_error {
                        igd::AddAnyPortError::ActionNotAuthorized => {
                            // TODO(@divagant-martian): invalidate gateway? prevent retries for some time?
                        }
                        igd::AddAnyPortError::InternalPortZeroInvalid => {
                            // TODO(@divagant-martian): should never get a local port that has not been assigned... unreachable?
                        }
                        igd::AddAnyPortError::NoPortsAvailable => {
                            // TODO(@divagant-martian): prevent retries?
                        }
                        igd::AddAnyPortError::ExternalPortInUse => {
                            // TODO(@divagant-martian): retry?
                        }
                        igd::AddAnyPortError::OnlyPermanentLeasesSupported => {
                            // TODO(@divagant-martian): lease is permanent now. unreachable?
                        }
                        igd::AddAnyPortError::DescriptionTooLong => {
                            // TODO(@divagant-martian): "iroh" doesn't seem too long. what to do here?
                        }
                        igd::AddAnyPortError::RequestError(req_err) => match req_err {
                            igd::RequestError::InvalidResponse(_)
                            | igd::RequestError::ErrorCode(_, _)
                            | igd::RequestError::UnsupportedAction(_) => {
                                // Different forms of "gateway behaved unexpectedly"
                                // TODO(@divagant-martian): invalidate gateway?
                            }
                            igd::RequestError::AttoHttpError(_)
                            | igd::RequestError::IoError(_)
                            | igd::RequestError::HyperError(_)
                            | igd::RequestError::HttpError(_)
                            | igd::RequestError::Utf8Error(_) => {
                                // Different forms of "request failed" for which we can't take any action
                            }
                        },
                    }
                }
            }
        }
    }

    /// Quickly returns with our current cached portmapping, if any.
    /// If there's not one, it starts up a background goroutine to create one.
    /// If the background goroutine ends up creating one, the `on_change` hook registered with the
    /// `Client::new` constructor (if any) will fire.
    // TODO(@divagant-martian): fix docs, no goroutines here. Re-evaluate callback behaviour.
    pub async fn get_cached_mapping_or_start_creating_one(&self) -> Option<SocketAddr> {
        // TODO:
        None
    }

    pub fn have_mapping(&self) -> bool {
        // TODO:
        false
    }

    pub fn note_network_down(&self) {
        // TODO:
    }

    pub fn close(&self) {
        // TODO:
    }
}
