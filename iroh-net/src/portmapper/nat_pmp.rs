use std::{net::Ipv4Addr, num::NonZeroU16, time::Duration};

use tracing::{debug, trace};

use self::protocol::{MapProtocol, Request, Response};

mod protocol;

/// Port to use when acting as a server. This is the one we direct requests to.
pub const SERVER_PORT: u16 = 5351;

/// Tailscale uses the recommended port mapping lifetime for PMP, which is 2 hours. So we assume a
/// half lifetime of 1h. See <https://datatracker.ietf.org/doc/html/rfc6886#section-3.3>
const MAPPING_REQUESTED_LIFETIME_SECONDS: u32 = 60 * 60;

#[derive(Debug)]
pub struct Mapping {
    external_port: NonZeroU16,
    external_addr: Ipv4Addr,
    lifetime_seconds: u32,
}

impl Mapping {
    pub async fn new(
        local_ip: Ipv4Addr,
        local_port: NonZeroU16,
        gateway: Ipv4Addr,
        preferred_external_address: Option<(Ipv4Addr, NonZeroU16)>,
    ) -> anyhow::Result<Self> {
        let socket = tokio::net::UdpSocket::bind((local_ip, 0)).await?;
        socket.connect((gateway, SERVER_PORT)).await?;

        let (preferred_external_address, preferred_external_port) = match preferred_external_address
        {
            Some((ip, port)) => (Some(ip), Some(port.into())),
            None => (None, None),
        };
        let local_port: u16 = local_port.into();
        let req = Request::Mapping {
            proto: MapProtocol::UDP,
            local_port,
            external_port: preferred_external_port.unwrap_or_default(),
            lifetime_seconds: MAPPING_REQUESTED_LIFETIME_SECONDS,
        };

        socket.send(&req.encode()).await?;
        let mut buffer = vec![0; Response::MAX_SIZE];
        let read = tokio::time::timeout(RECV_TIMEOUT, socket.recv(&mut buffer)).await??;
        let response = Response::decode(&buffer[..read])?;

        // pre-create the mapping since we have most info ready
        let (external_port, lifetime_seconds) = match response {
            Response::PortMap {
                proto: MapProtocol::UDP,
                epoch_time,
                private_port,
                external_port,
                lifetime_seconds,
            } if private_port == local_port => (external_port, lifetime_seconds),
            _ => anyhow::bail!("server returned unexpected response for mapping request"),
        };

        let external_port = external_port
            .try_into()
            .map_err(|_| anyhow::anyhow!("received 0 port from server as external port"))?;

        // now send the second response to get the external address
        let req = Request::ExternalAddress;
        socket.send(&req.encode()).await?;
        let mut buffer = vec![0; Response::MAX_SIZE];
        let read = tokio::time::timeout(RECV_TIMEOUT, socket.recv(&mut buffer)).await??;
        let response = Response::decode(&buffer[..read])?;
        let external_addr = match response {
            Response::PublicAddress {
                epoch_time,
                public_ip,
            } => public_ip,
            _ => anyhow::bail!("server returned unexpected response for mapping request"),
        };

        Ok(Mapping {
            external_port,
            external_addr,
            lifetime_seconds,
        })
    }
}

impl super::mapping::PortMapped for Mapping {
    fn external(&self) -> (Ipv4Addr, NonZeroU16) {
        (self.external_addr, self.external_port)
    }

    fn half_lifetime(&self) -> Duration {
        Duration::from_secs((self.lifetime_seconds / 2).into())
    }
}

/// Timeout to receive a response from a NAT-PMP server.
const RECV_TIMEOUT: Duration = Duration::from_millis(500);

pub async fn probe_available(local_ip: Ipv4Addr, gateway: Ipv4Addr) -> bool {
    debug!("starting probe");
    match probe_available_fallible(local_ip, gateway).await {
        Ok(response) => {
            trace!("probe response: {response:?}");
            match response {
                Response::PublicAddress { .. } => true,
                _ => {
                    debug!("server returned an unexpected response type for probe");
                    // missbehaving server is not useful
                    false
                }
            }
        }
        Err(e) => {
            debug!("probe failed: {e}");
            false
        }
    }
}

async fn probe_available_fallible(
    local_ip: Ipv4Addr,
    gateway: Ipv4Addr,
) -> anyhow::Result<Response> {
    // create the socket and send the request
    let socket = tokio::net::UdpSocket::bind((local_ip, 0)).await?;
    socket.connect((gateway, SERVER_PORT)).await?;
    let req = Request::ExternalAddress;
    socket.send(&req.encode()).await?;

    // wait for the response and decode it
    let mut buffer = vec![0; Response::MAX_SIZE];
    let read = tokio::time::timeout(RECV_TIMEOUT, socket.recv(&mut buffer)).await??;
    let response = Response::decode(&buffer[..read])?;

    Ok(response)
}
