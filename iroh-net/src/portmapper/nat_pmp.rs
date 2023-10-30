//! Definitions and utilities to interact with a NAT-PMP server.

use std::{net::Ipv4Addr, num::NonZeroU16, time::Duration};

use tracing::{debug, trace};

use crate::net::UdpSocket;

use self::protocol::{MapProtocol, Request, Response};

mod protocol;

/// Timeout to receive a response from a NAT-PMP server.
const RECV_TIMEOUT: Duration = Duration::from_millis(500);

/// Recommended lifetime is 2 hours. See [RFC 6886 Requesting a
/// Mapping](https://datatracker.ietf.org/doc/html/rfc6886#section-3.3).
const MAPPING_REQUESTED_LIFETIME_SECONDS: u32 = 60 * 60 * 2;

/// A mapping sucessfully registered with a NAT-PMP server.
#[derive(Debug)]
pub struct Mapping {
    /// Local ip used to create this mapping.
    local_ip: Ipv4Addr,
    /// Local port used to create this mapping.
    local_port: NonZeroU16,
    /// Gateway address used to registed this mapping.
    gateway: Ipv4Addr,
    /// External port of the mapping.
    external_port: NonZeroU16,
    /// External address of the mapping.
    external_addr: Ipv4Addr,
    /// Allowed time for this mapping as informed by the server.
    lifetime_seconds: u32,
}

impl super::mapping::PortMapped for Mapping {
    fn external(&self) -> (Ipv4Addr, NonZeroU16) {
        (self.external_addr, self.external_port)
    }

    fn half_lifetime(&self) -> Duration {
        Duration::from_secs((self.lifetime_seconds / 2).into())
    }
}

impl Mapping {
    /// Attempt to register a new mapping with the NAT-PMP server on the provided gateway.
    pub async fn new(
        local_ip: Ipv4Addr,
        local_port: NonZeroU16,
        gateway: Ipv4Addr,
        external_port: Option<NonZeroU16>,
    ) -> anyhow::Result<Self> {
        // create the socket and send the request
        let socket = UdpSocket::bind_full((local_ip, 0))?;
        socket.connect((gateway, protocol::SERVER_PORT)).await?;

        let req = Request::Mapping {
            proto: MapProtocol::Udp,
            local_port: local_port.into(),
            external_port: external_port.map(Into::into).unwrap_or_default(),
            lifetime_seconds: MAPPING_REQUESTED_LIFETIME_SECONDS,
        };

        socket.send(&req.encode()).await?;

        // wait for the response and decode it
        let mut buffer = vec![0; Response::MAX_SIZE];
        let read = tokio::time::timeout(RECV_TIMEOUT, socket.recv(&mut buffer)).await??;
        let response = Response::decode(&buffer[..read])?;

        let (external_port, lifetime_seconds) = match response {
            Response::PortMap {
                proto: MapProtocol::Udp,
                epoch_time: _,
                private_port,
                external_port,
                lifetime_seconds,
            } if private_port == Into::<u16>::into(local_port) => (external_port, lifetime_seconds),
            _ => anyhow::bail!("server returned unexpected response for mapping request"),
        };

        let external_port = external_port
            .try_into()
            .map_err(|_| anyhow::anyhow!("received 0 port from server as external port"))?;

        // now send the second request to get the external address
        let req = Request::ExternalAddress;
        socket.send(&req.encode()).await?;

        // wait for the response and decode it
        let mut buffer = vec![0; Response::MAX_SIZE];
        let read = tokio::time::timeout(RECV_TIMEOUT, socket.recv(&mut buffer)).await??;
        let response = Response::decode(&buffer[..read])?;

        let external_addr = match response {
            Response::PublicAddress {
                epoch_time: _,
                public_ip,
            } => public_ip,
            _ => anyhow::bail!("server returned unexpected response for mapping request"),
        };

        Ok(Mapping {
            external_port,
            external_addr,
            lifetime_seconds,
            local_ip,
            local_port,
            gateway,
        })
    }

    /// Releases the mapping.
    pub(crate) async fn release(self) -> anyhow::Result<()> {
        // A client requests explicit deletion of a mapping by sending a message to the NAT gateway
        // requesting the mapping, with the Requested Lifetime in Seconds set to zero. The
        // Suggested External Port MUST be set to zero by the client on sending

        let Mapping {
            local_ip,
            local_port,
            gateway,
            ..
        } = self;

        // create the socket and send the request
        let socket = UdpSocket::bind_full((local_ip, 0))?;
        socket.connect((gateway, protocol::SERVER_PORT)).await?;

        let req = Request::Mapping {
            proto: MapProtocol::Udp,
            local_port: local_port.into(),
            external_port: 0,
            lifetime_seconds: 0,
        };

        socket.send(&req.encode()).await?;

        // mapping deletion is a notification, no point in waiting for the response
        Ok(())
    }
}

/// Probes the local gateway for NAT-PMP support.
pub async fn probe_available(local_ip: Ipv4Addr, gateway: Ipv4Addr) -> bool {
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
    let socket = UdpSocket::bind_full((local_ip, 0))?;
    socket.connect((gateway, protocol::SERVER_PORT)).await?;
    let req = Request::ExternalAddress;
    socket.send(&req.encode()).await?;

    // wait for the response and decode it
    let mut buffer = vec![0; Response::MAX_SIZE];
    let read = tokio::time::timeout(RECV_TIMEOUT, socket.recv(&mut buffer)).await??;
    let response = Response::decode(&buffer[..read])?;

    Ok(response)
}
