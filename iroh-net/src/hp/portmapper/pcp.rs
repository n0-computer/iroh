//! Definitions and utilities to interact with a PCP server.

use std::{net::Ipv4Addr, num::NonZeroU16, time::Duration};

use rand::RngCore;
use tracing::{debug, trace};

mod protocol;

/// Timeout to receive a response from a PCP server.
const RECV_TIMEOUT: Duration = Duration::from_millis(500);

// nonce is used to issue a release request
#[allow(unused)]
#[derive(Debug)]
pub struct Mapping {
    external_port: NonZeroU16,
    external_address: Ipv4Addr,
    lifetime_seconds: u32,
    nonce: [u8; 12],
}

impl super::mapping::PortMapped for Mapping {
    fn external(&self) -> (Ipv4Addr, NonZeroU16) {
        (self.external_address, self.external_port)
    }

    fn half_lifetime(&self) -> Duration {
        Duration::from_secs((self.lifetime_seconds / 2).into())
    }
}

impl Mapping {
    pub async fn new(
        local_ip: Ipv4Addr,
        local_port: NonZeroU16,
        gateway: Ipv4Addr,
        preferred_external_address: Option<(Ipv4Addr, NonZeroU16)>,
    ) -> anyhow::Result<Self> {
        let socket = tokio::net::UdpSocket::bind((local_ip, 0)).await?;
        socket.connect((gateway, protocol::SERVER_PORT)).await?;

        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        let (requested_address, requested_port) = match preferred_external_address {
            Some((ip, port)) => (Some(ip), Some(port.into())),
            None => (None, None),
        };

        let local_port = local_port.into();
        let req = protocol::Request::get_mapping(
            nonce,
            local_port,
            local_ip,
            requested_port,
            requested_address,
        );

        socket.send(&req.encode()).await?;
        let mut buffer = vec![0; protocol::Response::MAX_SIZE];
        let read = tokio::time::timeout(RECV_TIMEOUT, socket.recv(&mut buffer)).await??;
        let response = protocol::Response::decode(&buffer[..read])?;

        let protocol::Response {
            lifetime_seconds,
            epoch_time: _,
            data,
        } = response;

        match data {
            protocol::OpcodeData::MapData(map_data) => {
                let protocol::MapData {
                    nonce: received_nonce,
                    protocol,
                    local_port: received_local_port,
                    external_port,
                    external_address,
                } = map_data;
                if nonce != received_nonce {
                    anyhow::bail!("received nonce does not match sent request");
                }
                if protocol != protocol::MapProtocol::Udp {
                    anyhow::bail!("received mapping is not for UDP");
                }
                if received_local_port != local_port {
                    anyhow::bail!("received mapping is for a local port that does not match the requested one");
                }
                let external_port = external_port
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("received 0 external port for mapping"))?;

                let external_address = external_address
                    .to_ipv4_mapped()
                    .ok_or(anyhow::anyhow!("received external address is not ipv4"))?;

                Ok(Mapping {
                    external_port,
                    external_address,
                    lifetime_seconds,
                    nonce,
                })
            }
            protocol::OpcodeData::Announce => {
                anyhow::bail!("received an announce response for a map request")
            }
        }
    }
}

/// Probes the local gateway for PCP support.
pub async fn probe_available(local_ip: Ipv4Addr, gateway: Ipv4Addr) -> bool {
    match probe_available_fallible(local_ip, gateway).await {
        Ok(response) => {
            trace!("probe response: {response:?}");
            let protocol::Response {
                lifetime_seconds: _,
                epoch_time: _,
                data,
            } = response;
            match data {
                protocol::OpcodeData::Announce => true,
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
) -> anyhow::Result<protocol::Response> {
    // create the socket and send the request
    let socket = tokio::net::UdpSocket::bind((local_ip, 0)).await?;
    socket.connect((gateway, protocol::SERVER_PORT)).await?;
    let req = protocol::Request::annouce(local_ip.to_ipv6_mapped());
    socket.send(&req.encode()).await?;

    // wait for the response and decode it
    let mut buffer = vec![0; protocol::Response::MAX_SIZE];
    let read = tokio::time::timeout(RECV_TIMEOUT, socket.recv(&mut buffer)).await??;
    let response = protocol::Response::decode(&buffer[..read])?;

    Ok(response)
}
