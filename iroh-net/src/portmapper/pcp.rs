//! Definitions and utilities to interact with a PCP server.

use std::{net::Ipv4Addr, time::Duration};

use tracing::{debug, trace};

mod protocol;

/// Timeout to receive a response from a PCP server.
const RECV_TIMEOUT: Duration = Duration::from_millis(500);

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
