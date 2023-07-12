//! Utilities for probing [NAT-PMP](https://datatracker.ietf.org/doc/html/rfc6886) and
//! [PCP](https://datatracker.ietf.org/doc/html/rfc6887).

// NOTES
// TODO(@divma): move to pr desc
// PCP has multicast announcements from the server to the clients, this means binding to
// 224.0.0.1:CLIENT_PORT. to implement or not to implement.

mod pcp;

use std::net::Ipv4Addr;

use anyhow::Result;
use tokio::net::UdpSocket;

pub use pcp::Version;

pub async fn probe_available(
    local_ip: Ipv4Addr,
    gateway: Ipv4Addr,
    version: pcp::Version,
) -> Result<bool> {
    // TODO(@divma): here we likely want to keep both the server epoch so that previous probes
    // identify loss of state
    tracing::debug!("Starting pxp probe");
    // TODO(@divma): do we want to keep this socket alive for more than the probe?
    let socket = UdpSocket::bind((local_ip, pcp::CLIENT_PORT)).await?;
    socket.connect((gateway, pcp::SERVER_PORT)).await?;
    let req = pcp::Request::annouce(version, local_ip.to_ipv6_mapped());
    socket.send(&req.encode()).await?;
    let mut buffer = vec![0; pcp::MAX_RESP_SIZE];
    socket.recv(&mut buffer).await?;
    let response = pcp::Response::decode(&buffer)?;
    tracing::debug!("received pcp response {response:?}");

    // TODO(@divma): this needs better handling
    // if the error code is unusupported version, the server sends the higher version is supports,
    // not sure where this value is sent
    let available = response.opcode == pcp::Opcode::Announce
        && response.result_code == pcp::ResultCode::Success;
    Ok(available)
}
