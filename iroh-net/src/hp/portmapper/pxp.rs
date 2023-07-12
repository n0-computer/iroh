//! Utilities for probing [NAT-PMP](https://datatracker.ietf.org/doc/html/rfc6886) and
//! [PCP](https://datatracker.ietf.org/doc/html/rfc6887).

// NOTES
// TODO(@divma): move to pr desc
// PCP has multicast announcements from the server to the clients, this means binding to
// 224.0.0.1:CLIENT_PORT. to implement or not to implement.

mod protocol;

use std::net::Ipv4Addr;

use anyhow::Result;
use tokio::net::UdpSocket;

pub use protocol::Version;

pub async fn probe_available(
    local_ip: Ipv4Addr,
    gateway: Ipv4Addr,
    version: protocol::Version,
) -> Result<bool> {
    tracing::debug!("Starting pxp probe");
    // TODO(@divma): do we want to keep this socket alive for more than the probe?
    let socket = UdpSocket::bind((local_ip, protocol::CLIENT_PORT)).await?;
    socket.connect((gateway, protocol::SERVER_PORT)).await?;
    let req = protocol::Request::annouce(version, local_ip.to_ipv6_mapped());
    socket.send(&req.encode()).await?;
    let mut buffer = vec![0; protocol::MAX_RESP_SIZE];
    socket.recv(&mut buffer).await?;
    let response = protocol::Response::decode(&buffer)?;
    tracing::debug!("received pcp response {response:?}");

    // TODO(@divma): this needs better handling
    // if the error code is unusupported version, the server sends the higher version is supports,
    // not sure where this value is sent
    let available = response.opcode == protocol::Opcode::Announce
        && response.result_code == protocol::ResultCode::Success;
    Ok(available)
}
