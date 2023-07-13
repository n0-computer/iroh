//! Definitions and utilities to interact with a NAT-PMP/PCP server.

use std::net::Ipv6Addr;

use tracing::{debug, trace};

// PCP and NAT-PMP share same ports, reasigned by IANA from the older version to the new one. See
// <https://datatracker.ietf.org/doc/html/rfc6887#section-19>

/// Port to use when acting as a client. This is the one we bind to.
pub const CLIENT_PORT: u16 = 5350;

/// Port to use when acting as a server. This is the one we direct requests to.
pub const SERVER_PORT: u16 = 5351;

/// Max size of a PCP packet as indicated in
/// [RFC 6887 Common Request and Response Header Format](https://datatracker.ietf.org/doc/html/rfc6887#section-7)
pub const MAX_RESP_SIZE: usize = 1100;

/// Size of a [`Request`] sent by this client, in bytes.
// NOTE: 1byte for the version +
//       1byte for the opcode +
//       2bytes reserved +
//       4bytes for the lifetime +
//       16bytes for the client's ip
const REQ_SIZE: usize = 1 + 1 + 2 + 4 + 16;

/// Minimum size of an encoded [`Response`] sent by a server to this client.
// NOTE: 1byte for the version +
//       1byte for the opcode ORd with [`RESPONSE_INDICATOR`] +
//       1byte reserved +
//       1byte for the result code +
//       4bytes for the lifetime +
//       4bytes for the epoch time +
//       12bytes reserved
const MIN_RESP_SIZE: usize = 1 + 1 + 1 + 1 + 4 + 4 + 12;

/// Indicator ORd into the [`Opcode`] to indicate a response packet.
const RESPONSE_INDICATOR: u8 = 1u8 << 7;

/// NAT-PMP/PCP Version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(strum::EnumIter))]
#[repr(u8)]
pub enum Version {
    /// PCP Version according to [RFC 6887 Version Negotiation](https://datatracker.ietf.org/doc/html/rfc6887#section-9)
    // Version 2
    Pcp = 2,
}

/// Opcode as defined in [RFC 6887 IANA Considerations](https://datatracker.ietf.org/doc/html/rfc6887#section-19)
// NOTE: PEER is not used, therefor not implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(strum::EnumIter))]
#[repr(u8)]
pub enum Opcode {
    /// Annouce Opcode.
    ///
    /// Used by the server to annouce changes to clients. These include restarts
    /// (indicating loss of state) and changes to mappings and external ip addresses.
    ///
    /// See [RFC 6887 ANNOUNCE Opcode](https://datatracker.ietf.org/doc/html/rfc6887#section-14.1)
    Announce = 0,
    /// Map Opcode,
    ///
    /// Used to deal with endpoint-idependent mappings.
    ///
    /// See [RFC 6887 MAP Opcode](https://datatracker.ietf.org/doc/html/rfc6887#section-11)
    Map = 1,
}

/// ResultCode in a [`Response`].
///
/// Refer to [RFC 6887 Result Codes](https://datatracker.ietf.org/doc/html/rfc6887#section-7.4)
// NOTE: docs for each variant are largely adapted from the RFC's description of each code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(strum::EnumIter))]
#[repr(u8)]
pub enum ResultCode {
    /// Success.
    Success = 0,
    /// The version number at the start of the PCP Request header is not recognized by the PCP
    /// server.
    UnsuppVersion = 1,
    /// The requested operation is disabled for this PCP client, or the PCP client requested an
    /// operation that cannot be fulfilled by the PCP server's security policy.
    NotAuthorized = 2,
    /// The request could not be successfully parsed.
    MalformedRequest = 3,
    /// Unsupported Opcode.
    UnsuppOpcode = 4,
    /// Unsupported option. This error only occurs if the option is in the mandatory-to-process
    /// range.
    UnsuppOption = 5,
    /// Malformed option (e.g., appears too many times, invalid length).
    MalformedOption = 6,
    /// The PCP server or the device it controls is experiencing a network failure of some sort
    /// (e.g., has not yet obtained an external IP address). This is a short lifetime error.
    NetworkFailure = 7,
    /// Request is well-formed and valid, but the server has insufficient resources to complete the
    /// requested operation at this time. This is a short lifetime error.
    NoResources = 8,
    /// Unsupported transport protocol, e.g., SCTP in a NAT that handles only UDP and TCP. This is
    /// a long lifetime error.
    UnsuppProtocol = 9,
    /// This attempt to create a new mapping would exceed this subscriber's port quota. This is a
    /// short lifetime error.
    UserExQuota = 10,
    /// The suggested external port and/or external address cannot be provided.
    CannotProvideExternal = 11,
    /// The source IP address of the request packet does not match the contents of the PCP Client's
    /// IP Address field.
    AddressMismatch = 12,
    /// The PCP server was not able to create the filters in this request.
    ExcessiveRemotePeers = 13,
}

/// A PCP Request.
///
/// See [RFC 6887 Request Header](https://datatracker.ietf.org/doc/html/rfc6887#section-7.1)
///
// NOTE: Opcode information and PCP Options are both optional, and currently not used in this
// code, thus not implemented.
pub struct Request {
    /// [`Version`] to use in this request.
    version: Version,
    /// Requested lifetime in seconds used by the [`Request::opcode`].
    lifetime_seconds: u32,
    /// IP Address of the client.
    ///
    /// If the IP is an IpV4 address, is represented as a IpV4-mapped IpV6 address.
    client_addr: Ipv6Addr,
    // TODO(@divma): docs
    opcode_data: OpcodeData,
    // TODO(@divma): docs
    pcp_options: Vec<u8>,
}

// TODO(@divma): docs
// NOTE: technically any IANA protocol is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    Udp = 17,
}

pub enum OpcodeData {
    Annouce,
    MapData(MapData),
}

impl OpcodeData {
    pub fn opcode(&self) -> Opcode {
        match self {
            OpcodeData::Annouce => Opcode::Announce,
            OpcodeData::MapData(_) => Opcode::Map,
        }
    }

    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        match self {
            OpcodeData::Annouce => {}
            OpcodeData::MapData(map_data) => buf.extend_from_slice(&map_data.encode()),
        }
    }

    pub const fn encoded_size(&self) -> usize {
        match self {
            OpcodeData::Annouce => 0,
            OpcodeData::MapData(_) => MapData::ENCODED_SIZE,
        }
    }
}

pub struct MapData {
    nonce: [u8; 12],
    protocol: Protocol,
    local_port: u16,
    preferred_external_port: u16,
    preferred_external_address: Ipv6Addr,
}

impl MapData {
    /// Size of the opcode-specific data of a [`Opcode::Map`] request.
    // NOTE: 12bytes for the nonce +
    //       1byte for the protocol +
    //       3bytes reserved +
    //       2bytes for the local port +
    //       2 butes for the external port +
    //       16bytes for the external address
    pub const ENCODED_SIZE: usize = 12 + 1 + 3 + 2 + 2 + 16;
    pub fn encode(&self) -> [u8; Self::ENCODED_SIZE] {
        let MapData {
            nonce,
            protocol,
            local_port,
            preferred_external_port,
            preferred_external_address,
        } = self;
        let mut buf = [0; Self::ENCODED_SIZE];
        buf[0..12].copy_from_slice(nonce);
        buf[12] = *protocol as u8;
        // buf[13..16] reserved
        buf[16..18].copy_from_slice(&local_port.to_be_bytes());
        buf[18..20].copy_from_slice(&preferred_external_port.to_be_bytes());
        buf[20..].copy_from_slice(&preferred_external_address.octets());

        buf
    }
}

/// A PCP Response/Notification.
///
/// See [RFC 6887 Response Header](https://datatracker.ietf.org/doc/html/rfc6887#section-7.2)
///
// NOTE: Opcode response data and PCP Options are both optional, and currently not used in this
// code, thus not implemented.
// NOTE: last three fields are *currently* not used, but are useful for debug purposes
#[allow(unused)]
#[derive(derive_more::Debug)]
pub struct Response {
    /// [`Version`] of the response.
    version: Version,
    /// [`Opcode`] of the [`Request`] that related to this response.
    opcode: Opcode,
    /// [`ResultCode`] of the response.
    result_code: ResultCode,
    /// Lifetime in seconds that can be assumed by this response.
    ///
    /// For sucessful requests, this lifetime is how long to assume a mapping will last. For error
    /// responses, the lifetime indicates how long will the server return the same response for
    /// this response.
    lifetime_seconds: u32,
    /// Epoch time of the server.
    epoch_time: u32,
    // TODO(@divma): docs
    #[debug("{}bytes", extra_data.len())]
    extra_data: Vec<u8>,
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let Request {
            version,
            lifetime_seconds,
            client_addr,
            opcode_data,
            pcp_options,
        } = self;
        let mut buf = Vec::with_capacity(REQ_SIZE + opcode_data.encoded_size());
        // buf[0]
        buf.push(*version as u8);
        // buf[1]
        buf.push(opcode_data.opcode() as u8);
        // buf[2] reserved
        buf.push(0);
        // buf[3] reserved
        buf.push(0);
        // buf[4..8]
        buf.extend_from_slice(&lifetime_seconds.to_be_bytes());
        // buf[8..12]
        buf.extend_from_slice(&client_addr.octets());
        // buf[12..]
        opcode_data.encode_into(&mut buf);
        buf.extend_from_slice(pcp_options);

        buf
    }

    pub fn annouce(client_addr: Ipv6Addr) -> Request {
        Request {
            version: Version::Pcp,
            // opcode announce requires a lifetime of 0 and to ignore the lifetime on response
            lifetime_seconds: 0,
            client_addr,
            // the pcp announce opcode requests and responses have no opcode-specific payload
            opcode_data: OpcodeData::Annouce,
            pcp_options: vec![],
        }
    }

    pub fn get_mapping(
        nonce: [u8; 12],
        lifetime_seconds: std::num::NonZeroU32,
        local_port: u16,
        local_ip: std::net::Ipv4Addr,
        preferred_external_port: Option<u16>,
        preferred_external_address: Option<std::net::Ipv4Addr>,
    ) -> Request {
        Request {
            version: Version::Pcp,
            lifetime_seconds: lifetime_seconds.into(),
            client_addr: local_ip.to_ipv6_mapped(),
            opcode_data: OpcodeData::MapData(MapData {
                nonce,
                protocol: Protocol::Udp,
                local_port,
                // if the pcp client does not know the external port, or does not have a
                // preference, it must use 0.
                preferred_external_port: preferred_external_port.unwrap_or_default(),
                preferred_external_address: preferred_external_address
                    .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED)
                    .to_ipv6_mapped(),
            }),
            pcp_options: vec![],
        }
    }
}

/// Errors that can occur when decoding a [`Response`] from a server.
// TODO(@divma): copy docs instead of refer?
#[derive(Debug, derive_more::Display, thiserror::Error)]
pub enum DecodeError {
    /// Request is too short or is otherwise malformed.
    #[display("Response is malformed")]
    Malformed,
    /// The [`RESPONSE_INDICATOR`] is not present.
    #[display("Packet does not appear to be a response")]
    NotAResponse,
    /// See [`InvalidOpcode`].
    #[display("Invalid Opcode received")]
    InvalidOpcode,
    /// See [`InvalidVersion`].
    #[display("Invalid version received")]
    InvalidVersion,
    /// See [`InvalidResultCode`].
    #[display("Invalid result code received")]
    InvalidResultCode,
}

impl From<InvalidOpcode> for DecodeError {
    fn from(_: InvalidOpcode) -> Self {
        DecodeError::InvalidOpcode
    }
}

impl From<InvalidVersion> for DecodeError {
    fn from(_: InvalidVersion) -> Self {
        DecodeError::InvalidVersion
    }
}

impl From<InvalidResultCode> for DecodeError {
    fn from(_: InvalidResultCode) -> Self {
        DecodeError::InvalidResultCode
    }
}

impl Response {
    // TODO(@divma): from_bytes?
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        if buf.len() < MIN_RESP_SIZE || buf.len() > MAX_RESP_SIZE {
            return Err(DecodeError::Malformed);
        }
        let version: Version = buf[0].try_into()?;
        let opcode = buf[1];
        if !(opcode & RESPONSE_INDICATOR == RESPONSE_INDICATOR) {
            return Err(DecodeError::NotAResponse);
        }
        let opcode = (opcode & !RESPONSE_INDICATOR).try_into()?;
        // buf[2] reserved
        let result_code = buf[3].try_into()?;
        let lifetime_bytes = buf[4..8].try_into().expect("slice has the right len");
        let lifetime_seconds = u32::from_be_bytes(lifetime_bytes);
        let epoch_bytes = buf[8..12].try_into().expect("slice has the right len");
        let epoch_time = u32::from_be_bytes(epoch_bytes);
        // buf[12..24] reserved
        let extra_data = buf[12..].into();

        Ok(Response {
            version,
            opcode,
            result_code,
            lifetime_seconds,
            epoch_time,
            extra_data,
        })
    }
}

/// Error ocurring when attempting to identify the [`Version`] in a server response.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidVersion;

impl TryFrom<u8> for Version {
    type Error = InvalidVersion;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            2 => Ok(Version::Pcp),
            _ => Err(InvalidVersion),
        }
    }
}

/// Error ocurring when attempting to identity the [`Opcode`] in a server response.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidOpcode;

impl TryFrom<u8> for Opcode {
    type Error = InvalidOpcode;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Opcode::Announce),
            1 => Ok(Opcode::Map),
            _ => Err(InvalidOpcode),
        }
    }
}

/// Error ocurring when attempting to decode the [`ResultCode`] in a server response.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidResultCode;

impl TryFrom<u8> for ResultCode {
    type Error = InvalidResultCode;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(ResultCode::Success),
            1 => Ok(ResultCode::UnsuppVersion),
            2 => Ok(ResultCode::NotAuthorized),
            3 => Ok(ResultCode::MalformedRequest),
            4 => Ok(ResultCode::UnsuppOpcode),
            5 => Ok(ResultCode::UnsuppOption),
            6 => Ok(ResultCode::MalformedOption),
            7 => Ok(ResultCode::NetworkFailure),
            8 => Ok(ResultCode::NoResources),
            9 => Ok(ResultCode::UnsuppProtocol),
            10 => Ok(ResultCode::UserExQuota),
            11 => Ok(ResultCode::CannotProvideExternal),
            12 => Ok(ResultCode::AddressMismatch),
            13 => Ok(ResultCode::ExcessiveRemotePeers),
            _ => Err(InvalidResultCode),
        }
    }
}

const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

pub async fn probe_available(local_ip: std::net::Ipv4Addr, gateway: std::net::Ipv4Addr) -> bool {
    debug!("starting pcp probe");
    match probe_available_fallible(local_ip, gateway).await {
        Ok(response) => {
            trace!("pcp probe response: {response:?}");
            match response.opcode {
                Opcode::Announce => match response.result_code {
                    ResultCode::Success => true,
                    other => {
                        // weird state here, since the server is not giving a positive result, but
                        // it's seemingly available anyway
                        debug!("pcp probe received error code: {other:?}");
                        false
                    }
                },
                _ => {
                    debug!("pcp server returned an unexpected response type for probe");
                    // missbehaving server is not useful
                    false
                }
            }
        }
        Err(e) => {
            debug!("pcp probe failed: {e}");
            false
        }
    }
}

async fn probe_available_fallible(
    local_ip: std::net::Ipv4Addr,
    gateway: std::net::Ipv4Addr,
) -> anyhow::Result<Response> {
    let socket = tokio::net::UdpSocket::bind((local_ip, 0)).await?;
    socket.connect((gateway, SERVER_PORT)).await?;
    let req = Request::annouce(local_ip.to_ipv6_mapped());
    socket.send(&req.encode()).await?;
    let mut buffer = vec![0; MAX_RESP_SIZE];
    let read = tokio::time::timeout(PROBE_TIMEOUT, socket.recv(&mut buffer)).await??;
    let response = Response::decode(&buffer[..read])?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn version_repr_identity() {
        for v in Version::iter() {
            assert_eq!((v as u8).try_into(), Ok(v));
        }
    }

    #[test]
    fn opcode_repr_identity() {
        for o in Opcode::iter() {
            assert_eq!((o as u8).try_into(), Ok(o));
        }
    }

    #[test]
    fn response_code_repr_identity() {
        for rc in ResultCode::iter() {
            assert_eq!((rc as u8).try_into(), Ok(rc));
        }
    }
}
