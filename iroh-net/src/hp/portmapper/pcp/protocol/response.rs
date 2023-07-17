use derive_more::Display;
use num_enum::{IntoPrimitive, TryFromPrimitive, TryFromPrimitiveError};

use super::{opcode_data::OpcodeData, Opcode, Version};

/// ResultCode in a [`Response`] whe it's successful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum SuccessCode {
    /// Result code indicating a successful response.
    Success = 0,
}

/// ResultCode in a [`Response`], when said code is an error.
/// [`SuccessCode`] handles the sucess case.
///
/// Refer to [RFC 6887 Result Codes](https://datatracker.ietf.org/doc/html/rfc6887#section-7.4)
// NOTE: docs for each variant are largely adapted from the RFC's description of each code.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive, Display, thiserror::Error,
)]
#[repr(u8)]
pub enum ErrorCode {
    /// The version number at the start of the PCP Request header is not recognized by the PCP
    /// server.
    #[display("sent version is not supported")]
    UnsuppVersion = 1,
    /// The requested operation is disabled for this PCP client, or the PCP client requested an
    /// operation that cannot be fulfilled by the PCP server's security policy.
    #[display("operation not authorized")]
    NotAuthorized = 2,
    /// The request could not be successfully parsed.
    #[display("could not parse the request")]
    MalformedRequest = 3,
    /// Unsupported Opcode.
    #[display("opcode is not supported")]
    UnsuppOpcode = 4,
    /// Unsupported option. This error only occurs if the option is in the mandatory-to-process
    /// range.
    #[display("option is not supported")]
    UnsuppOption = 5,
    /// Malformed option (e.g., appears too many times, invalid length).
    #[display("option could not be parsed")]
    MalformedOption = 6,
    /// The PCP server or the device it controls is experiencing a network failure of some sort
    /// (e.g., has not yet obtained an external IP address). This is a short lifetime error.
    #[display("spurious network failure")]
    NetworkFailure = 7,
    /// Request is well-formed and valid, but the server has insufficient resources to complete the
    /// requested operation at this time. This is a short lifetime error.
    #[display("not enough resources for this request")]
    NoResources = 8,
    /// Unsupported transport protocol, e.g., SCTP in a NAT that handles only UDP and TCP. This is
    /// a long lifetime error.
    #[display("unsupported protocol")]
    UnsuppProtocol = 9,
    /// This attempt to create a new mapping would exceed this subscriber's port quota. This is a
    /// short lifetime error.
    #[display("quota exceeded")]
    UserExQuota = 10,
    /// The suggested external port and/or external address cannot be provided.
    #[display("requested external address cannot be provided")]
    CannotProvideExternal = 11,
    /// The source IP address of the request packet does not match the contents of the PCP Client's
    /// IP Address field.
    #[display("sender and declared ip do not match")]
    AddressMismatch = 12,
    /// The PCP server was not able to create the filters in this request.
    #[display("excessive reporte peers in filter option")]
    ExcessiveRemotePeers = 13,
}

/// Result code of a PCP response.
#[derive(Debug)]
pub enum ResultCode {
    /// A success result code. See [`SuccessCode`].
    Success,
    /// An error code. See [`ErrorCode`].
    Error(ErrorCode),
}

impl TryFrom<u8> for ResultCode {
    type Error = TryFromPrimitiveError<ErrorCode>;

    fn try_from(value: u8) -> Result<Self, TryFromPrimitiveError<ErrorCode>> {
        if let Ok(SuccessCode::Success) = SuccessCode::try_from(value) {
            Ok(ResultCode::Success)
        } else {
            ErrorCode::try_from(value).map(ResultCode::Error)
        }
    }
}

impl From<ResultCode> for u8 {
    fn from(value: ResultCode) -> Self {
        match value {
            ResultCode::Success => SuccessCode::Success.into(),
            ResultCode::Error(e) => e.into(),
        }
    }
}

/// A PCP successful Response/Notification.
///
/// See [RFC 6887 Response Header](https://datatracker.ietf.org/doc/html/rfc6887#section-7.2)
///
// NOTE: first two fields are *currently* not used, but are useful for debug purposes
#[allow(unused)]
#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    /// Lifetime in seconds that can be assumed by this response.
    ///
    /// For map requests, this lifetime is how long to assume a mapping will last.
    pub lifetime_seconds: u32,
    /// Epoch time of the server.
    pub epoch_time: u32,
    /// Data of the resoponse.
    pub data: OpcodeData,
}

/// Errors that can occur when decoding a [`Response`] from a server.
#[derive(Debug, derive_more::Display, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    /// Request is too short or is otherwise malformed.
    #[display("Response is malformed")]
    Malformed,
    /// The [`Response::RESPONSE_INDICATOR`] is not present.
    #[display("Packet does not appear to be a response")]
    NotAResponse,
    /// The received opcode is not recognized.
    #[display("Invalid Opcode received")]
    InvalidOpcode,
    /// The received version is not recognized.
    #[display("Invalid version received")]
    InvalidVersion,
    /// The received result code is not recognized.
    #[display("Invalid result code received")]
    InvalidResultCode,
    /// The received opcode data could not be decoded.
    #[display("Invalid opcode data received")]
    InvalidOpcodeData,
}

#[derive(Debug, derive_more::Display, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    DecodeError(DecodeError),
    ErrorCode(ErrorCode),
}

impl Response {
    /// Max size of a PCP packet as indicated in
    /// [RFC 6887 Common Request and Response Header Format](https://datatracker.ietf.org/doc/html/rfc6887#section-7)
    pub const MAX_SIZE: usize = 1100;

    /// Minimum size of an encoded [`Response`] sent by a server to this client.
    pub const MIN_SIZE: usize = // parts
        1 + // version
        1 + // opcode ORd with [`Response::RESPONSE_INDICATOR`]
        1 + // reserved
        1 + // result code
        4 + // lifetime
        4 + // epoch time
        12; // reserved

    /// Indicator ORd into the [`Opcode`] to indicate a response packet.
    pub const RESPONSE_INDICATOR: u8 = 1u8 << 7;

    /// Decode a response.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::MIN_SIZE || buf.len() > Self::MAX_SIZE {
            return Err(Error::DecodeError(DecodeError::Malformed));
        }

        let _version: Version = buf[0]
            .try_into()
            .map_err(|_| Error::DecodeError(DecodeError::InvalidVersion))?;

        let opcode = buf[1];
        if opcode & Self::RESPONSE_INDICATOR != Self::RESPONSE_INDICATOR {
            return Err(Error::DecodeError(DecodeError::NotAResponse));
        }
        let opcode: Opcode = (opcode & !Self::RESPONSE_INDICATOR)
            .try_into()
            .map_err(|_| Error::DecodeError(DecodeError::InvalidOpcode))?;

        // buf[2] reserved

        // return early if the result code is an error
        let result_code: ResultCode = buf[3]
            .try_into()
            .map_err(|_| Error::DecodeError(DecodeError::InvalidResultCode))?;
        match result_code {
            ResultCode::Success => {}
            ResultCode::Error(error_code) => return Err(Error::ErrorCode(error_code)),
        }

        let lifetime_bytes = buf[4..8].try_into().expect("slice has the right len");
        let lifetime_seconds = u32::from_be_bytes(lifetime_bytes);

        let epoch_bytes = buf[8..12].try_into().expect("slice has the right len");
        let epoch_time = u32::from_be_bytes(epoch_bytes);

        // buf[12..24] reserved

        let data = OpcodeData::decode(opcode, &buf[24..])
            .map_err(|_| Error::DecodeError(DecodeError::InvalidOpcodeData))?;

        Ok(Response {
            lifetime_seconds,
            epoch_time,
            data,
        })
    }

    #[cfg(test)]
    fn random<R: rand::Rng>(opcode: Opcode, rng: &mut R) -> Self {
        let data = OpcodeData::random(opcode, rng);
        Self {
            lifetime_seconds: rng.gen(),
            epoch_time: rng.gen(),
            data,
        }
    }

    #[cfg(test)]
    fn encode(&self) -> Vec<u8> {
        let Response {
            lifetime_seconds,
            epoch_time,
            data,
        } = self;
        let mut buf = Vec::with_capacity(Self::MIN_SIZE);
        // version
        buf.push(Version::Pcp.into());
        // response indicator and opcode
        let opcode: u8 = data.opcode().into();
        buf.push(Response::RESPONSE_INDICATOR | opcode);
        // reserved
        buf.push(0);
        // result code
        buf.push(ResultCode::Success.into());
        // lifetime
        for b in lifetime_seconds.to_be_bytes() {
            buf.push(b);
        }
        // epoch
        for b in epoch_time.to_be_bytes() {
            buf.push(b);
        }
        // reserved
        for _ in 12..Response::MIN_SIZE {
            buf.push(0)
        }
        data.encode_into(&mut buf);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::SeedableRng;

    #[test]
    fn test_decode_external_addr_response() {
        let mut gen = rand_chacha::ChaCha8Rng::seed_from_u64(42);

        let response = Response::random(Opcode::Announce, &mut gen);
        let encoded = response.encode();
        assert_eq!(Ok(response), Response::decode(&encoded));
    }

    #[test]
    fn test_decode_known_response_vector() {
        // only test vector in the tailscale impl
        let encoded = [
            2, 129, 0, 0, 0, 0, 28, 32, 0, 2, 155, 237, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129,
            112, 9, 24, 241, 208, 251, 45, 157, 76, 10, 188, 17, 0, 0, 0, 4, 210, 4, 210, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 255, 255, 135, 180, 175, 246,
        ];
        let response = Response::decode(&encoded).unwrap();
        assert_eq!(&response.encode(), &encoded);
    }
}
