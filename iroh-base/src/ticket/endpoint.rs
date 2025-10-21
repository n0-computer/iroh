//! Tickets for endpoints.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::{Variant1AddrInfo, Variant1EndpointAddr};
use crate::{
    endpoint_addr::EndpointAddr,
    ticket::{self, ParseError, Ticket},
};

/// A token containing information for establishing a connection to an endpoint.
///
/// Contains
/// - The [`EndpointId`] of the endpoint to connect to (a 32-byte ed25519 public key).
/// - Any known [`TransportAddr`]s on which the endpoint can be reached.
///
/// This allows establishing a connection to the endpoint in most circumstances where it is
/// possible to do so.
///
/// This [`EndpointTicket`] is a single item which can be easily serialized and deserialized and
/// implements the [`Ticket`] trait.  The [`Display`] and [`FromStr`] traits can also be
/// used to round-trip the ticket to string.
///
/// [`EndpointId`]: crate::key::EndpointId
/// [`Display`]: std::fmt::Display
/// [`FromStr`]: std::str::FromStr
/// [`TransportAddr`]: crate::TransportAddr
#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
#[display("{}", Ticket::serialize(self))]
pub struct EndpointTicket {
    addr: EndpointAddr,
}

/// Wire format for [`EndpointTicket`].
#[derive(Serialize, Deserialize)]
enum TicketWireFormat {
    Variant1(Variant1EndpointTicket),
}

// Legacy
#[derive(Serialize, Deserialize)]
struct Variant1EndpointTicket {
    addr: Variant1EndpointAddr,
}

impl Ticket for EndpointTicket {
    const KIND: &'static str = "endpoint";

    fn to_bytes(&self) -> Vec<u8> {
        let data = TicketWireFormat::Variant1(Variant1EndpointTicket {
            addr: Variant1EndpointAddr {
                id: self.addr.id,
                info: Variant1AddrInfo {
                    addrs: self.addr.addrs.clone(),
                },
            },
        });
        postcard::to_stdvec(&data).expect("postcard serialization failed")
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let res: TicketWireFormat = postcard::from_bytes(bytes)?;
        let TicketWireFormat::Variant1(Variant1EndpointTicket { addr }) = res;
        Ok(Self {
            addr: EndpointAddr {
                id: addr.id,
                addrs: addr.info.addrs,
            },
        })
    }
}

impl FromStr for EndpointTicket {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ticket::Ticket::deserialize(s)
    }
}

impl EndpointTicket {
    /// Creates a new ticket.
    pub fn new(addr: EndpointAddr) -> Self {
        Self { addr }
    }

    /// The [`EndpointAddr`] of the provider for this ticket.
    pub fn endpoint_addr(&self) -> &EndpointAddr {
        &self.addr
    }
}

impl From<EndpointAddr> for EndpointTicket {
    /// Creates a ticket from given addressing info.
    fn from(addr: EndpointAddr) -> Self {
        Self { addr }
    }
}

impl From<EndpointTicket> for EndpointAddr {
    /// Returns the addressing info from given ticket.
    fn from(ticket: EndpointTicket) -> Self {
        ticket.addr
    }
}

impl Serialize for EndpointTicket {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            let EndpointTicket { addr } = self;
            (addr).serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for EndpointTicket {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_str(&s).map_err(serde::de::Error::custom)
        } else {
            let peer = Deserialize::deserialize(deserializer)?;
            Ok(Self::new(peer))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use data_encoding::HEXLOWER;
    use rand::SeedableRng;

    use super::*;
    use crate::{
        TransportAddr,
        key::{PublicKey, SecretKey},
    };

    fn make_ticket() -> EndpointTicket {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let peer = SecretKey::generate(&mut rng).public();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 1234));
        EndpointTicket {
            addr: EndpointAddr::from_parts(peer, [TransportAddr::Ip(addr)]),
        }
    }

    #[test]
    fn test_ticket_postcard() {
        let ticket = make_ticket();
        let bytes = postcard::to_stdvec(&ticket).unwrap();
        let ticket2: EndpointTicket = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ticket2, ticket);
    }

    #[test]
    fn test_ticket_json() {
        let ticket = make_ticket();
        let json = serde_json::to_string(&ticket).unwrap();
        let ticket2: EndpointTicket = serde_json::from_str(&json).unwrap();
        assert_eq!(ticket2, ticket);
    }

    #[test]
    fn test_ticket_base32() {
        let endpoint_id =
            PublicKey::from_str("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
                .unwrap();

        let ticket = EndpointTicket {
            addr: EndpointAddr::from_parts(
                endpoint_id,
                [
                    TransportAddr::Relay("http://derp.me./".parse().unwrap()),
                    TransportAddr::Ip("127.0.0.1:1024".parse().unwrap()),
                ],
            ),
        };
        let base32 = data_encoding::BASE32_NOPAD
            .decode(
                ticket
                    .to_string()
                    .strip_prefix("endpoint")
                    .unwrap()
                    .to_ascii_uppercase()
                    .as_bytes(),
            )
            .unwrap();
        let expected = [
            // variant
            "00",
            // endpoint id, 32 bytes, see above
            "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6",
            // two addrs
            "02",
            // TransportAddr: Relay
            "00",
            // 16 bytes
            "10",
            // RelayUrl
            "687474703a2f2f646572702e6d652e2f",
            // TransportAddr: IP
            "01",
            // IPv4
            "00",
            // address, see above
            "7f0000018008",
        ];

        // 00ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6
        // 02
        // 00
        // 10
        // 687474703a2f2f646572702e6d652e2f
        // 01
        // 00
        // 7f0000018008
        dbg!(&expected);
        dbg!(HEXLOWER.encode(&base32));
        let expected = HEXLOWER.decode(expected.concat().as_bytes()).unwrap();
        assert_eq!(base32, expected);
    }
}
