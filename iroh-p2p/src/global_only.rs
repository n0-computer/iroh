/// From https://github.com/mxinden/kademlia-exporter/blob/c0ba2b21d158bc23914c37e740f7140ef751ef8b/src/exporter/client/global_only.rs
///
/// A transport wrapper that doesn't dial addresses in the private RFC 1918 address space.
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    pin::Pin,
    task::{Context, Poll},
};

use libp2p::core::{
    multiaddr::{Multiaddr, Protocol},
    transport::{ListenerId, TransportError, TransportEvent},
    Transport,
};
use tracing::log::debug;

// Wrapper around a libp2p `Transport` dropping all dial requests to non-global
// IP addresses.
#[derive(Debug, Clone, Default)]
pub struct GlobalIpOnly<T> {
    inner: T,
}

impl<T> GlobalIpOnly<T> {
    pub fn new(transport: T) -> Self {
        GlobalIpOnly { inner: transport }
    }
}

// Stable adaptation of https://doc.rust-lang.org/std/net/struct.Ipv4Addr.html#method.is_global
const fn is_ipv4_global(addr: Ipv4Addr) -> bool {
    !(addr.octets()[0] == 0 // "This network"
        || addr.is_private()
        || (addr.octets()[0] == 100 && (addr.octets()[1] & 0b1100_0000 == 0b0100_0000)) // addr.is_shared()
        || addr.is_loopback()
        || addr.is_link_local()
        // addresses reserved for future protocols (`192.0.0.0/24`)
        ||(addr.octets()[0] == 192 && addr.octets()[1] == 0 && addr.octets()[2] == 0)
        || addr.is_documentation()
        || (addr.octets()[0] == 198 && (addr.octets()[1] & 0xfe) == 18) // addr.is_benchmarking()
        || (addr.octets()[0] & 240 == 240 && !addr.is_broadcast()) //addr.is_reserved()
        || addr.is_broadcast())
}

// Stable adaptation of https://doc.rust-lang.org/std/net/struct.Ipv6Addr.html#method.is_global
const fn is_ipv6_global(addr: Ipv6Addr) -> bool {
    !(
        addr.is_unspecified()
        || addr.is_loopback()
        // IPv4-mapped Address (`::ffff:0:0/96`)
        || matches!(addr.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
        // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
        || matches!(addr.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
        // Discard-Only Address Block (`100::/64`)
        || matches!(addr.segments(), [0x100, 0, 0, 0, _, _, _, _])
        // IETF Protocol Assignments (`2001::/23`)
        || (matches!(addr.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
            && !(
                // Port Control Protocol Anycast (`2001:1::1`)
                u128::from_be_bytes(addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                || u128::from_be_bytes(addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                // AMT (`2001:3::/32`)
                || matches!(addr.segments(), [0x2001, 3, _, _, _, _, _, _])
                // AS112-v6 (`2001:4:112::/48`)
                || matches!(addr.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                // ORCHIDv2 (`2001:20::/28`)
                || matches!(addr.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x2F)
            ))
        || ((addr.segments()[0] == 0x2001) && (addr.segments()[1] == 0xdb8)) // addr.is_documentation()
        || ((addr.segments()[0] & 0xfe00) == 0xfc00) // addr.is_unique_local()
        || ((addr.segments()[0] & 0xffc0) == 0xfe80)
        // addr.is_unicast_link_local()
    )
}

impl<T: Transport + Unpin> Transport for GlobalIpOnly<T> {
    type Output = <T as Transport>::Output;
    type Error = <T as Transport>::Error;
    type ListenerUpgrade = <T as Transport>::ListenerUpgrade;
    type Dial = <T as Transport>::Dial;

    fn listen_on(&mut self, addr: Multiaddr) -> Result<ListenerId, TransportError<Self::Error>> {
        self.inner.listen_on(addr)
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        self.inner.remove_listener(id)
    }

    fn dial(&mut self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        match addr.iter().next() {
            Some(Protocol::Ip4(a)) => {
                if is_ipv4_global(a) {
                    self.inner.dial(addr)
                } else {
                    debug!("Not dialing non global IP address {:?}.", a);
                    Err(TransportError::MultiaddrNotSupported(addr))
                }
            }
            Some(Protocol::Ip6(a)) => {
                if is_ipv6_global(a) {
                    self.inner.dial(addr)
                } else {
                    debug!("Not dialing non global IP address {:?}.", a);
                    Err(TransportError::MultiaddrNotSupported(addr))
                }
            }
            _ => {
                debug!("Not dialing unsupported Multiaddress {:?}.", addr);
                Err(TransportError::MultiaddrNotSupported(addr))
            }
        }
    }

    fn dial_as_listener(
        &mut self,
        addr: Multiaddr,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        self.inner.dial_as_listener(addr)
    }

    fn address_translation(&self, listen: &Multiaddr, observed: &Multiaddr) -> Option<Multiaddr> {
        self.inner.address_translation(listen, observed)
    }

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        Pin::new(&mut self.inner).poll(cx)
    }
}
