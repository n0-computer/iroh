//! NAT64 address synthesis (RFC 6052) and prefix discovery (RFC 7050).
//!
//! On IPv6-only networks with NAT64 (e.g. most large mobile carriers), an endpoint has no
//! usable IPv4 socket, so a remote's IPv4 direct addresses are unreachable as-is and the
//! connection stays on the relay. Those IPv4 addresses are still reachable through the
//! carrier's NAT64 gateway by sending to the IPv4-embedded IPv6 address synthesized from the
//! network's NAT64 prefix.
//!
//! The translation is done transparently in the IP transports, like a userspace CLAT
//! (RFC 6877): while a prefix is active, datagrams to a translatable IPv4 destination are sent
//! from the IPv6 socket to the synthesized address, and datagrams received from an address
//! inside the prefix are reported as coming from the embedded IPv4 address. The QUIC stack,
//! path management and the remote never see the IPv6 form. Because the relay's QAD probes use
//! the same sockets, an IPv4 QAD round trip then succeeds through NAT64 and yields the NAT64
//! gateway's public address, which is published as a reflexive candidate for hole punching.
//!
//! [`Nat64State`] is written by net_report and read by the IP transports. See
//! `net_report::Client::update_nat64` for when it is activated.
//!
//! Hand-written instead of depending on the `rfc6052` crate because that crate is GPL-3.0.

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

/// The name resolved to discover the NAT64 prefix (RFC 7050 §2).
pub(crate) const IPV4ONLY_ARPA: &str = "ipv4only.arpa.";

/// The well-known IPv4 addresses `ipv4only.arpa` resolves to (RFC 7050 §2.2).
const WELL_KNOWN_IPV4: [Ipv4Addr; 2] =
    [Ipv4Addr::new(192, 0, 0, 170), Ipv4Addr::new(192, 0, 0, 171)];

/// Prefix lengths allowed by RFC 6052 §2.2, in the order RFC 7050 §3 checks them.
const PREFIX_LENGTHS: [u8; 6] = [32, 40, 48, 56, 64, 96];

/// A NAT64 prefix as used to build IPv4-embedded IPv6 addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Nat64Prefix {
    prefix: Ipv6Addr,
    len: u8,
}

impl Nat64Prefix {
    /// The Well-Known Prefix `64:ff9b::/96` (RFC 6052 §2.1).
    pub(crate) const WELL_KNOWN: Self = Self {
        prefix: Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0),
        len: 96,
    };

    /// Creates a prefix, returning `None` for lengths not allowed by RFC 6052.
    ///
    /// Bits beyond `len` are cleared.
    pub(crate) fn new(prefix: Ipv6Addr, len: u8) -> Option<Self> {
        if !PREFIX_LENGTHS.contains(&len) {
            return None;
        }
        let mut octets = prefix.octets();
        for b in octets.iter_mut().skip(usize::from(len / 8)) {
            *b = 0;
        }
        Some(Self {
            prefix: Ipv6Addr::from(octets),
            len,
        })
    }

    /// Builds the IPv4-embedded IPv6 address for `v4` (RFC 6052 §2.2).
    pub(crate) fn synthesize(&self, v4: Ipv4Addr) -> Ipv6Addr {
        let mut octets = self.prefix.octets();
        for (pos, byte) in embed_positions(self.len).into_iter().zip(v4.octets()) {
            octets[pos] = byte;
        }
        Ipv6Addr::from(octets)
    }

    /// Extracts the embedded IPv4 address if `v6` lies within this prefix and its
    /// u-octet and suffix are zero.
    pub(crate) fn extract(&self, v6: Ipv6Addr) -> Option<Ipv4Addr> {
        let octets = v6.octets();
        let prefix_bytes = usize::from(self.len / 8);
        if octets[..prefix_bytes] != self.prefix.octets()[..prefix_bytes] {
            return None;
        }
        extract_at(self.len, &octets)
    }

    /// Discovers the NAT64 prefix from the AAAA answers for `ipv4only.arpa` (RFC 7050 §3).
    ///
    /// Returns the first prefix under which one of the well-known IPv4 addresses is found.
    pub(crate) fn from_ipv4only_arpa(answers: &[Ipv6Addr]) -> Option<Self> {
        answers.iter().find_map(|addr| {
            let octets = addr.octets();
            PREFIX_LENGTHS.iter().find_map(|&len| {
                let v4 = extract_at(len, &octets)?;
                WELL_KNOWN_IPV4
                    .contains(&v4)
                    .then(|| Self::new(*addr, len))
                    .flatten()
            })
        })
    }
}

impl From<Nat64Prefix> for ipnet::Ipv6Net {
    fn from(value: Nat64Prefix) -> Self {
        ipnet::Ipv6Net::new(value.prefix, value.len).expect("RFC 6052 lengths are valid")
    }
}

/// Byte positions holding the IPv4 octets for a given prefix length.
///
/// Bits 64..72 (byte 8, the "u" octet) are reserved and always skipped (RFC 6052 §2.2).
fn embed_positions(len: u8) -> [usize; 4] {
    let mut out = [0; 4];
    let mut pos = usize::from(len / 8);
    for slot in &mut out {
        if pos == 8 {
            pos += 1;
        }
        *slot = pos;
        pos += 1;
    }
    out
}

/// Reads the IPv4 octets for `len`, requiring the u-octet and the suffix to be zero.
fn extract_at(len: u8, octets: &[u8; 16]) -> Option<Ipv4Addr> {
    let positions = embed_positions(len);
    if octets[8] != 0 && !positions.contains(&8) {
        return None;
    }
    let last = positions[3];
    if octets[last + 1..].iter().any(|&b| b != 0) {
        return None;
    }
    let v4 = positions.map(|p| octets[p]);
    Some(Ipv4Addr::from(v4))
}

/// The NAT64 prefix currently used for translation, shared between net_report and the IP
/// transports.
#[derive(Debug, Clone, Default)]
pub(crate) struct Nat64State(Arc<Nat64StateInner>);

#[derive(Debug, Default)]
struct Nat64StateInner {
    /// Fast path for the common case of no NAT64, checked on every IPv4 send / IPv6 receive.
    active: AtomicBool,
    prefix: RwLock<Option<Nat64Prefix>>,
}

impl Nat64State {
    /// The active prefix, if translation is enabled.
    pub(crate) fn get(&self) -> Option<Nat64Prefix> {
        if !self.0.active.load(Ordering::Acquire) {
            return None;
        }
        *self.0.prefix.read().expect("poisoned")
    }

    /// Enables translation with `prefix`, or disables it with `None`.
    pub(crate) fn set(&self, prefix: Option<Nat64Prefix>) {
        let mut guard = self.0.prefix.write().expect("poisoned");
        *guard = prefix;
        self.0.active.store(prefix.is_some(), Ordering::Release);
    }

    /// The address to send to instead of `dst`, if `dst` should go through NAT64.
    pub(crate) fn translate_dst(&self, dst: SocketAddrV4) -> Option<SocketAddrV6> {
        let prefix = self.get()?;
        is_translatable(*dst.ip())
            .then(|| SocketAddrV6::new(prefix.synthesize(*dst.ip()), dst.port(), 0, 0))
    }

    /// The IPv4 address a datagram from `src` originally came from, if it came through NAT64.
    pub(crate) fn untranslate_src(&self, src: SocketAddrV6) -> Option<SocketAddrV4> {
        let prefix = self.get()?;
        let v4 = prefix.extract(*src.ip())?;
        is_translatable(v4).then(|| SocketAddrV4::new(v4, src.port()))
    }
}

/// Whether a remote IPv4 address is worth translating through NAT64.
///
/// NAT64 only reaches globally routable IPv4 destinations (RFC 6052 §3.1), so addresses a
/// remote may advertise but that are never reachable through it are skipped: private, shared
/// (CGNAT), loopback, link-local, IETF protocol assignments (which include the CLAT address
/// range `192.0.0.0/29`, RFC 7335), multicast and reserved.
///
/// The documentation and benchmarking ranges are deliberately not excluded: they never occur
/// as real addresses, and network simulations (e.g. patchbay) use them as public addresses.
pub(crate) fn is_translatable(v4: Ipv4Addr) -> bool {
    let [a, b, c, _] = v4.octets();
    !(v4.is_unspecified()
        || v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_multicast()
        || a == 0
        || a >= 240
        || (a == 100 && (b & 0xc0) == 64) // 100.64.0.0/10 shared address space
        || (a == 192 && b == 0 && c == 0)) // 192.0.0.0/24 IETF protocol assignments
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 33);

    fn p(s: &str, len: u8) -> Nat64Prefix {
        Nat64Prefix::new(s.parse().unwrap(), len).unwrap()
    }

    /// The table in RFC 6052 §2.4.
    #[test]
    fn rfc6052_examples() {
        let cases = [
            ("2001:db8::", 32, "2001:db8:c000:221::"),
            ("2001:db8:100::", 40, "2001:db8:1c0:2:21::"),
            ("2001:db8:122::", 48, "2001:db8:122:c000:2:2100::"),
            ("2001:db8:122:300::", 56, "2001:db8:122:3c0:0:221::"),
            ("2001:db8:122:344::", 64, "2001:db8:122:344:c0:2:2100:0"),
            ("2001:db8:122:344::", 96, "2001:db8:122:344::192.0.2.33"),
            ("64:ff9b::", 96, "64:ff9b::192.0.2.33"),
        ];
        for (prefix, len, expected) in cases {
            let prefix = p(prefix, len);
            let expected: Ipv6Addr = expected.parse().unwrap();
            assert_eq!(prefix.synthesize(V4), expected, "/{len}");
            assert_eq!(prefix.extract(expected), Some(V4), "/{len} roundtrip");
        }
    }

    #[test]
    fn well_known_prefix() {
        let synth = Nat64Prefix::WELL_KNOWN.synthesize(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(synth, "64:ff9b::102:304".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn rejects_invalid_lengths() {
        for len in [0, 33, 72, 128] {
            assert!(Nat64Prefix::new(Ipv6Addr::UNSPECIFIED, len).is_none());
        }
    }

    #[test]
    fn new_clears_bits_beyond_prefix() {
        assert_eq!(p("2001:db8:ffff:ffff::1", 32), p("2001:db8::", 32));
    }

    #[test]
    fn extract_rejects_other_prefixes_and_nonzero_suffix() {
        let prefix = p("2001:db8::", 32);
        assert_eq!(prefix.extract("2001:db9:c000:221::".parse().unwrap()), None);
        // Non-zero u-octet.
        assert_eq!(
            prefix.extract("2001:db8:c000:221:ff00::".parse().unwrap()),
            None
        );
        // Non-zero suffix.
        assert_eq!(
            prefix.extract("2001:db8:c000:221::1".parse().unwrap()),
            None
        );
    }

    /// RFC 7050 §3: the prefix is found by locating the well-known IPv4 address.
    #[test]
    fn discovers_prefix_from_ipv4only_arpa() {
        let answers = [
            "64:ff9b::c000:aa".parse().unwrap(),
            "64:ff9b::c000:ab".parse().unwrap(),
        ];
        assert_eq!(
            Nat64Prefix::from_ipv4only_arpa(&answers),
            Some(Nat64Prefix::WELL_KNOWN)
        );

        // A network-specific /64 prefix (byte 8 skipped).
        let nsp = p("2001:db8:122:344::", 64);
        let answer = nsp.synthesize(Ipv4Addr::new(192, 0, 0, 170));
        assert_eq!(Nat64Prefix::from_ipv4only_arpa(&[answer]), Some(nsp));

        // A network-specific /32 prefix.
        let nsp = p("2001:db8::", 32);
        let answer = nsp.synthesize(Ipv4Addr::new(192, 0, 0, 171));
        assert_eq!(Nat64Prefix::from_ipv4only_arpa(&[answer]), Some(nsp));
    }

    #[test]
    fn no_prefix_without_well_known_address() {
        // A real AAAA record (no NAT64): nothing embedded.
        let answers = ["2606:4700::6810:84e5".parse().unwrap()];
        assert_eq!(Nat64Prefix::from_ipv4only_arpa(&answers), None);
        assert_eq!(Nat64Prefix::from_ipv4only_arpa(&[]), None);
    }

    #[test]
    fn translatable_addresses() {
        assert!(is_translatable(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(is_translatable(Ipv4Addr::new(8, 8, 8, 8)));
        for v4 in [
            Ipv4Addr::new(192, 168, 1, 50),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 127, 255, 255),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(192, 0, 0, 170),
            // CLAT address seen on an iPhone on T-Mobile.
            Ipv4Addr::new(192, 0, 0, 6),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(240, 0, 0, 1),
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        ] {
            assert!(!is_translatable(v4), "{v4}");
        }
        // Just outside the shared range.
        assert!(is_translatable(Ipv4Addr::new(100, 128, 0, 1)));
        // Ranges used as public addresses in network simulations.
        assert!(is_translatable(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(is_translatable(Ipv4Addr::new(203, 0, 113, 1)));
    }

    #[test]
    fn state_inactive_by_default() {
        let state = Nat64State::default();
        let dst = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 4433);
        assert_eq!(state.get(), None);
        assert_eq!(state.translate_dst(dst), None);
        let src = SocketAddrV6::new("64:ff9b::102:304".parse().unwrap(), 4433, 0, 0);
        assert_eq!(state.untranslate_src(src), None);
    }

    #[test]
    fn state_translates_round_trip() {
        let state = Nat64State::default();
        state.set(Some(Nat64Prefix::WELL_KNOWN));
        let dst = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 4433);
        let synth = state.translate_dst(dst).unwrap();
        assert_eq!(synth.ip(), &"64:ff9b::102:304".parse::<Ipv6Addr>().unwrap());
        assert_eq!(synth.port(), 4433);
        assert_eq!(state.untranslate_src(synth), Some(dst));

        // Private destinations are not translated (NAT64 would not forward them).
        let lan = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 50), 1234);
        assert_eq!(state.translate_dst(lan), None);
        // Native IPv6 sources are left alone.
        let native = SocketAddrV6::new("2001:db8::1".parse().unwrap(), 1234, 0, 0);
        assert_eq!(state.untranslate_src(native), None);

        state.set(None);
        assert_eq!(state.translate_dst(dst), None);
        assert_eq!(state.untranslate_src(synth), None);
    }

    #[test]
    fn state_shared_between_clones() {
        let writer = Nat64State::default();
        let reader = writer.clone();
        writer.set(Some(Nat64Prefix::WELL_KNOWN));
        assert_eq!(reader.get(), Some(Nat64Prefix::WELL_KNOWN));
    }
}
