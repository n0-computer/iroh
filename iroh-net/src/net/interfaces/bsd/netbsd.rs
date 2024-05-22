use super::{MessageType, RoutingStack, WireFormat};

use libc::c_int;

// Missing constants from libc.
// https://github.com/rust-lang/libc/issues/3711

// net/route.h
pub const RTF_GATEWAY: c_int = 0x2;
pub const RTAX_DST: c_int = 0;
pub const RTAX_GATEWAY: c_int = 1;
pub const RTAX_NETMASK: c_int = 2;
pub const RTAX_IFP: c_int = 4;
pub const RTAX_BRD: c_int = 7;
pub const RTAX_MAX: c_int = 9;
pub const RTM_VERSION: c_int = 4;
pub const RTA_DST: c_int = 0x1;
pub const RTA_GATEWAY: c_int = 0x2;
pub const RTA_NETMASK: c_int = 0x4;
pub const RTA_GENMASK: c_int = 0x8;
pub const RTA_IFP: c_int = 0x10;
pub const RTA_IFA: c_int = 0x20;
pub const RTA_AUTHOR: c_int = 0x40;
pub const RTA_BRD: c_int = 0x80;

// Message types
pub const RTM_ADD: c_int = 0x1;
pub const RTM_DELETE: c_int = 0x2;
pub const RTM_CHANGE: c_int = 0x3;
pub const RTM_GET: c_int = 0x4;
pub const RTM_LOSING: c_int = 0x5;
pub const RTM_REDIRECT: c_int = 0x6;
pub const RTM_MISS: c_int = 0x7;
pub const RTM_LOCK: c_int = 0x8;
pub const RTM_OLDADD: c_int = 0x9;
pub const RTM_OLDDEL: c_int = 0xa;
// pub const RTM_RESOLVE: c_int = 0xb;
pub const RTM_ONEWADDR: c_int = 0xc;
pub const RTM_ODELADDR: c_int = 0xd;
pub const RTM_OOIFINFO: c_int = 0xe;
pub const RTM_OIFINFO: c_int = 0xf;
pub const RTM_NEWMADDR: c_int = 0xf;
pub const RTM_IFANNOUNCE: c_int = 0x10;
pub const RTM_IEEE80211: c_int = 0x11;
pub const RTM_SETGATE: c_int = 0x12;

pub const RTM_LLINFO_UPD: c_int = 0x13;

pub const RTM_IFINFO: c_int = 0x14;
pub const RTM_OCHGADDR: c_int = 0x15;
pub const RTM_NEWADDR: c_int = 0x16;
pub const RTM_DELADDR: c_int = 0x17;
pub const RTM_CHGADDR: c_int = 0x18;

// Hardcoded based on the generated values here: https://cs.opensource.google/go/x/net/+/master:route/zsys_netbsd.go

pub(super) const SIZEOF_IF_MSGHDR_NET_BSD7: usize = 0x98;
pub(super) const SIZEOF_IFA_MSGHDR_NET_BSD7: usize = 0x18;
pub(super) const SIZEOF_IF_ANNOUNCEMSGHDR_NET_BSD7: usize = 0x18;

pub(super) const SIZEOF_RT_MSGHDR_NET_BSD7: usize = 0x78;
pub(super) const SIZEOF_RT_METRICS_NET_BSD7: usize = 0x50;

pub(super) const SIZEOF_SOCKADDR_STORAGE: usize = 0x80;
pub(super) const SIZEOF_SOCKADDR_INET: usize = 0x10;
pub(super) const SIZEOF_SOCKADDR_INET6: usize = 0x1c;

pub(super) fn probe_routing_stack() -> RoutingStack {
    let rtm_version = RTM_VERSION;

    let rtm = WireFormat {
        ext_off: 40,
        body_off: SIZEOF_RT_MSGHDR_NET_BSD7,
        typ: MessageType::Route,
    };
    let ifm = WireFormat {
        ext_off: 16,
        body_off: SIZEOF_IF_MSGHDR_NET_BSD7,
        typ: MessageType::Interface,
    };
    let ifam = WireFormat {
        ext_off: SIZEOF_IFA_MSGHDR_NET_BSD7,
        body_off: SIZEOF_IFA_MSGHDR_NET_BSD7,
        typ: MessageType::InterfaceAddr,
    };
    let ifannm = WireFormat {
        ext_off: SIZEOF_IF_ANNOUNCEMSGHDR_NET_BSD7,
        body_off: SIZEOF_IF_ANNOUNCEMSGHDR_NET_BSD7,
        typ: MessageType::InterfaceAnnounce,
    };

    let wire_formats = [
        (RTM_ADD, rtm),
        (RTM_DELETE, rtm),
        (RTM_CHANGE, rtm),
        (RTM_GET, rtm),
        (RTM_LOSING, rtm),
        (RTM_REDIRECT, rtm),
        (RTM_MISS, rtm),
        (RTM_LOCK, rtm),
        (RTM_NEWADDR, ifam),
        (RTM_DELADDR, ifam),
        (RTM_IFANNOUNCE, ifannm),
        (RTM_IFINFO, ifm),
    ]
    .into_iter()
    .collect();

    // NetBSD 6 and above kernels require 64-bit aligned access to routing facilities.
    RoutingStack {
        rtm_version,
        wire_formats,
        kernel_align: 8,
    }
}
