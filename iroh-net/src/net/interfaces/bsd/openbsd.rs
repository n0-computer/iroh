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
pub const RTAX_MAX: c_int = 15;
pub const RTM_VERSION: c_int = 5;
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
pub const RTM_RESOLVE: c_int = 0xb;
pub const RTM_NEWADDR: c_int = 0xc;
pub const RTM_DELADDR: c_int = 0xd;
pub const RTM_IFINFO: c_int = 0xe;
pub const RTM_IFANNOUNCE: c_int = 0xf;
pub const RTM_DESYNC: c_int = 0x10;
pub const RTM_INVALIDATE: c_int = 0x11;
pub const RTM_BFD: c_int = 0x12;
pub const RTM_PROPOSAL: c_int = 0x13;
pub const RTM_CHGADDRATTR: c_int = 0x14;
pub const RTM_80211INFO: c_int = 0x15;
pub const RTM_SOURCE: c_int = 0x16;

// socket.h
pub const NET_RT_STATS: c_int = 5;
pub const NET_RT_TABLE: c_int = 5;

pub const SIZEOF_SOCKADDR_STORAGE: usize = 0x80;
pub const SIZEOF_SOCKADDR_INET: usize = 0x10;
pub const SIZEOF_SOCKADDR_INET6: usize = 0x1c;

// Hardcoded based on the generated values here: https://cs.opensource.google/go/x/net/+/master:route/sys_openbsd.go

pub(super) fn probe_routing_stack() -> RoutingStack {
    let rtm_version = RTM_VERSION;

    let rtm = WireFormat {
        ext_off: 0,
        body_off: 0,
        typ: MessageType::Route,
    };
    let ifm = WireFormat {
        ext_off: 0,
        body_off: 0,
        typ: MessageType::Interface,
    };
    let ifam = WireFormat {
        ext_off: 0,
        body_off: 0,
        typ: MessageType::InterfaceAddr,
    };
    let ifannm = WireFormat {
        ext_off: 0,
        body_off: 0,
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
        (RTM_RESOLVE, rtm),
        (RTM_NEWADDR, ifam),
        (RTM_DELADDR, ifam),
        (RTM_IFINFO, ifm),
        (RTM_IFANNOUNCE, ifannm),
        (RTM_DESYNC, ifannm),
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
