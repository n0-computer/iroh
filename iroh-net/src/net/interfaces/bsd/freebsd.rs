use super::{MessageType, RoutingStack, WireFormat};

use libc::c_int;

// Missing constants from libc.
// https://github.com/rust-lang/libc/issues/3711

const LOCAL_PEERCRED: c_int = 1;

// net/route.h
const RTF_GATEWAY: c_int = 0x2;
const RTAX_DST: c_int = 0;
const RTAX_GATEWAY: c_int = 1;
const RTAX_NETMASK: c_int = 2;
const RTAX_IFP: c_int = 4;
const RTAX_BRD: c_int = 7;
const RTAX_MAX: c_int = 8;
const RTM_VERSION: c_int = 5;
const RTA_DST: c_int = 0x1;
const RTA_GATEWAY: c_int = 0x2;
const RTA_NETMASK: c_int = 0x4;
const RTA_GENMASK: c_int = 0x8;
const RTA_IFP: c_int = 0x10;
const RTA_IFA: c_int = 0x20;
const RTA_AUTHOR: c_int = 0x40;
const RTA_BRD: c_int = 0x80;

// Message types
const RTM_ADD: c_int = 0x1;
const RTM_DELETE: c_int = 0x2;
const RTM_CHANGE: c_int = 0x3;
const RTM_GET: c_int = 0x4;
const RTM_LOSING: c_int = 0x5;
const RTM_REDIRECT: c_int = 0x6;
const RTM_MISS: c_int = 0x7;
const RTM_LOCK: c_int = 0x8;
const RTM_OLDADD: c_int = 0x9;
const RTM_OLDDEL: c_int = 0xa;
const RTM_RESOLVE: c_int = 0xb;
const RTM_NEWADDR: c_int = 0xc;
const RTM_DELADDR: c_int = 0xd;
const RTM_IFINFO: c_int = 0xe;
const RTM_NEWMADDR: c_int = 0xf;
const RTM_DELMADDR: c_int = 0x10;
const RTM_IFANNOUNCE: c_int = 0x11;
const RTM_IEEE80211: c_int = 0x12;

const SHUT_RD: c_int = 0;
const SHUT_WR: c_int = 1;
const SHUT_RDWR: c_int = 2;

// Hardcoded based on the generated values here: https://cs.opensource.google/go/x/net/+/master:route/zsys_freebsd_amd64.go
#[cfg(target_arch = "x86_64")]
use self::amd64::*;
#[cfg(target_arch = "x86_64")]
mod amd64 {
    pub(super) const SIZEOF_IF_MSGHDRL_FREE_BSD10: usize = 0xb0;
    pub(super) const SIZEOF_IFA_MSGHDR_FREE_BSD10: usize = 0x14;
    pub(super) const SIZEOF_IFA_MSGHDRL_FREE_BSD10: usize = 0xb0;
    pub(super) const SIZEOF_IFMA_MSGHDR_FREE_BSD10: usize = 0x10;
    pub(super) const SIZEOF_IF_ANNOUNCEMSGHDR_FREE_BSD10: usize = 0x18;

    pub(super) const SIZEOF_RT_MSGHDR_FREE_BSD10: usize = 0x98;
    pub(super) const SIZEOF_RT_METRICS_FREE_BSD10: usize = 0x70;

    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD7: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD8: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD9: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD10: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD11: usize = 0xa8;

    pub(super) const SIZEOF_IF_DATA_FREE_BSD7: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD8: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD9: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD10: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD11: usize = 0x98;

    pub(super) const SIZEOF_IF_MSGHDRL_FREE_BSD10_EMU: usize = 0xb0;
    pub(super) const SIZEOF_IFA_MSGHDR_FREE_BSD10_EMU: usize = 0x14;
    pub(super) const SIZEOF_IFA_MSGHDRL_FREE_BSD10_EMU: usize = 0xb0;
    pub(super) const SIZEOF_IFMA_MSGHDR_FREE_BSD10_EMU: usize = 0x10;
    pub(super) const SIZEOF_IF_ANNOUNCEMSGHDR_FREE_BSD10_EMU: usize = 0x18;

    pub(super) const SIZEOF_RT_MSGHDR_FREE_BSD10_EMU: usize = 0x98;
    pub(super) const SIZEOF_RT_METRICS_FREE_BSD10_EMU: usize = 0x70;

    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD7_EMU: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD8_EMU: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD9_EMU: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD10_EMU: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD11_EMU: usize = 0xa8;

    pub(super) const SIZEOF_IF_DATA_FREE_BSD7_EMU: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD8_EMU: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD9_EMU: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD10_EMU: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD11_EMU: usize = 0x98;

    pub(super) const SIZEOF_SOCKADDR_STORAGE: usize = 0x80;
    pub(super) const SIZEOF_SOCKADDR_INET: usize = 0x10;
    pub(super) const SIZEOF_SOCKADDR_INET6: usize = 0x1c;
}

// Hardcoded based on the generated values here: https://cs.opensource.google/go/x/net/+/master:route/zsys_freebsd_386.go
#[cfg(target_arch = "x86")]
use self::i686::*;
#[cfg(target_arch = "x86")]
mod i686 {
    pub(super) const SIZEOF_IF_MSGHDRL_FREE_BSD10: usize = 0x68;
    pub(super) const SIZEOF_IFA_MSGHDR_FREE_BSD10: usize = 0x14;
    pub(super) const SIZEOF_IFA_MSGHDRL_FREE_BSD10: usize = 0x6c;
    pub(super) const SIZEOF_IFMA_MSGHDR_FREE_BSD10: usize = 0x10;
    pub(super) const SIZEOF_IF_ANNOUNCEMSGHDR_FREE_BSD10: usize = 0x18;

    pub(super) const SIZEOF_RT_MSGHDR_FREE_BSD10: usize = 0x5c;
    pub(super) const SIZEOF_RT_METRICS_FREE_BSD10: usize = 0x38;

    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD7: usize = 0x60;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD8: usize = 0x60;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD9: usize = 0x60;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD10: usize = 0x64;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD11: usize = 0xa8;

    pub(super) const SIZEOF_IF_DATA_FREE_BSD7: usize = 0x50;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD8: usize = 0x50;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD9: usize = 0x50;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD10: usize = 0x54;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD11: usize = 0x98;

    // MODIFIED BY HAND FOR 386 EMULATION ON AMD64
    // 386 EMULATION USES THE UNDERLYING RAW DATA LAYOUT

    pub(super) const SIZEOF_IF_MSGHDRL_FREE_BSD10_EMU: usize = 0xb0;
    pub(super) const SIZEOF_IFA_MSGHDR_FREE_BSD10_EMU: usize = 0x14;
    pub(super) const SIZEOF_IFA_MSGHDRL_FREE_BSD10_EMU: usize = 0xb0;
    pub(super) const SIZEOF_IFMA_MSGHDR_FREE_BSD10_EMU: usize = 0x10;
    pub(super) const SIZEOF_IF_ANNOUNCEMSGHDR_FREE_BSD10_EMU: usize = 0x18;

    pub(super) const SIZEOF_RT_MSGHDR_FREE_BSD10_EMU: usize = 0x98;
    pub(super) const SIZEOF_RT_METRICS_FREE_BSD10_EMU: usize = 0x70;

    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD7_EMU: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD8_EMU: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD9_EMU: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD10_EMU: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD11_EMU: usize = 0xa8;

    pub(super) const SIZEOF_IF_DATA_FREE_BSD7_EMU: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD8_EMU: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD9_EMU: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD10_EMU: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD11_EMU: usize = 0x98;

    pub(super) const SIZEOF_SOCKADDR_STORAGE: usize = 0x80;
    pub(super) const SIZEOF_SOCKADDR_INET: usize = 0x10;
    pub(super) const SIZEOF_SOCKADDR_INET6: usize = 0x1c;
}

// Hardcoded based on the generated values here: https://cs.opensource.google/go/x/net/+/master:route/zsys_freebsd_arm.go
#[cfg(target_arch = "arm")]
use self::arm::*;
#[cfg(target_arch = "arm")]
mod arm {
    pub(super) const SIZEOF_IF_MSGHDRL_FREE_BSD10: usize = 0x68;
    pub(super) const SIZEOF_IFA_MSGHDR_FREE_BSD10: usize = 0x14;
    pub(super) const SIZEOF_IFA_MSGHDRL_FREE_BSD10: usize = 0x6c;
    pub(super) const SIZEOF_IFMA_MSGHDR_FREE_BSD10: usize = 0x10;
    pub(super) const SIZEOF_IF_ANNOUNCEMSGHDR_FREE_BSD10: usize = 0x18;

    pub(super) const SIZEOF_RT_MSGHDR_FREE_BSD10: usize = 0x5c;
    pub(super) const SIZEOF_RT_METRICS_FREE_BSD10: usize = 0x38;

    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD7: usize = 0x70;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD8: usize = 0x70;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD9: usize = 0x70;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD10: usize = 0x70;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD11: usize = 0xa8;

    pub(super) const SIZEOF_IF_DATA_FREE_BSD7: usize = 0x60;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD8: usize = 0x60;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD9: usize = 0x60;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD10: usize = 0x60;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD11: usize = 0x98;

    pub(super) const SIZEOF_IF_MSGHDRL_FREE_BSD10_EMU: usize = 0x68;
    pub(super) const SIZEOF_IFA_MSGHDR_FREE_BSD10_EMU: usize = 0x14;
    pub(super) const SIZEOF_IFA_MSGHDRL_FREE_BSD10_EMU: usize = 0x6c;
    pub(super) const SIZEOF_IFMA_MSGHDR_FREE_BSD10_EMU: usize = 0x10;
    pub(super) const SIZEOF_IF_ANNOUNCEMSGHDR_FREE_BSD10_EMU: usize = 0x18;

    pub(super) const SIZEOF_RT_MSGHDR_FREE_BSD10_EMU: usize = 0x5c;
    pub(super) const SIZEOF_RT_METRICS_FREE_BSD10_EMU: usize = 0x38;

    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD7_EMU: usize = 0x70;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD8_EMU: usize = 0x70;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD9_EMU: usize = 0x70;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD10_EMU: usize = 0x70;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD11_EMU: usize = 0xa8;

    pub(super) const SIZEOF_IF_DATA_FREE_BSD7_EMU: usize = 0x60;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD8_EMU: usize = 0x60;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD9_EMU: usize = 0x60;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD10_EMU: usize = 0x60;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD11_EMU: usize = 0x98;

    pub(super) const SIZEOF_SOCKADDR_STORAGE: usize = 0x80;
    pub(super) const SIZEOF_SOCKADDR_INET: usize = 0x10;
    pub(super) const SIZEOF_SOCKADDR_INET6: usize = 0x1c;
}

// Hardcoded based on the generated values here: https://cs.opensource.google/go/x/net/+/master:route/zsys_freebsd_arm.go
#[cfg(target_arch = "aarch64")]
use self::arm64::*;
#[cfg(target_arch = "aarch64")]
mod arm64 {
    pub(super) const SIZEOF_IF_MSGHDRL_FREE_BSD10: usize = 0xb0;
    pub(super) const SIZEOF_IFA_MSGHDR_FREE_BSD10: usize = 0x14;
    pub(super) const SIZEOF_IFA_MSGHDRL_FREE_BSD10: usize = 0xb0;
    pub(super) const SIZEOF_IFMA_MSGHDR_FREE_BSD10: usize = 0x10;
    pub(super) const SIZEOF_IF_ANNOUNCEMSGHDR_FREE_BSD10: usize = 0x18;

    pub(super) const SIZEOF_RT_MSGHDR_FREE_BSD10: usize = 0x98;
    pub(super) const SIZEOF_RT_METRICS_FREE_BSD10: usize = 0x70;

    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD7: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD8: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD9: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD10: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD11: usize = 0xa8;

    pub(super) const SIZEOF_IF_DATA_FREE_BSD7: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD8: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD9: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD10: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD11: usize = 0x98;

    pub(super) const SIZEOF_IF_MSGHDRL_FREE_BSD10_EMU: usize = 0xb0;
    pub(super) const SIZEOF_IFA_MSGHDR_FREE_BSD10_EMU: usize = 0x14;
    pub(super) const SIZEOF_IFA_MSGHDRL_FREE_BSD10_EMU: usize = 0xb0;
    pub(super) const SIZEOF_IFMA_MSGHDR_FREE_BSD10_EMU: usize = 0x10;
    pub(super) const SIZEOF_IF_ANNOUNCEMSGHDR_FREE_BSD10_EMU: usize = 0x18;

    pub(super) const SIZEOF_RT_MSGHDR_FREE_BSD10_EMU: usize = 0x98;
    pub(super) const SIZEOF_RT_METRICS_FREE_BSD10_EMU: usize = 0x70;

    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD7_EMU: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD8_EMU: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD9_EMU: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD10_EMU: usize = 0xa8;
    pub(super) const SIZEOF_IF_MSGHDR_FREE_BSD11_EMU: usize = 0xa8;

    pub(super) const SIZEOF_IF_DATA_FREE_BSD7_EMU: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD8_EMU: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD9_EMU: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD10_EMU: usize = 0x98;
    pub(super) const SIZEOF_IF_DATA_FREE_BSD11_EMU: usize = 0x98;

    pub(super) const SIZEOF_SOCKADDR_STORAGE: usize = 0x80;
    pub(super) const SIZEOF_SOCKADDR_INET: usize = 0x10;
    pub(super) const SIZEOF_SOCKADDR_INET6: usize = 0x1c;
}

/// 386 emulation on amd64
fn detect_compat_freebsd32() -> bool {
    // TODO: implement detection when someone actually needs it
    false
}

pub(super) fn probe_routing_stack() -> RoutingStack {
    let rtm_version = RTM_VERSION;

    // Currently only BSD11 support is implemented.
    // At the time of this writing rust supports 10 and 11, if this is a problem
    // please file an issue.

    let (rtm, ifm, ifam, ifmam, ifanm) = if detect_compat_freebsd32() {
        unimplemented!()
    } else {
        let rtm = WireFormat {
            ext_off: SIZEOF_RT_MSGHDR_FREE_BSD10 - SIZEOF_RT_METRICS_FREE_BSD10,
            body_off: SIZEOF_RT_MSGHDR_FREE_BSD10,
            typ: MessageType::Route,
        };
        let ifm = WireFormat {
            ext_off: 16,
            body_off: SIZEOF_IF_MSGHDR_FREE_BSD11,
            typ: MessageType::Interface,
        };
        let ifam = WireFormat {
            ext_off: SIZEOF_IFA_MSGHDR_FREE_BSD10,
            body_off: SIZEOF_IFA_MSGHDR_FREE_BSD10,
            typ: MessageType::InterfaceAddr,
        };
        let ifmam = WireFormat {
            ext_off: SIZEOF_IFMA_MSGHDR_FREE_BSD10,
            body_off: SIZEOF_IFMA_MSGHDR_FREE_BSD10,
            typ: MessageType::InterfaceMulticastAddr,
        };
        let ifannm = WireFormat {
            ext_off: SIZEOF_IF_ANNOUNCEMSGHDR_FREE_BSD10,
            body_off: SIZEOF_IF_ANNOUNCEMSGHDR_FREE_BSD10,
            typ: MessageType::InterfaceAnnounce,
        };
        (rtm, ifm, ifam, ifmam, ifanm)
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
        (RTM_RESOLVE, rtm),
        (RTM_NEWADDR, ifam),
        (RTM_DELADDR, ifam),
        (RTM_IFINFO, ifm),
        (RTM_NEWMADDR, ifmam),
        (RTM_DELMADDR, ifmam),
        (RTM_IFANNOUNCE, ifannm),
        (RTM_IEEE80211, ifannm),
    ]
    .into_iter()
    .collect();
    RoutingStack {
        rtm_version,
        wire_formats,
        kernel_align: 4,
    }
}
