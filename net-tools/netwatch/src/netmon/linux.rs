use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use anyhow::Result;
use futures_lite::StreamExt;
use libc::{
    RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV4_RULE, RTNLGRP_IPV6_IFADDR,
    RTNLGRP_IPV6_ROUTE, RTNLGRP_IPV6_RULE,
};
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::{address, route, RouteNetlinkMessage};
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::new_connection;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{info, trace, warn};

use super::actor::NetworkMessage;
use crate::ip::is_link_local;

#[derive(Debug)]
pub(super) struct RouteMonitor {
    conn_handle: JoinHandle<()>,
    handle: JoinHandle<()>,
}

impl Drop for RouteMonitor {
    fn drop(&mut self) {
        self.handle.abort();
        self.conn_handle.abort();
    }
}

const fn nl_mgrp(group: u32) -> u32 {
    if group > 31 {
        panic!("use netlink_sys::Socket::add_membership() for this group");
    }
    if group == 0 {
        0
    } else {
        1 << (group - 1)
    }
}
macro_rules! get_nla {
    ($msg:expr, $nla:path) => {
        $msg.attributes.iter().find_map(|nla| match nla {
            $nla(n) => Some(n),
            _ => None,
        })
    };
}

impl RouteMonitor {
    pub(super) fn new(sender: mpsc::Sender<NetworkMessage>) -> Result<Self> {
        let (mut conn, mut _handle, mut messages) = new_connection()?;

        // Specify flags to listen on.
        let groups = nl_mgrp(RTNLGRP_IPV4_IFADDR)
            | nl_mgrp(RTNLGRP_IPV6_IFADDR)
            | nl_mgrp(RTNLGRP_IPV4_ROUTE)
            | nl_mgrp(RTNLGRP_IPV6_ROUTE)
            | nl_mgrp(RTNLGRP_IPV4_RULE)
            | nl_mgrp(RTNLGRP_IPV6_RULE);

        let addr = SocketAddr::new(0, groups);
        conn.socket_mut().socket_mut().bind(&addr)?;

        let conn_handle = tokio::task::spawn(conn);

        let handle = tokio::task::spawn(async move {
            // let mut addr_cache: HashMap<u32, HashSet<Vec<u8>>> = HashMap::new();
            let mut addr_cache: HashMap<u32, HashSet<IpAddr>> = HashMap::new();

            while let Some((message, _)) = messages.next().await {
                match message.payload {
                    NetlinkPayload::Error(err) => {
                        warn!("error reading netlink payload: {:?}", err);
                    }
                    NetlinkPayload::Done(_) => {
                        info!("done received, exiting");
                        break;
                    }
                    NetlinkPayload::InnerMessage(msg) => match msg {
                        RouteNetlinkMessage::NewAddress(msg) => {
                            trace!("NEWADDR: {:?}", msg);
                            let addrs = addr_cache.entry(msg.header.index).or_default();
                            if let Some(addr) = get_nla!(msg, address::AddressAttribute::Address) {
                                if addrs.contains(addr) {
                                    // already cached
                                    continue;
                                } else {
                                    addrs.insert(*addr);
                                    sender.send(NetworkMessage::Change).await.ok();
                                }
                            }
                        }
                        RouteNetlinkMessage::DelAddress(msg) => {
                            trace!("DELADDR: {:?}", msg);
                            let addrs = addr_cache.entry(msg.header.index).or_default();
                            if let Some(addr) = get_nla!(msg, address::AddressAttribute::Address) {
                                addrs.remove(addr);
                            }
                            sender.send(NetworkMessage::Change).await.ok();
                        }
                        RouteNetlinkMessage::NewRoute(msg) | RouteNetlinkMessage::DelRoute(msg) => {
                            trace!("ROUTE:: {:?}", msg);

                            // Ignore the following messages
                            let table = get_nla!(msg, route::RouteAttribute::Table)
                                .copied()
                                .unwrap_or_default();
                            if let Some(dst) = get_nla!(msg, route::RouteAttribute::Destination) {
                                match dst {
                                    route::RouteAddress::Inet(addr) => {
                                        if (table == 255 || table == 254)
                                            && (addr.is_multicast()
                                                || is_link_local(IpAddr::V4(*addr)))
                                        {
                                            continue;
                                        }
                                    }
                                    route::RouteAddress::Inet6(addr) => {
                                        if (table == 255 || table == 254)
                                            && (addr.is_multicast()
                                                || is_link_local(IpAddr::V6(*addr)))
                                        {
                                            continue;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            sender.send(NetworkMessage::Change).await.ok();
                        }
                        RouteNetlinkMessage::NewRule(msg) => {
                            trace!("NEWRULE: {:?}", msg);
                            sender.send(NetworkMessage::Change).await.ok();
                        }
                        RouteNetlinkMessage::DelRule(msg) => {
                            trace!("DELRULE: {:?}", msg);
                            sender.send(NetworkMessage::Change).await.ok();
                        }
                        RouteNetlinkMessage::NewLink(msg) => {
                            trace!("NEWLINK: {:?}", msg);
                            // ignored atm
                        }
                        RouteNetlinkMessage::DelLink(msg) => {
                            trace!("DELLINK: {:?}", msg);
                            // ignored atm
                        }
                        msg => {
                            trace!("unhandled: {:?}", msg);
                        }
                    },
                    _ => {
                        // ignore other types
                    }
                }
            }
        });

        Ok(RouteMonitor {
            handle,
            conn_handle,
        })
    }
}

pub(super) fn is_interesting_interface(_name: &str) -> bool {
    true
}
