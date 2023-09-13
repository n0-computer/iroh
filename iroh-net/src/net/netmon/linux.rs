use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use anyhow::Result;
use futures::StreamExt;
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::{address, constants::*, route, RtnlMessage};
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::new_connection;
use tokio::task::JoinHandle;
use tracing::{info, trace, warn};

use crate::net::ip::is_link_local;

#[derive(Debug)]
pub struct Message;

#[derive(Debug)]
pub struct RouteMonitor {
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
        $msg.nlas.iter().find_map(|nla| match nla {
            $nla(n) => Some(n),
            _ => None,
        })
    };
}

impl RouteMonitor {
    pub async fn new(sender: flume::Sender<Message>) -> Result<Self> {
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
            let mut addr_cache: HashMap<u32, HashSet<Vec<u8>>> = HashMap::new();

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
                        RtnlMessage::NewAddress(msg) => {
                            trace!("NEWADDR: {:?}", msg);
                            let addrs = addr_cache.entry(msg.header.index).or_default();
                            if let Some(addr) = get_nla!(msg, address::Nla::Address) {
                                if addrs.contains(addr) {
                                    // already cached
                                    continue;
                                } else {
                                    addrs.insert(addr.clone());
                                    sender.send_async(Message).await.ok();
                                }
                            }
                        }
                        RtnlMessage::DelAddress(msg) => {
                            trace!("DELADDR: {:?}", msg);
                            let addrs = addr_cache.entry(msg.header.index).or_default();
                            if let Some(addr) = get_nla!(msg, address::Nla::Address) {
                                addrs.remove(addr);
                            }
                            sender.send_async(Message).await.ok();
                        }
                        RtnlMessage::NewRoute(msg) | RtnlMessage::DelRoute(msg) => {
                            trace!("ROUTE:: {:?}", msg);

                            // Ignore the following messages
                            let table = get_nla!(msg, route::Nla::Table)
                                .copied()
                                .unwrap_or_default();
                            if let Some(dst) = get_nla!(msg, route::Nla::Destination) {
                                let dst_addr = match dst.len() {
                                    4 => Some(IpAddr::from(
                                        TryInto::<[u8; 4]>::try_into(&dst[..]).unwrap(),
                                    )),
                                    16 => Some(IpAddr::from(
                                        TryInto::<[u8; 16]>::try_into(&dst[..]).unwrap(),
                                    )),
                                    _ => None,
                                };
                                if let Some(dst_addr) = dst_addr {
                                    if (table == 255 || table == 254)
                                        && (dst_addr.is_multicast() || is_link_local(dst_addr))
                                    {
                                        continue;
                                    }
                                }
                            }
                            sender.send_async(Message).await.ok();
                        }
                        RtnlMessage::NewRule(msg) => {
                            trace!("NEWRULE: {:?}", msg);
                            sender.send_async(Message).await.ok();
                        }
                        RtnlMessage::DelRule(msg) => {
                            trace!("DELRULE: {:?}", msg);
                            sender.send_async(Message).await.ok();
                        }
                        RtnlMessage::NewLink(msg) => {
                            trace!("NEWLINK: {:?}", msg);
                            // ignored atm
                        }
                        RtnlMessage::DelLink(msg) => {
                            trace!("DELLINK: {:?}", msg);
                            // ignored atm
                        }
                        msg => {
                            trace!("unhandeled: {:?}", msg);
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
