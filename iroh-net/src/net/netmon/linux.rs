use std::collections::{HashMap, HashSet};

use anyhow::Result;
use futures::StreamExt;
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::{address::Nla, constants::*, RtnlMessage};
use netlink_sys::{AsyncSocket, SocketAddr};
use rtnetlink::new_connection;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{info, warn};

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

impl RouteMonitor {
    pub async fn new(sender: mpsc::Sender<Message>) -> Result<Self> {
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
                            info!("NEWADDR: {:?}", msg);
                            let addrs = addr_cache.entry(msg.header.index).or_default();
                            if let Some(addr) = get_addr_from_nlas(&msg.nlas) {
                                if addrs.contains(addr) {
                                    // already cached
                                    continue;
                                } else {
                                    addrs.insert(addr.clone());
                                }
                            }
                        }
                        RtnlMessage::DelAddress(msg) => {
                            info!("DELADDR: {:?}", msg);
                            let addrs = addr_cache.entry(msg.header.index).or_default();
                            if let Some(addr) = get_addr_from_nlas(&msg.nlas) {
                                addrs.remove(addr);
                            }
                        }
                        RtnlMessage::NewRoute(msg) => {
                            info!("NEWROUTE:: {:?}", msg);
                        }
                        RtnlMessage::DelRoute(msg) => {
                            info!("DELROUTE: {:?}", msg);
                        }
                        _ => {
                            info!("unexpected: {:?}", msg);
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

fn get_addr_from_nlas(nlas: &[Nla]) -> Option<&Vec<u8>> {
    nlas.iter()
        .filter_map(|a| match a {
            Nla::Address(addr) => Some(addr),
            _ => None,
        })
        .next()
}

pub(super) fn is_interesting_interface(name: &str) -> bool {
    todo!()
}
