use anyhow::Result;
use tokio::{io::AsyncReadExt, sync::mpsc, task::JoinHandle};
use tracing::{trace, warn};

use crate::net::{interfaces::bsd::WireMessage, ip::is_link_local};

#[derive(Debug)]
pub struct Message;

#[derive(Debug)]
pub struct RouteMonitor {
    handle: JoinHandle<()>,
}

impl Drop for RouteMonitor {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl RouteMonitor {
    pub async fn new(sender: mpsc::Sender<Message>) -> Result<Self> {
        let socket = socket2::Socket::new(libc::AF_ROUTE.into(), socket2::Type::RAW, None)?;
        socket.set_nonblocking(true)?;
        let socket_std: std::os::unix::net::UnixStream = socket.into();
        let mut socket: tokio::net::UnixStream = socket_std.try_into()?;

        let handle = tokio::task::spawn(async move {
            trace!("AF_ROUTE monitor started");

            // TODO: cleaner shutdown
            let mut buffer = vec![0u8; 2048];
            loop {
                match socket.read(&mut buffer).await {
                    Ok(read) => {
                        trace!("AF_ROUTE: read {} bytes", read);
                        match super::super::interfaces::bsd::parse_rib(
                            libc::NET_RT_DUMP,
                            &buffer[..read],
                        ) {
                            Ok(msgs) => {
                                if contains_interesting_message(&msgs) {
                                    sender.send(Message).await.ok();
                                }
                            }
                            Err(err) => {
                                warn!("AF_ROUTE: failed to parse rib: {:?}", err);
                            }
                        }
                    }
                    Err(err) => {
                        warn!("AF_ROUTE: error reading: {:?}", err);
                    }
                }
            }
        });

        Ok(RouteMonitor { handle })
    }
}

fn contains_interesting_message(msgs: &[WireMessage]) -> bool {
    msgs.iter().any(is_interesting_message)
}

fn is_interesting_message(msg: &WireMessage) -> bool {
    match msg {
        WireMessage::InterfaceMulticastAddr(_) => true,
        WireMessage::Interface(_) => false,
        WireMessage::InterfaceAddr(msg) => {
            if let Some(addr) = msg.addrs.get(libc::RTAX_IFP as usize) {
                if !is_interesting_interface(addr.name()) {
                    return false;
                }
            }
            true
        }
        WireMessage::Route(msg) => {
            // Ignore local unicast
            if let Some(addr) = msg.addrs.get(libc::RTAX_DST as usize) {
                if let Some(ip) = addr.ip() {
                    if is_link_local(ip) {
                        return false;
                    }
                }
            }

            true
        }
    }
}

fn is_interesting_interface(name: Option<&str>) -> bool {
    match name {
        Some(name) => {
            let base_name = name.trim_end_matches("0123456789");
            if base_name == "llw" || base_name == "awdl" || base_name == "ipsec" {
                return false;
            }

            true
        }
        None => true,
    }
}
