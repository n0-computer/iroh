use anyhow::Result;
use tokio::{io::AsyncReadExt, sync::mpsc, task::JoinHandle};
use tracing::{trace, warn};

#[derive(Debug)]
pub struct Message;

#[derive(Debug)]
pub struct RouteMonitor {
    receiver: mpsc::Receiver<Message>,
    handle: JoinHandle<()>,
}

impl Drop for RouteMonitor {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl RouteMonitor {
    pub async fn new() -> Result<Self> {
        let socket = socket2::Socket::new(libc::AF_ROUTE.into(), socket2::Type::RAW, None)?;
        socket.set_nonblocking(true)?;
        let socket_std: std::os::unix::net::UnixStream = socket.into();
        let mut socket: tokio::net::UnixStream = socket_std.try_into()?;

        let (s, r) = mpsc::channel(16);

        let handle = tokio::task::spawn(async move {
            trace!("AF_ROUTE monitor started");

            // TODO: cleaner shutdown
            let mut buffer = vec![0u8; 2 << 10];
            loop {
                match socket.read(&mut buffer).await {
                    Ok(read) => {
                        trace!("AF_ROUTE: read {} bytes", read);
                        match super::super::interfaces::bsd::parse_rib(
                            libc::NET_RT_DUMP,
                            &buffer[..read],
                        ) {
                            Ok(msgs) => {
                                dbg!(msgs);
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

        Ok(RouteMonitor {
            receiver: r,
            handle,
        })
    }
}
