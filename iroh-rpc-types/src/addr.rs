use std::{
    fmt::{Debug, Display},
    net::SocketAddr,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll},
};

use anyhow::{anyhow, bail};
use futures::{Sink, Stream};
use serde_with::{DeserializeFromStr, SerializeDisplay};

#[derive(SerializeDisplay, DeserializeFromStr)]
pub enum Addr<Req = (), Resp = ()>
where
    Req: Send + Sync + 'static,
    Resp: Send + Sync + 'static,
{
    Tcp(SocketAddr),
    #[cfg(unix)]
    Uds(std::path::PathBuf),
    Mem(Channel<Req, Resp>),
}

impl<Req, Resp> Clone for Addr<Req, Resp>
where
    Req: Send + Sync + 'static,
    Resp: Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        match self {
            Self::Tcp(addr) => Self::Tcp(addr.clone()),
            #[cfg(unix)]
            Self::Uds(path) => Self::Uds(path.clone()),
            Self::Mem(chan) => Self::Mem(chan.clone()),
        }
    }
}

impl<Req, Resp> PartialEq for Addr<Req, Resp>
where
    Req: Send + Sync + 'static,
    Resp: Send + Sync + 'static,
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Tcp(addr1), Self::Tcp(addr2)) => addr1.eq(addr2),
            #[cfg(unix)]
            (Self::Uds(path1), Self::Uds(path2)) => path1.eq(path2),
            _ => false,
        }
    }
}

impl<Req, Resp> Addr<Req, Resp>
where
    Req: Send + Sync + 'static,
    Resp: Send + Sync + 'static,
{
    pub fn new_mem() -> (Addr<Req, Resp>, Addr<Resp, Req>) {
        let (s, r) = bounded(256);

        (Addr::Mem(r), Addr::Mem(s))
    }
}

impl<Req, Resp> Addr<Req, Resp>
where
    Req: Send + Sync + 'static,
    Resp: Send + Sync + 'static,
{
    pub fn try_as_socket_addr(&self) -> Option<SocketAddr> {
        if let Addr::Tcp(addr) = self {
            return Some(*addr);
        }
        None
    }
}

impl<Req, Resp> Display for Addr<Req, Resp>
where
    Req: Send + Sync + 'static,
    Resp: Send + Sync + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Addr::Tcp(addr) => write!(f, "tcp://{}", addr),
            #[cfg(unix)]
            Addr::Uds(path) => write!(f, "uds://{}", path.display()),
            Addr::Mem(_) => write!(f, "mem"),
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }
}

impl<Req, Resp> Debug for Addr<Req, Resp>
where
    Req: Send + Sync + 'static,
    Resp: Send + Sync + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl<Req, Resp> FromStr for Addr<Req, Resp>
where
    Req: Send + Sync + 'static,
    Resp: Send + Sync + 'static,
{
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "mem" {
            bail!("memory addresses can not be serialized or deserialized");
        }

        let mut parts = s.split("://");
        if let Some(prefix) = parts.next() {
            if prefix == "tcp" {
                if let Some(part) = parts.next() {
                    if let Ok(addr) = part.parse::<SocketAddr>() {
                        return Ok(Addr::Tcp(addr));
                    }
                }
            }
            #[cfg(unix)]
            if prefix == "uds" {
                if let Some(part) = parts.next() {
                    if let Ok(path) = part.parse::<std::path::PathBuf>() {
                        return Ok(Addr::Uds(path));
                    }
                }
            }
        }

        Err(anyhow!("invalid addr: {}", s))
    }
}

/// Returns two channel peers with buffer equal to `capacity`. Each [`Stream`] yields items sent
/// through the other's [`Sink`].
pub fn bounded<SinkItem, Item>(
    capacity: usize,
) -> (Channel<SinkItem, Item>, Channel<Item, SinkItem>)
where
    Item: Send + Sync + 'static,
    SinkItem: Send + Sync + 'static,
{
    let (tx1, rx2) = flume::bounded(capacity);
    let (tx2, rx1) = flume::bounded(capacity);
    (
        Channel {
            tx: tx1.into_sink(),
            rx: rx1.into_stream(),
        },
        Channel {
            tx: tx2.into_sink(),
            rx: rx2.into_stream(),
        },
    )
}

/// A bi-directional channel backed by a [`Sender`](flume::Sender) and [`Receiver`](flume::Receiver).
pub struct Channel<Item, SinkItem>
where
    Item: Send + Sync + 'static,
    SinkItem: Send + Sync + 'static,
{
    rx: flume::r#async::RecvStream<'static, Item>,
    tx: flume::r#async::SendSink<'static, SinkItem>,
}

impl<Item, SinkItem> Clone for Channel<Item, SinkItem>
where
    Item: Send + Sync + 'static,
    SinkItem: Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            rx: self.rx.clone(),
            tx: self.tx.clone(),
        }
    }
}

impl<Item, SinkItem> Stream for Channel<Item, SinkItem>
where
    Item: Send + Sync + 'static,
    SinkItem: Send + Sync + 'static,
{
    type Item = Result<Item, ChannelError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Item, ChannelError>>> {
        Pin::new(&mut self.rx)
            .poll_next(cx)
            .map(|option| option.map(Ok))
    }
}

/// Errors that occur in the sending or receiving of messages over a channel.
#[derive(thiserror::Error, Debug)]
pub enum ChannelError {
    /// An error occurred sending over the channel.
    #[error("an error occurred sending over the channel")]
    Send(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl<Item, SinkItem> Sink<SinkItem> for Channel<Item, SinkItem>
where
    Item: Send + Sync + 'static,
    SinkItem: Send + Sync + 'static,
{
    type Error = ChannelError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.tx)
            .poll_ready(cx)
            .map_err(|e| ChannelError::Send(Box::new(e)))
    }

    fn start_send(mut self: Pin<&mut Self>, item: SinkItem) -> Result<(), Self::Error> {
        Pin::new(&mut self.tx)
            .start_send(item)
            .map_err(|e| ChannelError::Send(Box::new(e)))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.tx)
            .poll_flush(cx)
            .map_err(|e| ChannelError::Send(Box::new(e)))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.tx)
            .poll_close(cx)
            .map_err(|e| ChannelError::Send(Box::new(e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{prelude::*, stream};
    use std::io;
    use tarpc::server::incoming::Incoming;

    #[test]
    fn test_addr_roundtrip_tcp() {
        let socket: SocketAddr = "198.168.2.1:1234".parse().unwrap();
        let addr = Addr::Tcp(socket);

        assert_eq!(addr.to_string().parse::<Addr>().unwrap(), addr);
        assert_eq!(addr.to_string(), "tcp://198.168.2.1:1234");
    }

    #[cfg(unix)]
    #[test]
    fn test_addr_roundtrip_uds() {
        let path: std::path::PathBuf = "/foo/bar".parse().unwrap();
        let addr = Addr::Uds(path);

        assert_eq!(addr.to_string().parse::<Addr>().unwrap(), addr);
        assert_eq!(addr.to_string(), "uds:///foo/bar");
    }

    #[test]
    fn channel_ensure_is_transport() {
        fn is_transport<SinkItem, Item, T: tarpc::Transport<SinkItem, Item>>() {}
        is_transport::<(), (), Channel<(), ()>>();
    }

    #[tokio::test]
    async fn channel_integration() -> anyhow::Result<()> {
        let (client_channel, server_channel) = bounded(1024);
        tokio::spawn(
            stream::once(future::ready(server_channel))
                .map(tarpc::server::BaseChannel::with_defaults)
                .execute(|_ctx, request: String| {
                    future::ready(request.parse::<u64>().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("{request:?} is not an int"),
                        )
                    }))
                }),
        );

        for _ in 0..5 {
            // ensure cloning works as expected, to create multiple clients
            let client =
                tarpc::client::new(tarpc::client::Config::default(), client_channel.clone())
                    .spawn();

            let response1 = client
                .call(tarpc::context::current(), "", "123".into())
                .await?;
            let response2 = client
                .call(tarpc::context::current(), "", "abc".into())
                .await?;

            println!("response1: {:?}, response2: {:?}", response1, response2);

            assert!(matches!(response1, Ok(123)));
            assert!(matches!(response2, Err(ref e) if e.kind() == io::ErrorKind::InvalidInput));
        }
        Ok(())
    }
}
