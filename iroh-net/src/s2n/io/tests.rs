// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use core::{
    convert::TryInto,
    task::{Context, Poll},
};
use s2n_quic_core::{
    endpoint::{self, CloseError},
    event,
    inet::ExplicitCongestionNotification,
    io::{rx, tx},
    path::{mtu, Handle as _},
    time::{Clock, Duration, Timestamp},
};
use std::{collections::BTreeMap, net::ToSocketAddrs};

struct TestEndpoint<const IS_SERVER: bool> {
    handle: PathHandle,
    messages: BTreeMap<u32, Option<Timestamp>>,
    now: Option<Timestamp>,
    subscriber: NoopSubscriber,
}

impl<const IS_SERVER: bool> TestEndpoint<IS_SERVER> {
    fn new(handle: PathHandle) -> Self {
        let messages = if IS_SERVER { 0 } else { 30 };
        let messages = (0..messages).map(|id| (id, None)).collect();
        Self {
            handle,
            messages,
            now: None,
            subscriber: Default::default(),
        }
    }
}

#[derive(Debug, Default)]
struct NoopSubscriber;

impl event::Subscriber for NoopSubscriber {
    type ConnectionContext = ();

    fn create_connection_context(
        &mut self,
        _meta: &event::api::ConnectionMeta,
        _info: &event::api::ConnectionInfo,
    ) -> Self::ConnectionContext {
    }
}

impl<const IS_SERVER: bool> Endpoint for TestEndpoint<IS_SERVER> {
    type PathHandle = PathHandle;
    type Subscriber = NoopSubscriber;

    const ENDPOINT_TYPE: endpoint::Type = if IS_SERVER {
        endpoint::Type::Server
    } else {
        endpoint::Type::Client
    };

    fn transmit<Tx: tx::Queue<Handle = PathHandle>, C: Clock>(
        &mut self,
        queue: &mut Tx,
        clock: &C,
    ) {
        let now = clock.get_time();
        self.now = Some(now);

        for (id, tx_time) in &mut self.messages {
            match tx_time {
                Some(time) if now.saturating_duration_since(*time) < Duration::from_millis(50) => {
                    continue
                }
                _ => {
                    let payload = id.to_be_bytes();
                    let addr = self.handle;
                    let ecn = ExplicitCongestionNotification::Ect0;
                    let msg = (addr, ecn, payload);
                    if queue.push(msg).is_ok() {
                        *tx_time = Some(now);
                    } else {
                        // no more capacity
                        return;
                    }
                }
            }
        }
    }

    fn receive<Rx: rx::Queue<Handle = PathHandle>, C: Clock>(&mut self, queue: &mut Rx, clock: &C) {
        let now = clock.get_time();
        self.now = Some(now);

        queue.for_each(|_header, payload| {
            // we should only be receiving u32 values
            if payload.len() != 4 {
                return;
            }

            let id = (&*payload).try_into().unwrap();
            let id = u32::from_be_bytes(id);

            if IS_SERVER {
                self.messages.insert(id, None);
            } else {
                self.messages.remove(&id);
            }
        });
    }

    fn poll_wakeups<C: Clock>(
        &mut self,
        _cx: &mut Context<'_>,
        clock: &C,
    ) -> Poll<Result<usize, CloseError>> {
        let now = clock.get_time();
        self.now = Some(now);

        if !IS_SERVER && self.messages.is_empty() {
            return Err(CloseError).into();
        }

        Poll::Pending
    }

    fn timeout(&self) -> Option<Timestamp> {
        self.now.map(|now| now + Duration::from_millis(50))
    }

    fn set_mtu_config(&mut self, _mtu_config: mtu::Config) {
        // noop
    }

    fn subscriber(&mut self) -> &mut Self::Subscriber {
        &mut self.subscriber
    }
}

async fn runtime<A: ToSocketAddrs>(
    receive_addr: A,
    send_addr: Option<A>,
) -> io::Result<(super::Io, SocketAddress)> {
    let rx_socket = syscall::bind_udp(receive_addr, false, false)?;
    rx_socket.set_nonblocking(true)?;
    let rx_socket: std::net::UdpSocket = rx_socket.into();
    let rx_addr = rx_socket.local_addr()?;

    let mut io_builder = Io::builder().with_rx_socket(rx_socket)?;

    if let Some(tx_addr) = send_addr {
        let tx_socket = syscall::bind_udp(tx_addr, false, false)?;
        tx_socket.set_nonblocking(true)?;
        let tx_socket: std::net::UdpSocket = tx_socket.into();
        io_builder = io_builder.with_tx_socket(tx_socket)?
    }

    let io = io_builder.build()?;

    let rx_addr = if rx_addr.is_ipv6() {
        ("::1", rx_addr.port())
    } else {
        ("127.0.0.1", rx_addr.port())
    }
    .to_socket_addrs()?
    .next()
    .unwrap();

    Ok((io, rx_addr.into()))
}

/// The tokio IO provider allows the application to configure different sockets for rx
/// and tx. This function will accept optional TX addresses to test this functionality.
async fn test<A: ToSocketAddrs>(
    server_rx_addr: A,
    server_tx_addr: Option<A>,
    client_rx_addr: A,
    client_tx_addr: Option<A>,
) -> io::Result<()> {
    let (server_io, server_addr) = runtime(server_rx_addr, server_tx_addr).await?;
    let (client_io, client_addr) = runtime(client_rx_addr, client_tx_addr).await?;

    let server_endpoint = {
        let mut handle = PathHandle::from_remote_address(client_addr.into());
        handle.set_local_address(server_addr.into());
        TestEndpoint::<true>::new(handle)
    };

    let client_endpoint = {
        let mut handle = PathHandle::from_remote_address(server_addr.into());
        handle.set_local_address(client_addr.into());
        TestEndpoint::<false>::new(handle)
    };

    let (server_task, actual_server_addr) = server_io.start(server_endpoint)?;
    assert_eq!(actual_server_addr, server_addr);

    let (client_task, actual_client_addr) = client_io.start(client_endpoint)?;
    assert_eq!(actual_client_addr, client_addr);

    tokio::time::timeout(core::time::Duration::from_secs(60), client_task).await??;

    server_task.abort();

    Ok(())
}

static IPV4_LOCALHOST: &str = "127.0.0.1:0";
static IPV6_LOCALHOST: &str = "[::1]:0";

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn ipv4_test() -> io::Result<()> {
    test(IPV4_LOCALHOST, None, IPV4_LOCALHOST, None).await
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn ipv4_two_socket_test() -> io::Result<()> {
    test(
        IPV4_LOCALHOST,
        Some(IPV4_LOCALHOST),
        IPV4_LOCALHOST,
        Some(IPV4_LOCALHOST),
    )
    .await
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn ipv6_test() -> io::Result<()> {
    let result = test(IPV6_LOCALHOST, None, IPV6_LOCALHOST, None).await;

    match result {
        Err(err) if err.kind() == io::ErrorKind::AddrNotAvailable => {
            eprintln!("The current environment does not support IPv6; skipping");
            Ok(())
        }
        other => other,
    }
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn ipv6_two_socket_test() -> io::Result<()> {
    let result = test(
        IPV6_LOCALHOST,
        Some(IPV6_LOCALHOST),
        IPV6_LOCALHOST,
        Some(IPV6_LOCALHOST),
    )
    .await;

    match result {
        Err(err) if err.kind() == io::ErrorKind::AddrNotAvailable => {
            eprintln!("The current environment does not support IPv6; skipping");
            Ok(())
        }
        other => other,
    }
}
