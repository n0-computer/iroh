// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use core::task::{Context, Poll};
use s2n_quic_core::task::cooldown::Cooldown;
use s2n_quic_platform::{
    features::Gso,
    message::msg::Ext,
    socket::{
        ring,
        task::{rx, tx},
    },
    syscall::{SocketEvents, UnixMessage},
};
use tokio::io;

use crate::magicsock::MagicSock;

pub async fn rx<M: UnixMessage + Unpin + Ext>(
    magicsock: MagicSock,
    producer: ring::Producer<M>,
    cooldown: Cooldown,
) -> io::Result<()> {
    println!("!!!unix");
    let socket = UdpSocket { magic: magicsock };
    let result = rx::Receiver::new(producer, socket, cooldown).await;
    if let Some(err) = result {
        Err(err)
    } else {
        Ok(())
    }
}

pub async fn tx<M: UnixMessage + Unpin + Ext>(
    magicsock: MagicSock,
    consumer: ring::Consumer<M>,
    gso: Gso,
    cooldown: Cooldown,
) -> io::Result<()> {
    let socket = UdpSocket { magic: magicsock };
    let result = tx::Sender::new(consumer, socket, gso, cooldown).await;
    if let Some(err) = result {
        Err(err)
    } else {
        Ok(())
    }
}

pub struct UdpSocket {
    magic: MagicSock,
}

impl<M: UnixMessage + Ext> tx::Socket<M> for UdpSocket {
    type Error = io::Error;

    #[inline]
    fn send(
        &mut self,
        cx: &mut Context,
        entries: &mut [M],
        events: &mut tx::Events,
    ) -> io::Result<()> {
        self.magic.poll_send_s2n_many(cx, entries, events);
        Ok(())
    }
}

impl<M: UnixMessage + Ext> rx::Socket<M> for UdpSocket {
    type Error = io::Error;

    #[inline]
    fn recv(
        &mut self,
        cx: &mut Context,
        entries: &mut [M],
        events: &mut rx::Events,
    ) -> io::Result<()> {
        self.magic.poll_recv_s2n_many(cx, entries, events);
        Ok(())
    }
}
