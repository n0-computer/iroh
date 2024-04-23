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
        // TODO: don't send individually

        for entry in entries {
            let target = entry.remote_address().expect("missing addr").into();
            let payload = entry.payload_mut();
            match self.magic.poll_send_s2n(cx, payload, target) {
                Poll::Ready(Ok(_)) => {
                    if events.on_complete(1).is_break() {
                        return Ok(());
                    }
                }
                Poll::Ready(Err(err)) => {
                    if events.on_error(err).is_break() {
                        return Ok(());
                    }
                }
                Poll::Pending => {
                    events.blocked();
                    break;
                }
            }
        }

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
        let entries_len = entries.len();
        tracing::info!("trying to recv {} entries", entries_len);
        let mut i = 0;
        while i < entries_len {
            let payload = entries[i].payload_mut();
            let mut buf = io::ReadBuf::new(payload);
            match self.magic.poll_recv_s2n(cx, &mut buf) {
                Poll::Ready(Ok(Some(addr))) => {
                    unsafe {
                        let len = buf.filled().len();
                        entries[i].set_payload_len(len);
                    }

                    entries[i].set_remote_address(&(addr.into()));

                    i += 1;
                    if events.on_complete(1).is_break() {
                        return Ok(());
                    }
                }
                Poll::Ready(Ok(None)) => {
                    // no packet for, us lets try again
                    // (not increasing i)
                }
                Poll::Ready(Err(err)) => {
                    i += 1;
                    if events.on_error(err).is_break() {
                        return Ok(());
                    }
                }
                Poll::Pending => {
                    events.blocked();
                    break;
                }
            }
        }

        Ok(())
    }
}
