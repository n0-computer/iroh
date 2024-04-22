// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use core::task::{Context, Poll};
use s2n_quic_core::path;
use s2n_quic_core::inet::SocketAddress;
use s2n_quic_core::task::cooldown::Cooldown;
use s2n_quic_platform::{
    features::Gso,
    message::{Message as MessageTrait},
    socket::{
        ring, task,
        task::{rx, tx},
    },
    syscall::SocketEvents,
};
use tokio::io;

#[derive(Copy, Clone)]
pub struct Message {}

impl Message {
    #[inline]
    pub(crate) fn remote_address(&self) -> &SocketAddress {
        todo!()
    }

    #[inline]
    pub(crate) fn set_remote_address(&mut self, remote_address: &SocketAddress) {
        todo!()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Handle {

}

impl Handle {
    pub(crate) fn set_local_address(&mut self, addr: SocketAddress) {
        todo!()
    }
}

impl path::Handle for Handle {
    fn from_remote_address(remote_addr: path::RemoteAddress) -> Self {
        todo!()
    }

    fn remote_address(&self) -> path::RemoteAddress {
        todo!()
    }

    fn set_remote_port(&mut self, port: u16) {
        todo!()
    }

    fn local_address(&self) -> path::LocalAddress {
        todo!()
    }

    fn eq(&self, other: &Self) -> bool {
        todo!()
    }

    fn strict_eq(&self, other: &Self) -> bool {
        todo!()
    }

    fn maybe_update(&mut self, other: &Self) {
        todo!()
    }
}

impl MessageTrait for Message {
    type Handle = Handle;

    const SUPPORTS_GSO: bool = false;
    const SUPPORTS_ECN: bool = false;
    const SUPPORTS_FLOW_LABELS: bool = false;

    #[inline]
    fn alloc(entries: u32, payload_len: u32, offset: usize) -> s2n_quic_platform::message::Storage {
        todo!()
    }

    #[inline]
    fn payload_len(&self) -> usize {
        todo!()
    }

    #[inline]
    unsafe fn set_payload_len(&mut self, len: usize) {
        todo!()
    }

    #[inline]
    unsafe fn reset(&mut self, mtu: usize) {
        self.set_payload_len(mtu)
    }

    #[inline]
    fn payload_ptr_mut(&mut self) -> *mut u8 {
        todo!()
    }

    #[inline]
    fn validate_replication(source: &Self, dest: &Self) {
        todo!()
    }

    #[inline]
    fn rx_read(
        &mut self,
        local_address: &path::LocalAddress,
    ) -> Option<s2n_quic_platform::message::RxMessage<Self::Handle>> {
        todo!()
    }

    #[inline]
    fn tx_write<M: s2n_quic_core::io::tx::Message<Handle = Self::Handle>>(
        &mut self,
        mut message: M,
    ) -> Result<usize, s2n_quic_core::io::tx::Error> {
        todo!()
    }
}

pub async fn rx<S: Into<std::net::UdpSocket>>(
    socket: S,
    producer: ring::Producer<Message>,
    cooldown: Cooldown,
) -> io::Result<()> {
    let socket = socket.into();
    socket.set_nonblocking(true).unwrap();

    let socket = UdpSocket(tokio::net::UdpSocket::from_std(socket).unwrap());
    let result = task::Receiver::new(producer, socket, cooldown).await;
    if let Some(err) = result {
        Err(err)
    } else {
        Ok(())
    }
}

pub async fn tx<S: Into<std::net::UdpSocket>>(
    socket: S,
    consumer: ring::Consumer<Message>,
    gso: Gso,
    cooldown: Cooldown,
) -> io::Result<()> {
    let socket = socket.into();
    socket.set_nonblocking(true).unwrap();

    let socket = UdpSocket(tokio::net::UdpSocket::from_std(socket).unwrap());
    let result = task::Sender::new(consumer, socket, gso, cooldown).await;
    if let Some(err) = result {
        Err(err)
    } else {
        Ok(())
    }
}

pub struct UdpSocket(tokio::net::UdpSocket);

impl tx::Socket<Message> for UdpSocket {
    type Error = io::Error;

    #[inline]
    fn send(
        &mut self,
        cx: &mut Context,
        entries: &mut [Message],
        events: &mut tx::Events,
    ) -> io::Result<()> {
        for entry in entries {
            let target = (*entry.remote_address()).into();
            let payload = entry.payload_mut();
            match self.0.poll_send_to(cx, payload, target) {
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

impl rx::Socket<Message> for UdpSocket {
    type Error = io::Error;

    #[inline]
    fn recv(
        &mut self,
        cx: &mut Context,
        entries: &mut [Message],
        events: &mut rx::Events,
    ) -> io::Result<()> {
        for entry in entries {
            let payload = entry.payload_mut();
            let mut buf = io::ReadBuf::new(payload);
            match self.0.poll_recv_from(cx, &mut buf) {
                Poll::Ready(Ok(addr)) => {
                    unsafe {
                        let len = buf.filled().len();
                        entry.set_payload_len(len);
                    }

                    entry.set_remote_address(&(addr.into()));

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
