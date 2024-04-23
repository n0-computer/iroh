// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use core::task::{Context, Poll};
use s2n_quic_core::task::cooldown::Cooldown;
use s2n_quic_platform::{
    features::Gso,
    socket::{
        ring,
        task::{rx, tx},
    },
    syscall::{SocketType, UnixMessage},
};
use std::{io, os::unix::io::AsRawFd};
use tokio::io::unix::AsyncFd;

pub async fn rx<S: Into<std::net::UdpSocket>, M: UnixMessage + Unpin>(
    socket: S,
    producer: ring::Producer<M>,
    cooldown: Cooldown,
) -> io::Result<()> {
    let socket = socket.into();
    socket.set_nonblocking(true).unwrap();

    let socket = AsyncFd::new(socket).unwrap();
    let result = rx::Receiver::new(producer, socket, cooldown).await;
    if let Some(err) = result {
        Err(err)
    } else {
        Ok(())
    }
}

pub async fn tx<S: Into<std::net::UdpSocket>, M: UnixMessage + Unpin>(
    socket: S,
    consumer: ring::Consumer<M>,
    gso: Gso,
    cooldown: Cooldown,
) -> io::Result<()> {
    let socket = socket.into();
    socket.set_nonblocking(true).unwrap();

    let socket = AsyncFd::new(socket).unwrap();
    let result = tx::Sender::new(consumer, socket, gso, cooldown).await;
    if let Some(err) = result {
        Err(err)
    } else {
        Ok(())
    }
}

/*impl<S: AsRawFd, M: UnixMessage> tx::Socket<M> for AsyncFd<S> {
    type Error = io::Error;

    #[inline]
    fn send(
        &mut self,
        cx: &mut Context,
        entries: &mut [M],
        events: &mut tx::Events,
    ) -> io::Result<()> {
        // Call the syscall for the socket
        //
        // NOTE: we usually wrap this in a `AsyncFdReadyGuard::try_io`. However, here we just
        //       assume the socket is ready in the general case and then fall back to querying
        //       socket readiness if it's not. This can avoid some things like having to construct
        //       a `std::io::Error` with `WouldBlock` and dereferencing the registration.
        M::send(self.get_ref().as_raw_fd(), entries, events);

        // yield back if we weren't blocked
        if !events.is_blocked() {
            return Ok(());
        }

        // * First iteration we need to clear socket readiness since the `send` call returned a
        // `WouldBlock`.
        // * Second iteration we need to register the waker, assuming the socket readiness was
        // cleared.
        //   * If we got a `Ready` anyway, then clear the blocked status and have the caller try
        //   again.
        for i in 0..2 {
            match self.poll_write_ready(cx) {
                Poll::Ready(guard) => {
                    let mut guard = guard?;
                    if i == 0 {
                        guard.clear_ready();
                    } else {
                        events.take_blocked();
                    }
                }
                Poll::Pending => {
                    return Ok(());
                }
            }
        }

        Ok(())
    }
}

impl<S: AsRawFd, M: UnixMessage> rx::Socket<M> for AsyncFd<S> {
    type Error = io::Error;

    #[inline]
    fn recv(
        &mut self,
        cx: &mut Context,
        entries: &mut [M],
        events: &mut rx::Events,
    ) -> io::Result<()> {
        // Call the syscall for the socket
        //
        // NOTE: we usually wrap this in a `AsyncFdReadyGuard::try_io`. However, here we just
        //       assume the socket is ready in the general case and then fall back to querying
        //       socket readiness if it's not. This can avoid some things like having to construct
        //       a `std::io::Error` with `WouldBlock` and dereferencing the registration.
        M::recv(
            self.get_ref().as_raw_fd(),
            SocketType::NonBlocking,
            entries,
            events,
        );

        // yield back if we weren't blocked
        if !events.is_blocked() {
            return Ok(());
        }

        // * First iteration we need to clear socket readiness since the `recv` call returned a
        // `WouldBlock`.
        // * Second iteration we need to register the waker, assuming the socket readiness was
        // cleared.
        //   * If we got a `Ready` anyway, then clear the blocked status and have the caller try
        //   again.
        for i in 0..2 {
            match self.poll_read_ready(cx) {
                Poll::Ready(guard) => {
                    let mut guard = guard?;
                    if i == 0 {
                        guard.clear_ready();
                    } else {
                        events.take_blocked();
                    }
                }
                Poll::Pending => {
                    return Ok(());
                }
            }
        }

        Ok(())
    }
}
*/
