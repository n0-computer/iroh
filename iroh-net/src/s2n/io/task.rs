// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// depending on the platform, some of these implementations aren't used
#![allow(dead_code)]

mod simple;
#[cfg(unix)]
mod unix;

cfg_if::cfg_if! {
    /*if #[cfg(s2n_quic_platform_socket_mmsg)] {
        pub use mmsg::{rx, tx};
    } else */
    if #[cfg(s2n_quic_platform_socket_msg)] {
        pub use msg::{rx, tx};
    } else {
        pub use simple::{rx, tx};
    }
}

macro_rules! libc_msg {
    ($message:ident, $cfg:ident) => {
        #[cfg($cfg)]
        mod $message {
            use super::unix;
            use crate::magicsock::MagicSock;
            use s2n_quic_core::task::cooldown::Cooldown;
            use s2n_quic_platform::{features::Gso, message::$message::Message, socket::ring};

            pub async fn rx(
                magicsock: MagicSock,
                producer: ring::Producer<Message>,
                cooldown: Cooldown,
            ) -> std::io::Result<()> {
                unix::rx(magicsock, producer, cooldown).await
            }

            pub async fn tx(
                magicsock: MagicSock,
                consumer: ring::Consumer<Message>,
                gso: Gso,
                cooldown: Cooldown,
            ) -> std::io::Result<()> {
                unix::tx(magicsock, consumer, gso, cooldown).await
            }
        }
    };
}

libc_msg!(msg, s2n_quic_platform_socket_msg);
// libc_msg!(mmsg, s2n_quic_platform_socket_mmsg);
