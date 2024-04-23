use s2n_quic_core::{
    endpoint::Endpoint,
    event::{self, EndpointPublisher as _},
    inet::{self, SocketAddress},
    io::event_loop::EventLoop,
    path::{self, mtu, MaxMtu},
    task::cooldown::Cooldown,
    time::Clock as ClockTrait,
};
use s2n_quic_platform::{features::gso, socket, syscall};
use std::{convert::TryInto, io, io::ErrorKind};
use tokio::runtime::Handle;

use crate::magicsock::MagicSock;

mod builder;
mod clock;
pub(crate) mod task;
#[cfg(test)]
mod tests;

pub type PathHandle = path::Tuple;
pub use builder::Builder;
pub(crate) use clock::Clock;

#[derive(Debug)]
pub struct Io {
    builder: Builder,
}

impl s2n_quic::provider::io::Provider for Io {
    type PathHandle = PathHandle;
    type Error = io::Error;

    fn start<E: Endpoint<PathHandle = Self::PathHandle>>(
        self,
        endpoint: E,
    ) -> Result<SocketAddress, Self::Error> {
        let (_, e) = self.start(endpoint)?;
        Ok(e)
    }
}

impl Io {
    pub fn builder(magic: MagicSock) -> Builder {
        Builder::new(magic)
    }

    pub fn new<A: std::net::ToSocketAddrs>(magic: MagicSock, addr: A) -> io::Result<Self> {
        let address = addr.to_socket_addrs()?.next().expect("missing address");
        let builder = Builder::new(magic).with_receive_address(address)?;
        Ok(Self { builder })
    }

    pub fn start<E: Endpoint<PathHandle = PathHandle>>(
        self,
        mut endpoint: E,
    ) -> io::Result<(tokio::task::JoinHandle<()>, SocketAddress)> {
        let Builder {
            handle,
            rx_socket,
            tx_socket,
            recv_addr,
            send_addr,
            socket_recv_buffer_size,
            socket_send_buffer_size,
            queue_recv_buffer_size,
            queue_send_buffer_size,
            mtu_config_builder,
            max_segments,
            gro_enabled,
            reuse_address,
            reuse_port,
            magic,
        } = self.builder;

        let clock = Clock::default();

        let mut publisher = event::EndpointPublisherSubscriber::new(
            event::builder::EndpointMeta {
                endpoint_type: E::ENDPOINT_TYPE,
                timestamp: clock.get_time(),
            },
            None,
            endpoint.subscriber(),
        );

        publisher.on_platform_feature_configured(event::builder::PlatformFeatureConfigured {
            configuration: event::builder::PlatformFeatureConfiguration::Gso {
                max_segments: max_segments.into(),
            },
        });

        // try to use the tokio runtime handle if provided, otherwise try to use the implicit tokio
        // runtime in the current scope of the application.
        let handle = if let Some(handle) = handle {
            handle
        } else {
            Handle::try_current().map_err(|err| std::io::Error::new(io::ErrorKind::Other, err))?
        };

        let guard = handle.enter();

        let rx_socket = if let Some(rx_socket) = rx_socket {
            rx_socket
        } else if let Some(recv_addr) = recv_addr {
            syscall::bind_udp(recv_addr, reuse_address, reuse_port)?
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing bind address",
            ));
        };

        let rx_addr = convert_addr_to_std(rx_socket.local_addr()?)?;

        let tx_socket = if let Some(tx_socket) = tx_socket {
            tx_socket
        } else if let Some(send_addr) = send_addr {
            syscall::bind_udp(send_addr, reuse_address, reuse_port)?
        } else {
            // No tx_socket or send address was specified, so the tx socket
            // will be a handle to the rx socket.
            rx_socket.try_clone()?
        };

        if let Some(size) = socket_send_buffer_size {
            tx_socket.set_send_buffer_size(size)?;
        }

        if let Some(size) = socket_recv_buffer_size {
            rx_socket.set_recv_buffer_size(size)?;
        }

        let mut mtu_config = mtu_config_builder
            .build()
            .map_err(|err| io::Error::new(ErrorKind::InvalidInput, format!("{err}")))?;
        let original_max_mtu = mtu_config.max_mtu;

        // Configure MTU discovery
        if !syscall::configure_mtu_disc(&tx_socket) {
            // disable MTU probing if we can't prevent fragmentation
            mtu_config = mtu::Config::MIN;
        }

        publisher.on_platform_feature_configured(event::builder::PlatformFeatureConfigured {
            configuration: event::builder::PlatformFeatureConfiguration::BaseMtu {
                mtu: mtu_config.base_mtu.into(),
            },
        });

        publisher.on_platform_feature_configured(event::builder::PlatformFeatureConfigured {
            configuration: event::builder::PlatformFeatureConfiguration::InitialMtu {
                mtu: mtu_config.initial_mtu.into(),
            },
        });

        publisher.on_platform_feature_configured(event::builder::PlatformFeatureConfigured {
            configuration: event::builder::PlatformFeatureConfiguration::MaxMtu {
                mtu: mtu_config.max_mtu.into(),
            },
        });

        // Configure the socket with GRO
        let gro_enabled = gro_enabled.unwrap_or(true) && syscall::configure_gro(&rx_socket);

        publisher.on_platform_feature_configured(event::builder::PlatformFeatureConfigured {
            configuration: event::builder::PlatformFeatureConfiguration::Gro {
                enabled: gro_enabled,
            },
        });

        // Configure packet info CMSG
        syscall::configure_pktinfo(&rx_socket);

        // Configure TOS/ECN
        let tos_enabled = syscall::configure_tos(&rx_socket);

        publisher.on_platform_feature_configured(event::builder::PlatformFeatureConfigured {
            configuration: event::builder::PlatformFeatureConfiguration::Ecn {
                enabled: tos_enabled,
            },
        });

        let rx = {
            // if GRO is enabled, then we need to provide the syscall with the maximum size buffer
            let payload_len = if gro_enabled {
                u16::MAX
            } else {
                // Use the originally configured MTU to allow larger packets to be received
                // even if the tx MTU has been reduced due to configure_mtu_disc failing
                original_max_mtu.into()
            } as u32;

            let rx_buffer_size = queue_recv_buffer_size.unwrap_or(8 * (1 << 20));
            let entries = rx_buffer_size / payload_len;
            let entries = if entries.is_power_of_two() {
                entries
            } else {
                // round up to the nearest power of two, since the ring buffers require it
                entries.next_power_of_two()
            };

            let mut consumers = vec![];

            let rx_socket_count = parse_env("S2N_QUIC_UNSTABLE_RX_SOCKET_COUNT").unwrap_or(1);

            // configure the number of self-wakes before "cooling down" and waiting for epoll to
            // complete
            let rx_cooldown = cooldown("RX");

            for idx in 0usize..rx_socket_count {
                let (producer, consumer) = socket::ring::pair(entries, payload_len);
                consumers.push(consumer);

                // spawn a task that actually reads from the socket into the ring buffer
                if idx + 1 == rx_socket_count {
                    handle.spawn(task::rx(magic.clone(), rx_socket, producer, rx_cooldown));
                    break;
                } else {
                    let rx_socket = rx_socket.try_clone()?;
                    handle.spawn(task::rx(
                        magic.clone(),
                        rx_socket,
                        producer,
                        rx_cooldown.clone(),
                    ));
                }
            }

            // construct the RX side for the endpoint event loop
            let max_mtu = MaxMtu::try_from(payload_len as u16).unwrap();
            let addr: inet::SocketAddress = rx_addr.into();
            socket::io::rx::Rx::new(consumers, max_mtu, addr.into())
        };

        let tx = {
            let gso = s2n_quic_platform::features::Gso::from(max_segments);

            // compute the payload size for each message from the number of GSO segments we can
            // fill
            let payload_len = {
                let max_mtu: u16 = mtu_config.max_mtu.into();
                (max_mtu as u32 * gso.max_segments() as u32).min(u16::MAX as u32)
            };

            let tx_buffer_size = queue_send_buffer_size.unwrap_or(128 * 1024);
            let entries = tx_buffer_size / payload_len;
            let entries = if entries.is_power_of_two() {
                entries
            } else {
                // round up to the nearest power of two, since the ring buffers require it
                entries.next_power_of_two()
            };

            let mut producers = vec![];

            let tx_socket_count = parse_env("S2N_QUIC_UNSTABLE_TX_SOCKET_COUNT").unwrap_or(1);

            // configure the number of self-wakes before "cooling down" and waiting for epoll to
            // complete
            let tx_cooldown = cooldown("TX");

            for idx in 0usize..tx_socket_count {
                let (producer, consumer) = socket::ring::pair(entries, payload_len);
                producers.push(producer);

                // spawn a task that actually flushes the ring buffer to the socket
                if idx + 1 == tx_socket_count {
                    handle.spawn(task::tx(
                        magic.clone(),
                        tx_socket,
                        consumer,
                        gso.clone(),
                        tx_cooldown,
                    ));
                    break;
                } else {
                    let tx_socket = tx_socket.try_clone()?;
                    handle.spawn(task::tx(
                        magic.clone(),
                        tx_socket,
                        consumer,
                        gso.clone(),
                        tx_cooldown.clone(),
                    ));
                }
            }

            // construct the TX side for the endpoint event loop
            socket::io::tx::Tx::new(producers, gso, mtu_config.max_mtu)
        };

        // Notify the endpoint of the MTU that we chose
        endpoint.set_mtu_config(mtu_config);

        let task = handle.spawn(
            EventLoop {
                endpoint,
                clock,
                rx,
                tx,
                cooldown: cooldown("ENDPOINT"),
            }
            .start(),
        );

        drop(guard);

        Ok((task, rx_addr.into()))
    }
}

fn convert_addr_to_std(addr: socket2::SockAddr) -> io::Result<std::net::SocketAddr> {
    addr.as_socket()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid domain for socket"))
}

fn parse_env<T: core::str::FromStr>(name: &str) -> Option<T> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

pub fn cooldown(direction: &str) -> Cooldown {
    let name = format!("S2N_QUIC_UNSTABLE_COOLDOWN_{direction}");
    let limit = parse_env(&name).unwrap_or(0);
    Cooldown::new(limit)
}
