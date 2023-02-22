use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use super::key;

pub mod http {
    use std::net::SocketAddr;

    use anyhow::Result;

    use crate::hp::key;

    use super::{DerpRegion, ReceivedMessage};

    #[derive(Debug, thiserror::Error, PartialEq, Eq)]
    pub enum ClientError {
        #[error("closed")]
        Closed,
    }

    #[derive(Default, Debug, Clone, PartialEq, Eq)]
    pub struct Client {}

    impl Client {
        pub fn new_region<F>(key: key::node::SecretKey, f: F) -> Self
        where
            F: Fn() -> Option<DerpRegion>,
        {
            todo!()
        }

        pub fn set_can_ack_pings(&self, val: bool) {
            todo!()
        }

        pub async fn note_preferred(&self, is_preferred: bool) {
            todo!()
        }

        // S returns if we should prefer ipv6
        // it replaces the derphttp.AddressFamilySelector we pass
        // It provides the hint as to whether in an IPv4-vs-IPv6 race that
        // IPv4 should be held back a bit to give IPv6 a better-than-50/50
        // chance of winning. We only return true when we believe IPv6 will
        // work anyway, so we don't artificially delay the connection speed.
        pub fn set_address_family_selector<S>(&self, selector: S)
        where
            S: Fn() -> bool,
        {
            todo!();
        }

        pub fn local_addr(&self) -> Option<SocketAddr> {
            todo!()
        }
        pub async fn ping(&self) -> Result<()> {
            todo!()
        }

        pub async fn send_pong(&self, data: [u8; 8]) -> Result<(), ClientError> {
            todo!()
        }
        pub async fn recv_detail(&self) -> Result<(ReceivedMessage, usize), ClientError> {
            todo!()
        }

        pub async fn send(
            &self,
            dst_key: Option<key::node::PublicKey>,
            b: Vec<u8>,
        ) -> Result<(), ClientError> {
            todo!()
        }

        pub async fn close(self) {
            todo!()
        }
    }
}

// derp_client.go

#[derive(Debug, Clone)]
pub enum ReceivedMessage {
    /// Represents an incoming packet.
    ReceivedPacket {
        source: key::node::PublicKey,
        /// The received packet bytes. It aliases the memory passed to Client.Recv.
        data: Vec<u8>, // TODO: ref
    },
    /// Indicates that the client identified by the underlying public key had previously sent you a
    /// packet but has now disconnected from the server.
    PeerGone(key::node::PublicKey),
    /// Indicates that the client is connected to the server. (Only used by trusted mesh clients)
    PeerPresent(key::node::PublicKey),
    /// Sent by the server upon first connect.
    ServerInfo {
        /// How many bytes per second the server says it will accept, including all framing bytes.
        ///
        /// Zero means unspecified. There might be a limit, but the client need not try to respect it.
        token_bucket_bytes_per_second: usize,
        /// TokenBucketBytesBurst is how many bytes the server will
        /// allow to burst, temporarily violating
        /// TokenBucketBytesPerSecond.
        ///
        /// Zero means unspecified. There might be a limit, but the client need not try to respect it.
        token_bucket_bytes_burst: usize,
    },
    /// Request from a client or server to reply to the
    /// other side with a PongMessage with the given payload.
    Ping([u8; 8]),
    /// Reply to a Ping from a client or server
    /// with the payload sent previously in a Ping.
    Pong([u8; 8]),
    /// A one-way empty message from server to client, just to
    /// keep the connection alive. It's like a Ping, but doesn't solicit
    /// a reply from the client.
    KeepAlive,
    /// A one-way message from server to client, declaring the connection health state.
    Health {
        /// If set, is a description of why the connection is unhealthy.
        ///
        /// If `None` means the connection is healthy again.
        ///
        /// The default condition is healthy, so the server doesn't broadcast a HealthMessage
        /// until a problem exists.
        problem: Option<String>,
    },
    /// A one-way message from server to client, advertising that the server is restarting.
    ServerRestarting {
        /// An advisory duration that the client should wait before attempting to reconnect.
        /// It might be zero. It exists for the server to smear out the reconnects.
        reconnect_in: Duration,
        /// An advisory duration for how long the client should attempt to reconnect
        /// before giving up and proceeding with its normal connection failure logic. The interval
        /// between retries is undefined for now. A server should not send a TryFor duration more
        /// than a few seconds.
        try_for: Duration,
    },
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DerpMap {
    pub regions: HashMap<usize, DerpRegion>,
}

impl DerpMap {
    /// Returns the sorted region IDs.
    pub fn region_ids(&self) -> Vec<usize> {
        let mut ids: Vec<_> = self.regions.keys().copied().collect();
        ids.sort();
        ids
    }
}

/// A geographic region running DERP relay node(s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerpRegion {
    /// A unique integer for a geographic region.
    pub region_id: usize,
    pub nodes: Vec<DerpNode>,
    pub avoid: bool,
    pub region_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerpNode {
    pub name: String,
    pub region_id: usize,
    pub host_name: String,
    pub stun_only: bool,
    pub stun_port: u16,
    pub stun_test_ip: Option<IpAddr>,
    // Optionally forces an IPv4 address to use, instead of using DNS.
    // If `None`, A record(s) from DNS lookups of HostName are used.
    // If `Disabled`, IPv4 is not used;
    pub ipv4: UseIpv4,
    // Optionally forces an IPv6 address to use, instead of using DNS.
    // If `None`, A record(s) from DNS lookups of HostName are used.
    // If `Disabled`, IPv4 is not used;
    pub ipv6: UseIpv6,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UseIpv4 {
    None,
    Disabled,
    Some(Ipv4Addr),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UseIpv6 {
    None,
    Disabled,
    Some(Ipv6Addr),
}
