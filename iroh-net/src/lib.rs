//! Peer-to-peer connectivity based on QUIC.
//!
//! iroh-net is a library to establish direct connectivity between peers.  It exposes an
//! interface to [QUIC] connections and streams to the user, while implementing direct
//! connectivity using [hole punching] complemented by relay servers under the hood.
//!
//!
//! # Connection Establishment
//!
//! An iroh-net connection between two iroh-net nodes is usually established with the help
//! of a Relay server.  When creating the [`Endpoint`] it connects to the closest Relay
//! server and designates this as the *home relay*.  When other nodes want to connect they
//! first establish connection via this home relay.  As soon as connection between the two
//! nodes is established they will attempt to create a direct connection, using [hole
//! punching] if needed.  Once the direct connection is established the relay server is no
//! longer involved in the connection.
//!
//! If one of the iroh-net nodes can be reached directly, connectivity can also be
//! established without involving a Relay server.  This is done by using the node's
//! listening addresses in the connection establishement instead of the [`RelayUrl`] which
//! is used to identify a Relay server.  Of course it is also possible to use both a
//! [`RelayUrl`] and direct addresses at the same time to connect.
//!
//!
//! # Encryption
//!
//! The connection is encrypted using TLS, like standard QUIC connections.  Unlike standard
//! QUIC there is no client, server or server TLS key and certificate chain.  Instead each iroh-net node has a
//! unique [`SecretKey`] used to authenticate and encrypt the connection.  When an iroh-net
//! node connects, it uses the corresponding [`PublicKey`] to ensure the connection is only
//! established with the intended peer.
//!
//! Since the [`PublicKey`] is also used to identify the iroh-net node it is also known as
//! the [`NodeId`].  As encryption is an integral part of TLS as used in QUIC this
//! [`NodeId`] is always a required parameter to establish a connection.
//!
//! When accepting connections the peer's [`NodeId`] is authenticated.  However it is up to
//! the application to decide if a particular peer is allowed to connect or not.
//!
//!
//! # Relay Servers
//!
//! Relay servers exist to ensure all iroh-net nodes are always reachable.  They accept
//! **encrypted** traffic for iroh-net nodes which are connected to them, forwarding it to
//! the correct destination based on the [`NodeId`] only.  Since nodes only send encrypted
//! traffic, the Relay servers can not decode any traffic for other iroh-net nodes and only
//! forward it.
//!
//! The connections to the Relay server are initiated as normal HTTP 1.1 connections using
//! TLS.  Once connected the transport is upgraded to a plain TCP connection using a custom
//! protocol.  All further data is then sent using this custom relaying protocol.  Usually
//! soon after the connection is established via the Relay it will migrate to a direct
//! connection.  However if this is not possible the connection will keep flowing over the
//! relay server as a fallback.
//!
//! Additionally to providing reliable connectivity between iroh-net nodes, Relay servers
//! provide some functions to assist in [hole punching].  They have various services to help
//! nodes understand their own network situation.  This includes offering a [STUN] server,
//! but also a few HTTP extra endpoints as well as responding to ICMP echo requests.
//!
//!
//! # Connections and Streams
//!
//! An iroh-net node is managed using the [`Endpoint`] and this is used to create or accept
//! connections to other nodes.  To establish a connection to an iroh-net node you need to
//! know three pieces of information:
//!
//! - The [`NodeId`] of the peer to connect to.
//! - Some addressing information:
//!   - Usually the [`RelayUrl`] identifying the Relay server.
//!   - Sometimes, or usually additionally, any direct addresses which might be known.
//! - The QUIC/TLS Application-Layer Protocol Negotiation, or [ALPN], name to use.
//!
//! The ALPN is used by both sides to agree on which application-specific protocol will be
//! used over the resulting QUIC connection.  These can be protocols like `h3` used for
//! [`HTTP/3`], but more commonly will be a custom identifier for the application.
//!
//! Once connected the API exposes QUIC streams.  These are very cheap to create so can be
//! created at any time and can be used to create very many short-lived stream as well as
//! long-lived streams.  There are two stream types to choose from:
//!
//! - **Uni-directional** which only allows the peer which initiated the stream to send
//!   data.
//!
//! - **Bi-directional** which allows both peers to send and receive data.  However, the
//!   initiator of this stream has to send data before the peer will be aware of this
//!   stream.
//!
//! Additionally to being extremely light-weight, streams can be interleaved and will not block
//! each other.  Allowing many streams to co-exist, regardless of how long they last.
//!
//!
//! ## Node Discovery
//!
//! The need to know the [`RelayUrl`] *or* some direct addresses in addition to the
//! [`NodeId`] to connect to an iroh-net node can be an obstacle.  To address this the
//! [`endpoint::Builder`] allows to configure a [`discovery`] service.
//!
//! The [`DnsDiscovery`] service is a discovery service which will publish the [`RelayUrl`]
//! and direct addresses to a service publishing those as DNS records.  To connect it looks
//! up the [`NodeId`] in the DNS system to find the adressing details.  This enables
//! connecting using only the [`NodeId`] which is often more convenient and resilient.
//!
//!
//! [QUIC]: https://quickwg.org
//! [hole punching]: https://en.wikipedia.org/wiki/Hole_punching_(networking)
//! [socket addresses]: https://doc.rust-lang.org/stable/std/net/enum.SocketAddr.html
//! [STUN]: https://en.wikipedia.org/wiki/STUN
//! [ALPN]: https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation
//! [HTTP/3]: https://en.wikipedia.org/wiki/HTTP/3
//! [`SecretKey`]: crate::key::SecretKey
//! [`PublicKey`]: crate::key::PublicKey
//! [`RelayUrl`]: crate::relay::RelayUrl
//! [`discovery`]: crate::endpoint::Builder::discovery
//! [`DnsDiscovery`]: crate::discovery::dns::DnsDiscovery

#![recursion_limit = "256"]
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub mod defaults;
pub mod dialer;
mod disco;
pub mod discovery;
pub mod dns;
pub mod endpoint;
mod magicsock;
pub mod metrics;
pub mod net;
pub mod netcheck;
pub mod ping;
pub mod portmapper;
pub mod relay;
pub mod stun;
pub mod ticket;
pub mod tls;
pub mod util;

pub use endpoint::{AddrInfo, Endpoint, NodeAddr};

pub use iroh_base::key;

pub use iroh_base::key::NodeId;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
