//! Peer-to-peer QUIC connections.
//!
//! iroh is a library to establish direct connectivity between peers.  It exposes an
//! interface to [QUIC] connections and streams to the user, while implementing direct
//! connectivity using [hole punching] complemented by relay servers under the hood.
//!
//! An iroh endpoint is created and controlled by the [`Endpoint`], e.g. connecting to
//! another endpoint:
//!
//! ```no_run
//! # use iroh::{Endpoint, EndpointAddr};
//! # use n0_snafu::ResultExt;
//! # async fn wrapper() -> n0_snafu::Result {
//! let addr: EndpointAddr = todo!();
//! let ep = Endpoint::bind().await?;
//! let conn = ep.connect(addr, b"my-alpn").await?;
//! let mut send_stream = conn.open_uni().await.context("unable to open uni")?;
//! send_stream
//!     .write_all(b"msg")
//!     .await
//!     .context("unable to write all")?;
//! # Ok(())
//! # }
//! ```
//!
//! The other endpoint can accept incoming connections using the [`Endpoint`] as well:
//!
//! ```no_run
//! # use iroh::{Endpoint, EndpointAddr};
//! # use n0_snafu::ResultExt;
//! # async fn wrapper() -> n0_snafu::Result {
//! let ep = Endpoint::builder()
//!     .alpns(vec![b"my-alpn".to_vec()])
//!     .bind()
//!     .await?;
//! let conn = ep
//!     .accept()
//!     .await
//!     .context("accept error")?
//!     .await
//!     .context("connecting error")?;
//! let mut recv_stream = conn.accept_uni().await.context("unable to open uni")?;
//! let mut buf = [0u8; 3];
//! recv_stream
//!     .read_exact(&mut buf)
//!     .await
//!     .context("unable to read")?;
//! # Ok(())
//! # }
//! ```
//!
//! Of course you can also use [bi-directional streams] or any other features from QUIC.
//!
//! For more elaborate examples, see [below](#examples) or the examples directory in
//! the source repository.
//!
//!
//! # Connection Establishment
//!
//! An iroh connection between two iroh endpoints is usually established with the help
//! of a Relay server.  When creating the [`Endpoint`] it connects to the closest Relay
//! server and designates this as the *home relay*.  When other endpoints want to connect they
//! first establish connection via this home relay.  As soon as connection between the two
//! endpoints is established they will attempt to create a direct connection, using [hole
//! punching] if needed.  Once the direct connection is established the relay server is no
//! longer involved in the connection.
//!
//! If one of the iroh endpoints can be reached directly, connectivity can also be
//! established without involving a Relay server.  This is done by using the endpoint's
//! listening addresses in the connection establishement instead of the [`RelayUrl`] which
//! is used to identify a Relay server.  Of course it is also possible to use both a
//! [`RelayUrl`] and direct addresses at the same time to connect.
//!
//!
//! # Encryption
//!
//! The connection is encrypted using TLS, like standard QUIC connections.  Unlike standard
//! QUIC there is no client, server or server TLS key and certificate chain.  Instead each iroh endpoint has a
//! unique [`SecretKey`] used to authenticate and encrypt the connection.  When an iroh
//! endpoint connects, it uses the corresponding [`PublicKey`] to ensure the connection is only
//! established with the intended peer.
//!
//! Since the [`PublicKey`] is also used to identify the iroh endpoint it is also known as
//! the [`EndpointId`].  As encryption is an integral part of TLS as used in QUIC this
//! [`EndpointId`] is always a required parameter to establish a connection.
//!
//! When accepting connections the peer's [`EndpointId`] is authenticated.  However it is up to
//! the application to decide if a particular peer is allowed to connect or not.
//!
//!
//! # Relay Servers
//!
//! Relay servers exist to ensure all iroh endpoints are always reachable.  They accept
//! **encrypted** traffic for iroh endpoints which are connected to them, forwarding it to
//! the correct destination based on the [`EndpointId`] only.  Since endpoints only send encrypted
//! traffic, the Relay servers can not decode any traffic for other iroh endpoints and only
//! forward it.
//!
//! The connections to the Relay server are initiated as normal HTTP 1.1 connections using
//! TLS.  Once connected the transport is upgraded to a plain TCP connection using a custom
//! protocol.  All further data is then sent using this custom relaying protocol.  Usually
//! soon after the connection is established via the Relay it will migrate to a direct
//! connection.  However if this is not possible the connection will keep flowing over the
//! relay server as a fallback.
//!
//! Additionally to providing reliable connectivity between iroh endpoints, Relay servers
//! provide some functions to assist in [hole punching].  They have various services to help
//! endpoints understand their own network situation.  This includes offering a [QAD] server,
//! but also a few HTTP extra endpoints as well as responding to ICMP echo requests.
//!
//! By default the [number 0] relay servers are used, see [`RelayMode::Default`].
//!
//!
//! # Connections and Streams
//!
//! An iroh endpoint is managed using the [`Endpoint`] and this is used to create or accept
//! connections to other endpoints.  To establish a connection to an iroh endpoint you need to
//! know three pieces of information:
//!
//! - The [`EndpointId`] of the peer to connect to.
//! - Some addressing information:
//!   - Usually the [`RelayUrl`] identifying the Relay server.
//!   - Sometimes, or usually additionally, any direct addresses which might be known.
//! - The QUIC/TLS Application-Layer Protocol Negotiation, or [ALPN], name to use.
//!
//! The ALPN is used by both sides to agree on which application-specific protocol will be
//! used over the resulting QUIC connection.  These can be protocols like `h3` used for
//! [HTTP/3][HTTP3], but more commonly will be a custom identifier for the application.
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
//! Additionally to being extremely light-weight, streams can be interleaved and will not
//! block each other.  Allowing many streams to co-exist, regardless of how long they last.
//!
//! <div class="warning">
//!
//! To keep streams cheap, they are lazily created on the network: only once a sender starts
//! sending data on the stream will the receiver become aware of a stream.  This means only
//! calling [`Connection::open_bi`] is not sufficient for the corresponding call to
//! [`Connection::accept_bi`] to return.  The sender **must** send data on the stream before
//! the receiver's [`Connection::accept_bi`] call will return.
//!
//! </div>
//!
//! ## Endpoint Discovery
//!
//! The need to know the [`RelayUrl`] *or* some direct addresses in addition to the
//! [`EndpointId`] to connect to an iroh endpoint can be an obstacle.  To address this, the
//! [`endpoint::Builder`] allows you to configure a [`discovery`] service.
//!
//! The [`DnsDiscovery`] service is a discovery service which will publish the [`RelayUrl`]
//! and direct addresses to a service publishing those as DNS records.  To connect it looks
//! up the [`EndpointId`] in the DNS system to find the addressing details.  This enables
//! connecting using only the [`EndpointId`] which is often more convenient and resilient.
//!
//! See [the discovery module] for more details.
//!
//!
//! # Examples
//!
//! The central struct is the [`Endpoint`], which allows you to connect to other endpoints:
//!
//! ```no_run
//! use iroh::{Endpoint, EndpointAddr};
//! use n0_snafu::{Result, ResultExt};
//!
//! async fn connect(addr: EndpointAddr) -> Result<()> {
//!     // The Endpoint is the central object that manages an iroh node.
//!     let ep = Endpoint::bind().await?;
//!
//!     // Establish a QUIC connection, open a bi-directional stream, exchange messages.
//!     let conn = ep.connect(addr, b"hello-world").await?;
//!     let (mut send_stream, mut recv_stream) = conn.open_bi().await.context("open bi")?;
//!     send_stream.write_all(b"hello").await.context("write")?;
//!     send_stream.finish().context("finish")?;
//!     let _msg = recv_stream.read_to_end(10).await.context("read")?;
//!
//!     // Gracefully close the connection and endpoint.
//!     conn.close(1u8.into(), b"done");
//!     ep.close().await;
//!     println!("Client closed");
//!     Ok(())
//! }
//! ```
//!
//! Every [`Endpoint`] can also accept connections:
//!
//! ```no_run
//! use iroh::{Endpoint, EndpointAddr};
//! use n0_future::StreamExt;
//! use n0_snafu::{Result, ResultExt};
//!
//! async fn accept() -> Result<()> {
//!     // To accept connections at least one ALPN must be configured.
//!     let ep = Endpoint::builder()
//!         .alpns(vec![b"hello-world".to_vec()])
//!         .bind()
//!         .await?;
//!
//!     // Accept a QUIC connection, accept a bi-directional stream, exchange messages.
//!     let conn = ep
//!         .accept()
//!         .await
//!         .context("no incoming connection")?
//!         .await
//!         .context("accept conn")?;
//!     let (mut send_stream, mut recv_stream) = conn.accept_bi().await.context("accept stream")?;
//!     let _msg = recv_stream.read_to_end(10).await.context("read")?;
//!     send_stream.write_all(b"world").await.context("write")?;
//!     send_stream.finish().context("finish")?;
//!
//!     // Wait for the client to close the connection and gracefully close the endpoint.
//!     conn.closed().await;
//!     ep.close().await;
//!     Ok(())
//! }
//! ```
//!
//! Please see the examples directory for more nuanced examples.
//!
//!
//! [QUIC]: https://quicwg.org
//! [bi-directional streams]: crate::endpoint::Connection::open_bi
//! [hole punching]: https://en.wikipedia.org/wiki/Hole_punching_(networking)
//! [socket addresses]: https://doc.rust-lang.org/stable/std/net/enum.SocketAddr.html
//! [QAD]: https://www.ietf.org/archive/id/draft-ietf-quic-address-discovery-00.html
//! [ALPN]: https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation
//! [HTTP3]: https://en.wikipedia.org/wiki/HTTP/3
//! [`SecretKey`]: crate::SecretKey
//! [`PublicKey`]: crate::PublicKey
//! [`RelayUrl`]: crate::RelayUrl
//! [`discovery`]: crate::endpoint::Builder::discovery
//! [`DnsDiscovery`]: crate::discovery::dns::DnsDiscovery
//! [number 0]: https://n0.computer
//! [`RelayMode::Default`]: crate::RelayMode::Default
//! [the discovery module]: crate::discovery
//! [`Connection::open_bi`]: crate::endpoint::Connection::open_bi
//! [`Connection::accept_bi`]: crate::endpoint::Connection::accept_bi

#![recursion_limit = "256"]
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
#![cfg_attr(wasm_browser, allow(unused))]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(iroh_docsrs, feature(doc_cfg))]

mod magicsock;
mod tls;

pub(crate) mod util;
#[cfg(wasm_browser)]
pub(crate) mod web_runtime;

pub mod defaults;
pub mod discovery;
#[cfg(not(wasm_browser))]
pub mod dns;
pub mod endpoint;
pub mod metrics;
pub mod net_report;
pub mod protocol;

pub use endpoint::{Endpoint, RelayMode};
pub use iroh_base::{
    EndpointAddr, EndpointId, KeyParsingError, PublicKey, RelayUrl, RelayUrlParseError, SecretKey,
    Signature, SignatureError, TransportAddr,
};
pub use iroh_relay::{RelayConfig, RelayMap, endpoint_info};
pub use n0_watcher::Watcher;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
