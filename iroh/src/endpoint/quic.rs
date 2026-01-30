//! Exporting and encapsulating structs from quinn
//!
//! Co-locates all iroh-quinn exports.
//!
//! There are some structs that we use in particular ways, where we would like
//! to limit or expand how those structs are used in iroh. By encapsulating them
//! we can ensure the functionality needed to make iroh work.

#[cfg(feature = "qlog")]
use std::path::Path;
use std::{sync::Arc, time::Duration};

/// `quinn` types that are used in the public iroh API.
// Each type is notated with the iroh type or quinn type that uses it.
pub use quinn::{
    AcceptBi,             // iroh::endpoint::Connection
    AcceptUni,            // iroh::endpoint::Connection
    AckFrequencyConfig,   // iroh::endpoint::quic::QuicTransportConfig
    ClosedStream,         // iroh::protocol::AcceptError, quinn::RecvStream, quinn::SendStream
    ConnectionError,      // iroh::endpoint::ConnectError
    ConnectionStats,      // iroh::endpoint::Connection
    Dir,                  // quinn::StreamId
    IdleTimeout,          // iroh::endpoint::quic::QuicTransportConfig
    MtuDiscoveryConfig,   // iroh::endpoint::quic::QuicTransportConfig
    OpenBi,               // iroh::endpoint::Connection
    OpenUni,              // iroh::endpoint::Connection
    PathStats,            // iroh::socket::remote_map::remote_state::PathInfo
    ReadDatagram,         // iroh::endpoint::Connection
    ReadError,            // quinn::RecvStream
    ReadExactError,       // quinn::RecvStream
    ReadToEndError,       // quinn::RecvStream
    RecvStream,           // quinn::AcceptBi, quinn::AcceptUni, quinn::OpenBi, quinn::OpenUni
    ResetError,           // quinn::RecvStream
    SendDatagram,         // iroh::endpoint::Connection
    SendDatagramError,    // iroh::endpoint::Connection
    SendStream,           // quinn::AcceptBi, quinn::OpenUni
    Side,                 // iroh::endpoint::Connection, quinn::StreamId,
    StoppedError,         // quinn::SendStream
    StreamId,             // quinn::RecvStream
    UnorderedRecvStream,  // quinn::RecvStream
    VarInt,               // various
    VarIntBoundsExceeded, // quinn::VarInt, quinn::IdleTimeout
    WriteError,           // quinn::SendStream
    Written,              // quinn::SendStream
};
#[cfg(feature = "qlog")]
pub use quinn::{QlogConfig, QlogFactory, QlogFileFactory};
/// `quinn_proto` types that are used in the public iroh API.
// Each type is notated with the iroh type or quinn type that uses it.
pub use quinn_proto::{
    ApplicationClose,                 // quinn::ConnectionError
    Chunk,                            // quinn::RecvStream
    ConnectError as QuicConnectError, // iroh::endpoint::ConnectWithOptsError
    ConnectionClose,                  // quinn::ConnectionError
    FrameStats,                       // quinn::ConnectionStats
    FrameType,                        // quinn_proto::TransportError
    PathId,                           // quinn_proto::crypto::PacketKey
    RttEstimator,                     // quinn_proto::congestion::Controller
    TimeSource,                       // iroh::endpoint::quic::ServerConfig
    TokenLog,                         // quinn::ValidationTokenConfig
    TokenReuseError,                  // quinn::TokenLog
    TransportError,                   // quinn::ConnectionError
    TransportErrorCode,               // quinn_proto::TransportError
    UdpStats,                         // quinn::ConnectionStats
    ValidationTokenConfig,            // iroh::endpoint::quic::::ServerConfig
    congestion::{
        Controller,        // iroh::endpoint::Connection
        ControllerFactory, // iroh::endpoint::quic::QuicTransportConfig
        ControllerMetrics, // quinn_proto::congestion::Controller
    },
    crypto::{
        AeadKey,                   // quinn::HandshakeTokenKey
        CryptoError, // quinn_proto::crypto::CryptoError, quinn_proto::crypto::PacketKey
        ExportKeyingMaterialError, // iroh::endpoint::Connection
        HandshakeTokenKey, // iroh::endpoint::quic::ServerConfig
        HeaderKey,   // quinn_proto::crypto::Keys
        Keys,        // quinn_proto::crypto::Session
        PacketKey,   // quinn_proto::crypto::Keys
        UnsupportedVersion, // quinn_proto::ConnectError
    },
    transport_parameters::TransportParameters, // quinn_proto::crypot::ServerConfig
};
use tracing::warn;

use crate::socket::{HEARTBEAT_INTERVAL, MAX_MULTIPATH_PATHS, PATH_MAX_IDLE_TIMEOUT};

/// Builder for a [`QuicTransportConfig`].
#[derive(Debug, Clone)]
pub struct QuicTransportConfigBuilder(quinn::TransportConfig);

/// Parameters governing the core QUIC state machine
///
/// Default values should be suitable for most internet applications. Applications protocols which
/// forbid remotely-initiated streams should set `max_concurrent_bidi_streams` and
/// `max_concurrent_uni_streams` to zero.
///
/// In some cases, performance or resource requirements can be improved by tuning these values to
/// suit a particular application and/or network connection. In particular, data window sizes can be
/// tuned for a particular expected round trip time, link capacity, and memory availability. Tuning
/// for higher bandwidths and latencies increases worst-case memory consumption, but does not impair
/// performance at lower bandwidths and latencies. The default configuration is tuned for a 100Mbps
/// link with a 100ms round trip time.
///
/// Use the [`QuicTransportConfigBuilder`] to customize these tunable fields.
///
/// In iroh, the config has some specific default values that make iroh's holepunching work
/// well with QUIC multipath. Adjusting those settings may cause suboptimal usage.
///
/// Look at the following methods for more details:
/// - [`QuicTransportConfigBuilder::default_path_keep_alive_interval`]
/// - [`QuicTransportConfigBuilder::default_path_max_idle_timeout`]
/// - [`QuicTransportConfigBuilder::max_concurrent_multipath_paths`]
/// - [`QuicTransportConfigBuilder::set_max_remote_nat_traversal_addresses`]
///
/// # Examples
/// ```
/// use std::time::Duration;
///
/// use iroh::endpoint::QuicTransportConfig;
///
/// let _cfg = QuicTransportConfig::builder()
///     .send_observed_address_reports(true)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct QuicTransportConfig(Arc<quinn::TransportConfig>);

impl QuicTransportConfig {
    /// Returns a default [`QuicTransportConfigBuilder`] that allows customizing
    /// a [`QuicTransportConfig`].
    pub fn builder() -> QuicTransportConfigBuilder {
        QuicTransportConfigBuilder::new()
    }
}

impl Default for QuicTransportConfig {
    fn default() -> Self {
        QuicTransportConfigBuilder::new().build()
    }
}

impl QuicTransportConfig {
    pub(crate) fn to_inner_arc(&self) -> Arc<quinn::TransportConfig> {
        self.0.clone()
    }
}

impl QuicTransportConfigBuilder {
    /// Create a default [`QuicTransportConfigBuilder`].
    fn new() -> Self {
        let mut cfg = quinn::TransportConfig::default();
        // Override some transport config settings.
        cfg.keep_alive_interval(Some(HEARTBEAT_INTERVAL));
        cfg.default_path_keep_alive_interval(Some(HEARTBEAT_INTERVAL));
        cfg.default_path_max_idle_timeout(Some(PATH_MAX_IDLE_TIMEOUT));
        cfg.max_concurrent_multipath_paths(MAX_MULTIPATH_PATHS + 1);
        cfg.set_max_remote_nat_traversal_addresses(MAX_MULTIPATH_PATHS as u8);
        Self(cfg)
    }

    /// Build a [`QuicTransportConfig`] from the builder.
    pub fn build(self) -> QuicTransportConfig {
        QuicTransportConfig(Arc::new(self.0))
    }

    /// Maximum number of incoming bidirectional streams that may be open concurrently.
    ///
    /// Must be nonzero for the peer to open any bidirectional streams.
    ///
    /// Worst-case memory use is directly proportional to `max_concurrent_bidi_streams *
    /// stream_receive_window`, with an upper bound proportional to `receive_window`.
    pub fn max_concurrent_bidi_streams(mut self, value: VarInt) -> Self {
        self.0.max_concurrent_bidi_streams(value);
        self
    }

    /// Variant of `max_concurrent_bidi_streams` affecting unidirectional streams.
    pub fn max_concurrent_uni_streams(mut self, value: VarInt) -> Self {
        self.0.max_concurrent_uni_streams(value);
        self
    }

    /// Maximum duration of inactivity to accept before timing out the connection.
    ///
    /// The true idle timeout is the minimum of this and the peer's own max idle timeout. `None`
    /// represents an infinite timeout. Defaults to 30 seconds.
    ///
    /// **WARNING**: If a peer or its network path malfunctions or acts maliciously, an infinite
    /// idle timeout can result in permanently hung futures!
    ///
    /// ```
    /// # use std::{convert::TryInto, time::Duration};
    /// # use iroh::endpoint::{QuicTransportConfig, VarInt, VarIntBoundsExceeded};
    /// # fn main() -> Result<(), VarIntBoundsExceeded> {
    /// let mut builder = QuicTransportConfig::builder()
    ///     // Set the idle timeout as `VarInt`-encoded milliseconds
    ///     .max_idle_timeout(Some(VarInt::from_u32(10_000).into()));
    ///
    /// // Set the idle timeout as a `Duration`
    /// builder = builder.max_idle_timeout(Some(Duration::from_secs(10).try_into()?));
    ///
    /// let _cfg = builder.build();
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn max_idle_timeout(mut self, value: Option<IdleTimeout>) -> Self {
        self.0.max_idle_timeout(value);
        self
    }

    /// Maximum number of bytes the peer may transmit without acknowledgement on any one stream
    /// before becoming blocked.
    ///
    /// This should be set to at least the expected connection latency multiplied by the maximum
    /// desired throughput. Setting this smaller than `receive_window` helps ensure that a single
    /// stream doesn't monopolize receive buffers, which may otherwise occur if the application
    /// chooses not to read from a large stream for a time while still requiring data on other
    /// streams.
    pub fn stream_receive_window(mut self, value: VarInt) -> Self {
        self.0.stream_receive_window(value);
        self
    }

    /// Maximum number of bytes the peer may transmit across all streams of a connection before
    /// becoming blocked.
    ///
    /// This should be set to at least the expected connection latency multiplied by the maximum
    /// desired throughput. Larger values can be useful to allow maximum throughput within a
    /// stream while another is blocked.
    pub fn receive_window(mut self, value: VarInt) -> Self {
        self.0.receive_window(value);
        self
    }

    /// Maximum number of bytes to transmit to a peer without acknowledgment.
    ///
    /// Provides an upper bound on memory when communicating with peers that issue large amounts of
    /// flow control credit. Endpoints that wish to handle large numbers of connections robustly
    /// should take care to set this low enough to guarantee memory exhaustion does not occur if
    /// every connection uses the entire window.
    pub fn send_window(mut self, value: u64) -> Self {
        self.0.send_window(value);
        self
    }

    /// Whether to implement fair queuing for send streams having the same priority.
    ///
    /// When enabled, connections schedule data from outgoing streams having the same priority in a
    /// round-robin fashion. When disabled, streams are scheduled in the order they are written to.
    ///
    /// Note that this only affects streams with the same priority. Higher priority streams always
    /// take precedence over lower priority streams.
    ///
    /// Disabling fairness can reduce fragmentation and protocol overhead for workloads that use
    /// many small streams.
    pub fn send_fairness(mut self, value: bool) -> Self {
        self.0.send_fairness(value);
        self
    }

    /// Maximum reordering in packet number space before FACK style loss detection considers a
    /// packet lost. Should not be less than 3, per RFC5681.
    pub fn packet_threshold(mut self, value: u32) -> Self {
        self.0.packet_threshold(value);
        self
    }

    /// Maximum reordering in time space before time based loss detection considers a packet lost,
    /// as a factor of RTT.
    pub fn time_threshold(mut self, value: f32) -> Self {
        self.0.time_threshold(value);
        self
    }

    /// The RTT used before an RTT sample is taken.
    pub fn initial_rtt(mut self, value: Duration) -> Self {
        self.0.initial_rtt(value);
        self
    }

    /// The initial value to be used as the maximum UDP payload size before running MTU discovery
    /// (see [`QuicTransportConfigBuilder::mtu_discovery_config`]).
    ///
    /// Must be at least 1200, which is the default, and known to be safe for typical internet
    /// applications. Larger values are more efficient, but increase the risk of packet loss due to
    /// exceeding the network path's IP MTU. If the provided value is higher than what the network
    /// path actually supports, packet loss will eventually trigger black hole detection and bring
    /// it down to [`QuicTransportConfigBuilder::min_mtu`].
    pub fn initial_mtu(mut self, value: u16) -> Self {
        self.0.initial_mtu(value);
        self
    }

    /// The maximum UDP payload size guaranteed to be supported by the network.
    ///
    /// Must be at least 1200, which is the default, and lower than or equal to
    /// [`QuicTransportConfigBuilder::initial_mtu`].
    ///
    /// Real-world MTUs can vary according to ISP, VPN, and properties of intermediate network links
    /// outside of either endpoint's control. Extreme care should be used when raising this value
    /// outside of private networks where these factors are fully controlled. If the provided value
    /// is higher than what the network path actually supports, the result will be unpredictable and
    /// catastrophic packet loss, without a possibility of repair. Prefer
    /// [`QuicTransportConfigBuilder::initial_mtu`] together with
    /// [`QuicTransportConfigBuilder::mtu_discovery_config`] to set a maximum UDP payload size that robustly
    /// adapts to the network.
    pub fn min_mtu(mut self, value: u16) -> Self {
        self.0.min_mtu(value);
        self
    }

    /// Specifies the MTU discovery config (see [`MtuDiscoveryConfig`] for details).
    ///
    /// Enabled by default.
    pub fn mtu_discovery_config(mut self, value: Option<MtuDiscoveryConfig>) -> Self {
        self.0.mtu_discovery_config(value);
        self
    }

    /// Pad UDP datagrams carrying application data to current maximum UDP payload size.
    ///
    /// Disabled by default. UDP datagrams containing loss probes are exempt from padding.
    ///
    /// Enabling this helps mitigate traffic analysis by network observers, but it increases
    /// bandwidth usage. Without this mitigation precise plain text size of application datagrams as
    /// well as the total size of stream write bursts can be inferred by observers under certain
    /// conditions. This analysis requires either an uncongested connection or application datagrams
    /// too large to be coalesced.
    pub fn pad_to_mtu(mut self, value: bool) -> Self {
        self.0.pad_to_mtu(value);
        self
    }

    /// Specifies the ACK frequency config (see [`AckFrequencyConfig`] for details).
    ///
    /// The provided configuration will be ignored if the peer does not support the acknowledgement
    /// frequency QUIC extension.
    ///
    /// Defaults to `None`, which disables controlling the peer's acknowledgement frequency. Even
    /// if set to `None`, the local side still supports the acknowledgement frequency QUIC
    /// extension and may use it in other ways.
    pub fn ack_frequency_config(mut self, value: Option<AckFrequencyConfig>) -> Self {
        self.0.ack_frequency_config(value);
        self
    }

    /// Number of consecutive PTOs after which network is considered to be experiencing persistent congestion.
    pub fn persistent_congestion_threshold(mut self, value: u32) -> Self {
        self.0.persistent_congestion_threshold(value);
        self
    }

    /// Period of inactivity before sending a keep-alive packet.
    ///
    /// Keep-alive packets prevent an inactive but otherwise healthy connection from timing out.
    ///
    /// `None` to disable, which is the default. Only one side of any given connection needs keep-alive
    /// enabled for the connection to be preserved. Must be set lower than the idle_timeout of both
    /// peers to be effective.
    pub fn keep_alive_interval(mut self, value: Duration) -> Self {
        self.0.keep_alive_interval(Some(value));
        self
    }

    /// Maximum quantity of out-of-order crypto layer data to buffer.
    pub fn crypto_buffer_size(mut self, value: usize) -> Self {
        self.0.crypto_buffer_size(value);
        self
    }

    /// Whether the implementation is permitted to set the spin bit on this connection.
    ///
    /// This allows passive observers to easily judge the round trip time of a connection, which can
    /// be useful for network administration but sacrifices a small amount of privacy.
    pub fn allow_spin(mut self, value: bool) -> Self {
        self.0.allow_spin(value);
        self
    }

    /// Maximum number of incoming application datagram bytes to buffer, or None to disable
    /// incoming datagrams.
    ///
    /// The peer is forbidden to send single datagrams larger than this size. If the aggregate size
    /// of all datagrams that have been received from the peer but not consumed by the application
    /// exceeds this value, old datagrams are dropped until it is no longer exceeded.
    pub fn datagram_receive_buffer_size(mut self, value: Option<usize>) -> Self {
        self.0.datagram_receive_buffer_size(value);
        self
    }

    /// Maximum number of outgoing application datagram bytes to buffer.
    ///
    /// While datagrams are sent ASAP, it is possible for an application to generate data faster
    /// than the link, or even the underlying hardware, can transmit them. This limits the amount of
    /// memory that may be consumed in that case. When the send buffer is full and a new datagram is
    /// sent, older datagrams are dropped until sufficient space is available.
    pub fn datagram_send_buffer_size(mut self, value: usize) -> Self {
        self.0.datagram_send_buffer_size(value);
        self
    }

    /// How to construct new `congestion::Controller`s.
    ///
    /// Typically the refcounted configuration of a `congestion::Controller`,
    /// e.g. a `congestion::NewRenoConfig`.
    ///
    /// # Example
    /// ```
    /// # use iroh::endpoint::QuicTransportConfig; use quinn_proto::congestion; use std::sync::Arc;
    /// let config = QuicTransportConfig::builder()
    ///     .congestion_controller_factory(Arc::new(congestion::NewRenoConfig::default()))
    ///     .build();
    /// ```
    pub fn congestion_controller_factory(
        mut self,
        factory: Arc<dyn ControllerFactory + Send + Sync + 'static>,
    ) -> Self {
        self.0.congestion_controller_factory(factory);
        self
    }

    /// Whether to use "Generic Segmentation Offload" to accelerate transmits, when supported by the
    /// environment.
    ///
    /// Defaults to `true`.
    ///
    /// GSO dramatically reduces CPU consumption when sending large numbers of packets with the same
    /// headers, such as when transmitting bulk data on a connection. However, it is not supported
    /// by all network interface drivers or packet inspection tools. `quinn-udp` will attempt to
    /// disable GSO automatically when unavailable, but this can lead to spurious packet loss at
    /// startup, temporarily degrading performance.
    pub fn enable_segmentation_offload(mut self, enabled: bool) -> Self {
        self.0.enable_segmentation_offload(enabled);
        self
    }

    /// Whether to send observed address reports to peers.
    ///
    /// This will aid peers in inferring their reachable address, which in most NATd networks
    /// will not be easily available to them.
    pub fn send_observed_address_reports(mut self, enabled: bool) -> Self {
        self.0.send_observed_address_reports(enabled);
        self
    }

    /// Whether to receive observed address reports from other peers.
    ///
    /// Peers with the address discovery extension enabled that are willing to provide observed
    /// address reports will do so if this transport parameter is set. In general, observed address
    /// reports cannot be trusted. This, however, can aid the current endpoint in inferring its
    /// reachable address, which in most NATd networks will not be easily available.
    pub fn receive_observed_address_reports(mut self, enabled: bool) -> Self {
        self.0.receive_observed_address_reports(enabled);
        self
    }

    /// Enables the Multipath Extension for QUIC.
    ///
    /// Setting this to any nonzero value will enable the Multipath Extension for QUIC,
    /// <https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/>.
    ///
    /// The value provided specifies the number maximum number of paths this endpoint may open
    /// concurrently when multipath is negotiated. For any path to be opened, the remote must
    /// enable multipath as well.
    ///
    /// Note: this method will ignore values less than the recommended 13 and will log a warning.
    pub fn max_concurrent_multipath_paths(mut self, max_concurrent: u32) -> Self {
        if max_concurrent < MAX_MULTIPATH_PATHS + 1 {
            warn!(
                "QuicTransportConfig::max_concurrent_multipath_paths must be at minimum {}, ignoring user supplied value",
                MAX_MULTIPATH_PATHS + 1
            );
            return self;
        }
        self.0.max_concurrent_multipath_paths(max_concurrent);
        self
    }

    /// Sets a default per-path maximum idle timeout.
    ///
    /// If the path is idle for this long the path will be abandoned. Bear in mind this will
    /// interact with the [`QuicTransportConfigBuilder::max_idle_timeout`], if the last path is
    /// abandoned the entire connection will be closed.
    ///
    /// Note: this method will ignore values higher than the recommended 6500 ms and will log a warning.
    pub fn default_path_max_idle_timeout(mut self, timeout: Duration) -> Self {
        if timeout > PATH_MAX_IDLE_TIMEOUT {
            warn!(
                "QuicTransportConfig::default_path_max_idle must be at most {:?}, ignoring user supplied value",
                PATH_MAX_IDLE_TIMEOUT
            );
            return self;
        }
        self.0.default_path_max_idle_timeout(Some(timeout));
        self
    }

    /// Sets a default per-path keep alive interval.
    ///
    /// Note that this does not interact with the connection-wide
    /// [`QuicTransportConfigBuilder::keep_alive_interval`].  This setting will keep this path active,
    /// [`QuicTransportConfigBuilder::keep_alive_interval`] will keep the connection active, with no
    /// control over which path is used for this.
    ///
    /// Note: this method will ignore values higher than the recommended 5 seconds and will log a warning.
    pub fn default_path_keep_alive_interval(mut self, interval: Duration) -> Self {
        if interval > HEARTBEAT_INTERVAL {
            warn!(
                "QuicTransportConfig::default_path_keep_alive must be at most {:?}, ignoring user supplied value",
                HEARTBEAT_INTERVAL
            );
            return self;
        }
        self.0.default_path_keep_alive_interval(Some(interval));
        self
    }

    /// Sets the maximum number of nat traversal addresses this endpoint allows the remote to
    /// advertise.
    ///
    /// Setting this to any nonzero value will enable Iroh's holepunching, loosely based in the Nat
    /// Traversal Extension for QUIC, see
    /// <https://www.ietf.org/archive/id/draft-seemann-quic-nat-traversal-02.html>
    ///
    /// This implementation expects the multipath extension to be enabled as well. If not yet
    /// enabled via [`Self::max_concurrent_multipath_paths`], a default value of
    /// 12 will be used.
    ///
    /// Note: this method will ignore values less than the recommended 12 and will log a warning.
    pub fn set_max_remote_nat_traversal_addresses(mut self, max_addresses: u8) -> Self {
        if max_addresses < MAX_MULTIPATH_PATHS as u8 {
            warn!(
                "QuicTransportConfig::max_remote_nat_traversal_addresses must be at least {}, ignoring user supplied value",
                MAX_MULTIPATH_PATHS
            );
            return self;
        }
        self.0.set_max_remote_nat_traversal_addresses(max_addresses);
        self
    }

    /// Configures qlog capturing by setting a [`QlogFactory`].
    ///
    /// This assigns a [`QlogFactory`] that produces qlog capture configurations for
    /// individual connections.
    #[cfg(feature = "qlog")]
    pub fn qlog_factory(mut self, factory: Arc<dyn QlogFactory>) -> Self {
        self.0.qlog_factory(factory);
        self
    }

    /// Configures qlog capturing through the `QLOGDIR` environment variable.
    ///
    /// This uses [`QlogFileFactory::from_env`] to create a factory to write qlog traces
    /// into the directory set through the `QLOGDIR` environment variable.
    ///
    /// If `QLOGDIR` is not set, no traces will be written. If `QLOGDIR` is set to a path
    /// that does not exist, it will be created.
    ///
    /// The files will be prefixed with `prefix`.
    #[cfg(feature = "qlog")]
    pub fn qlog_from_env(mut self, prefix: &str) -> Self {
        self.0.qlog_from_env(prefix);
        self
    }

    /// Configures qlog capturing into a directory.
    ///
    /// This uses [`QlogFileFactory`] to create a factory to write qlog traces into
    /// the specified directory.  The files will be prefixed with `prefix`.
    #[cfg(feature = "qlog")]
    pub fn qlog_from_path(mut self, path: impl AsRef<Path>, prefix: &str) -> Self {
        self.0.qlog_from_path(path, prefix);
        self
    }
}

/// A builder for a [`ServerConfig`].
#[derive(Debug, Clone)]
pub struct ServerConfigBuilder {
    inner: quinn::ServerConfig,
    transport: QuicTransportConfig,
}

/// Parameters governing incoming connections
///
/// Default values should be suitable for most internet applications.
///
/// Use a [`ServerConfigBuilder`] to adjust the default values.
///
/// To create a [`ServerConfig`] compatible with your [`Endpoint`] identity, use the [`Endpoint::create_server_config_builder`] method.
///
/// [`Endpoint`]: crate::Endpoint
/// [`Endpoint::create_server_config_builder`]: crate::Endpoint::create_server_config_builder
// Note: used in `iroh::endpoint::connection::Incoming::accept_with`
// This is new-typed since `quinn::ServerConfig` takes a `TransportConfig`, which we new-type as a `QuicTransportConfig`
#[derive(Debug, Clone)]
pub struct ServerConfig(Arc<quinn::ServerConfig>);

impl ServerConfig {
    pub(crate) fn to_inner_arc(&self) -> Arc<quinn::ServerConfig> {
        self.0.clone()
    }
}

impl ServerConfigBuilder {
    /// Build a [`ServerConfig`] from a [`ServerConfigBuilder`].
    pub fn build(self) -> ServerConfig {
        ServerConfig(Arc::new(self.inner))
    }

    pub(crate) fn new(inner: quinn::ServerConfig, transport: QuicTransportConfig) -> Self {
        Self { inner, transport }
    }

    /// Sets a custom [`QuicTransportConfig`].
    pub fn set_transport_config(mut self, transport: QuicTransportConfig) -> Self {
        self.inner.transport_config(transport.to_inner_arc());
        self.transport = transport;
        self
    }

    /// Sets a custom [`ValidationTokenConfig`].
    pub fn set_validation_token_config(mut self, validation_token: ValidationTokenConfig) -> Self {
        self.inner.validation_token_config(validation_token);
        self
    }

    /// Private key used to authenticate data included in handshake tokens
    pub fn set_token_key(mut self, value: Arc<dyn HandshakeTokenKey>) -> Self {
        self.inner.token_key(value);
        self
    }

    /// Duration after a retry token was issued for which it's considered valid
    ///
    /// Defaults to 15 seconds.
    pub fn set_retry_token_lifetime(mut self, value: Duration) -> Self {
        self.inner.retry_token_lifetime(value);
        self
    }

    /// Maximum number of [`Incoming`] to allow to exist at a time.
    ///
    /// An [`Incoming`] comes into existence when an incoming connection attempt
    /// is received and stops existing when the application either accepts it or otherwise disposes
    /// of it. While this limit is reached, new incoming connection attempts are immediately
    /// refused. Larger values have greater worst-case memory consumption, but accommodate greater
    /// application latency in handling incoming connection attempts.
    ///
    /// The default value is set to 65536. With a typical Ethernet MTU of 1500 bytes, this limits
    /// memory consumption from this to under 100 MiB--a generous amount that still prevents memory
    /// exhaustion in most contexts.
    ///
    /// [`Incoming`]: crate::endpoint::Incoming
    pub fn set_max_incoming(mut self, max_incoming: usize) -> Self {
        self.inner.max_incoming(max_incoming);
        self
    }

    /// Maximum number of received bytes to buffer for each [`Incoming`].
    ///
    /// An [`Incoming`] comes into existence when an incoming connection attempt
    /// is received and stops existing when the application either accepts it or otherwise disposes
    /// of it. This limit governs only packets received within that period, and does not include
    /// the first packet. Packets received in excess of this limit are dropped, which may cause
    /// 0-RTT or handshake data to have to be retransmitted.
    ///
    /// The default value is set to 10 MiB--an amount such that in most situations a client would
    /// not transmit that much 0-RTT data faster than the server handles the corresponding
    /// [`Incoming`].
    ///
    /// [`Incoming`]: crate::endpoint::Incoming
    pub fn set_incoming_buffer_size(mut self, incoming_buffer_size: u64) -> Self {
        self.inner.incoming_buffer_size(incoming_buffer_size);
        self
    }

    /// Maximum number of received bytes to buffer for all [`Incoming`]
    /// collectively.
    ///
    /// An [`Incoming`] comes into existence when an incoming connection attempt
    /// is received and stops existing when the application either accepts it or otherwise disposes
    /// of it. This limit governs only packets received within that period, and does not include
    /// the first packet. Packets received in excess of this limit are dropped, which may cause
    /// 0-RTT or handshake data to have to be retransmitted.
    ///
    /// The default value is set to 100 MiB--a generous amount that still prevents memory
    /// exhaustion in most contexts.
    ///
    /// [`Incoming`]: crate::endpoint::Incoming
    pub fn set_incoming_buffer_size_total(mut self, incoming_buffer_size_total: u64) -> Self {
        self.inner
            .incoming_buffer_size_total(incoming_buffer_size_total);
        self
    }

    /// Object to get current [`SystemTime`].
    ///
    /// This exists to allow system time to be mocked in tests, or wherever else desired.
    ///
    /// Defaults to [`quinn::StdSystemTime`], which simply calls [`SystemTime::now()`](std::time::SystemTime::now).
    ///
    /// [`SystemTime`]: std::time::SystemTime
    pub fn set_time_source(mut self, time_source: Arc<dyn TimeSource>) -> Self {
        self.inner.time_source(time_source);
        self
    }
}
