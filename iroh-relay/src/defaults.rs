//! Default values used in the relay.

/// The default QUIC port used by the Relay server to accept QUIC connections
/// for QUIC address discovery
///
/// The port is "QUIC" typed on a phone keypad.
pub const DEFAULT_RELAY_QUIC_PORT: u16 = 7842;

/// The default HTTP port used by the Relay server.
pub const DEFAULT_HTTP_PORT: u16 = 80;

/// The default HTTPS port used by the Relay server.
pub const DEFAULT_HTTPS_PORT: u16 = 443;

/// The default metrics port used by the Relay server.
pub const DEFAULT_METRICS_PORT: u16 = 9090;

/// The default capacity of the key cache for the relay server.
///
/// Sized for 1 million concurrent clients.
/// memory usage will be (32 + 8 + 8 + 8) * 1_000_000 = 56MB on 64 bit,
/// which seems reasonable for a server.
pub const DEFAULT_KEY_CACHE_CAPACITY: usize = 1024 * 1024;

/// Contains all timeouts that we use in `iroh`.
#[cfg(not(wasm_browser))]
pub(crate) mod timeouts {
    use n0_future::time::Duration;

    /// Timeout used by the relay client while connecting to the relay server,
    /// using `TcpStream::connect`
    pub(crate) const DIAL_ENDPOINT_TIMEOUT: Duration = Duration::from_millis(1500);
    /// Timeout for our async dns resolver
    pub(crate) const DNS_TIMEOUT: Duration = Duration::from_secs(1);

    /// Maximum time the server will attempt to get a successful write to the connection.
    #[cfg(feature = "server")]
    pub(crate) const SERVER_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
}
