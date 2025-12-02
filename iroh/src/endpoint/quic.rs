//! Exporting and encapsulating structs from quinn
//!
//! This is necessary for two reasons:
//! 1) There are some structs that we use in particular ways, where we would like
//!    to limit or expand how those structs are used in iroh. By encapsulating them
//!    we can ensure the functionality needed to make iroh work.
//! 2) quinn is not yet at 1.0, we need to ensure that the iroh API remains stable
//!    even as quinn changes.

// TODO: encapsulate structs
// Missing still: SendDatagram and ConnectionClose::frame_type's Type.
pub use quinn::{
    AcceptBi, AcceptUni, AckFrequencyConfig, ApplicationClose, Chunk, ClosedStream,
    ConnectionClose, ConnectionError, ConnectionStats, MtuDiscoveryConfig, OpenBi, OpenUni,
    PathStats, ReadDatagram, ReadError, ReadExactError, ReadToEndError, RecvStream, ResetError,
    RetryError, SendDatagramError, SendStream, ServerConfig, StoppedError, StreamId,
    TransportConfig, VarInt, WeakConnectionHandle, WriteError,
};
pub use quinn_proto::{
    FrameStats, TransportError, TransportErrorCode, UdpStats, Written,
    congestion::{Controller, ControllerFactory},
    crypto::{
        AeadKey, CryptoError, ExportKeyingMaterialError, HandshakeTokenKey,
        ServerConfig as CryptoServerConfig, UnsupportedVersion,
    },
};
