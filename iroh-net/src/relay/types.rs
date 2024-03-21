use std::num::NonZeroU32;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};

use super::{client_conn::ClientConnBuilder, codec::PROTOCOL_VERSION};
use crate::key::PublicKey;

pub(crate) struct RateLimiter {
    inner: governor::RateLimiter<
        governor::state::direct::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::DefaultClock,
        governor::middleware::NoOpMiddleware,
    >,
}

impl RateLimiter {
    pub(crate) fn new(bytes_per_second: usize, bytes_burst: usize) -> Result<Option<Self>> {
        if bytes_per_second == 0 || bytes_burst == 0 {
            return Ok(None);
        }
        let bytes_per_second = NonZeroU32::new(u32::try_from(bytes_per_second)?)
            .context("bytes_per_second not non-zero")?;
        let bytes_burst =
            NonZeroU32::new(u32::try_from(bytes_burst)?).context("bytes_burst not non-zero")?;
        Ok(Some(Self {
            inner: governor::RateLimiter::direct(
                governor::Quota::per_second(bytes_per_second).allow_burst(bytes_burst),
            ),
        }))
    }

    pub(crate) fn check_n(&self, n: usize) -> Result<()> {
        let n = NonZeroU32::new(u32::try_from(n)?).context("n not non-zero")?;
        match self.inner.check_n(n) {
            Ok(_) => Ok(()),
            Err(_) => bail!("batch cannot go through"),
        }
    }
}

/// A request to write a dataframe to a Client
#[derive(Debug, Clone)]
pub(crate) struct Packet {
    /// The sender of the packet
    pub(crate) src: PublicKey,
    /// The data packet bytes.
    pub(crate) bytes: Bytes,
}

#[derive(Debug, Serialize, Deserialize, MaxSize, PartialEq, Eq)]
pub(crate) struct ClientInfo {
    /// The DERP protocol version that the client was built with.
    /// See [`PROTOCOL_VERSION`].
    pub(crate) version: usize,
    /// Unused field, ignored by the relay server.
    pub(crate) mesh_key: Option<[u8; 32]>,
    /// Whether the client declares it's able to ack pings
    pub(crate) can_ack_pings: bool,
    /// Whether this client is a prober.
    pub(crate) is_prober: bool,
}

/// The information we send to the [`super::client::Client`] about the [`super::server::Server`]'s
/// protocol version & rate limiting
///
/// If either `token_bucket_bytes_per_second` or `token_bucket_bytes_burst` is 0, there is no rate
/// limit.
#[derive(Debug, Clone, Serialize, Deserialize, MaxSize)]
pub(crate) struct ServerInfo {
    pub(crate) version: usize,
    pub(crate) token_bucket_bytes_per_second: usize,
    pub(crate) token_bucket_bytes_burst: usize,
}

impl ServerInfo {
    /// Specifies the server requires no rate limit
    pub fn no_rate_limit() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            token_bucket_bytes_burst: 0,
            token_bucket_bytes_per_second: 0,
        }
    }
}

#[derive(derive_more::Debug)]
pub(crate) enum ServerMessage {
    SendPacket((PublicKey, Packet)),
    SendDiscoPacket((PublicKey, Packet)),
    #[debug("CreateClient")]
    CreateClient(ClientConnBuilder),
    RemoveClient((PublicKey, usize)),
    Shutdown,
}
