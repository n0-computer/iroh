//! WebRTC connection identification types.
//!
//! This module provides types for uniquely identifying WebRTC connections in the iroh network.
//! A WebRTC connection is uniquely identified by the combination of a [`NodeId`] and a
//! [`ChannelId`], represented by the [`WebRtcPort`] type.

use crate::NodeId;
use serde::{Deserialize, Serialize};

/// A unique identifier for a WebRTC connection.
///
/// In the iroh network, WebRTC connections are established between nodes and need to be
/// uniquely identified to handle multiple concurrent connections. A [`WebRtcPort`] combines
/// a [`NodeId`] (which identifies the peer node) with a [`ChannelId`] (which identifies
/// the specific channel/connection to that node).
///
/// This is particularly useful when:
/// - A node needs to maintain multiple WebRTC connections to the same peer
/// - Routing messages to specific WebRTC channels
/// - Managing connection lifecycle and cleanup
///
/// # Examples
///
/// ```rust
/// use iroh_base::{NodeId, WebRtcPort, ChannelId};
///
/// // Create a new WebRTC port identifier
/// let node_id = NodeId::from([1u8; 32]);
/// let channel_id = ChannelId::from(42);
/// let webrtc_port = WebRtcPort::new(node_id, channel_id);
///
/// println!("WebRTC connection: {}", webrtc_port);
/// // Output: WebRtcPort(NodeId(...), ChannelId(42))
/// ```
#[derive(Debug, derive_more::Display, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[display("WebRtcPort({}, {})", node_id, channel_id)]
pub struct WebRtcPort {
    /// The identifier of the peer node in this WebRTC connection.
    pub node_id: NodeId,
    /// The specific channel identifier for this WebRTC connection.
    pub channel_id: ChannelId,
}

impl PartialEq<WebRtcPort> for &mut WebRtcPort {
    fn eq(&self, other: &WebRtcPort) -> bool {
        self.eq(&other)
    }
}

impl WebRtcPort {
    /// Creates a new [`WebRtcPort`] from a node ID and channel ID.
    ///
    /// # Arguments
    ///
    /// * `node` - The [`NodeId`] of the peer node
    /// * `channel_id` - The [`ChannelId`] identifying the specific channel
    ///
    /// # Examples
    ///
    /// ```rust
    /// use iroh_base::{NodeId, WebRtcPort, ChannelId};
    ///
    /// let node_id = NodeId::from([1u8; 32]);
    /// let channel_id = ChannelId::from(42);
    /// let port = WebRtcPort::new(node_id, channel_id);
    /// ```
    pub fn new(node: NodeId, channel_id: ChannelId) -> Self {
        Self {
            node_id: node,
            channel_id,
        }
    }

    /// Returns the node ID of this WebRTC connection.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Returns the channel ID of this WebRTC connection.
    pub fn channel_id(&self) -> ChannelId {
        self.channel_id
    }
}

/// A unique identifier for a WebRTC channel.
///
/// [`ChannelId`] is used to distinguish between multiple WebRTC data channels or connections
/// to the same peer node. It's a 16-bit unsigned integer, allowing for up to 65,536 unique
/// channels per node pair.
///
/// The channel ID space is managed by the WebRTC implementation and should be:
/// - Unique per node pair during the lifetime of connections
/// - Reusable after connections are closed
/// - Assigned in a way that avoids collisions
///
/// # Examples
///
/// ```rust
/// use iroh_base::ChannelId;
///
/// // Create a channel ID
/// let channel = ChannelId::from(1234);
/// println!("Channel: {}", channel); // Output: ChannelId(1234)
///
/// // Channel IDs can be compared and ordered
/// let channel_a = ChannelId::from(1);
/// let channel_b = ChannelId::from(2);
/// assert!(channel_a < channel_b);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Copy, PartialOrd, Ord)]
pub struct ChannelId(u16);

impl ChannelId {
    /// Creates a new [`ChannelId`] from a `u16` value.
    ///
    /// # Arguments
    ///
    /// * `id` - The numeric channel identifier (0-65535)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use iroh_base::ChannelId;
    ///
    /// let channel = ChannelId::new(42);
    /// assert_eq!(channel.as_u16(), 42);
    /// ```
    pub fn new(id: u16) -> Self {
        Self(id)
    }

    /// Returns the numeric value of this channel ID.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use iroh_base::ChannelId;
    ///
    /// let channel = ChannelId::from(1234);
    /// assert_eq!(channel.as_u16(), 1234);
    /// ```
    pub fn as_u16(self) -> u16 {
        self.0
    }
}

impl From<u16> for ChannelId {
    /// Creates a [`ChannelId`] from a `u16` value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use iroh_base::ChannelId;
    ///
    /// let channel = ChannelId::from(42u16);
    /// assert_eq!(channel.as_u16(), 42);
    /// ```
    fn from(id: u16) -> Self {
        Self::new(id)
    }
}

impl From<ChannelId> for u16 {
    /// Converts a [`ChannelId`] to its numeric `u16` value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use iroh_base::ChannelId;
    ///
    /// let channel = ChannelId::from(42);
    /// let id: u16 = channel.into();
    /// assert_eq!(id, 42);
    /// ```
    fn from(channel: ChannelId) -> Self {
        channel.as_u16()
    }
}

impl std::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChannelId({})", self.0)
    }
}
