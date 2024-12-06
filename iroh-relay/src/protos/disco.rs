//! This module exports [`looks_like_disco_wrapper`] as the only disco-related relay
//! functionality.
//!
//! Despite the relay not being able to read disco messages by design, it does attempt to
//! identify this traffic to ensure hole-punching messages are not lost do to congestion.

/// The 6 byte header of all discovery messages.
pub const MAGIC: &str = "TS💬"; // 6 bytes: 0x54 53 f0 9f 92 ac
pub(crate) const MAGIC_LEN: usize = MAGIC.as_bytes().len();
pub(crate) const KEY_LEN: usize = 32;

const MESSAGE_HEADER_LEN: usize = MAGIC_LEN + KEY_LEN;

/// Reports whether p looks like it's a packet containing an encrypted disco message.
pub fn looks_like_disco_wrapper(p: &[u8]) -> bool {
    if p.len() < MESSAGE_HEADER_LEN {
        return false;
    }

    &p[..MAGIC_LEN] == MAGIC.as_bytes()
}
