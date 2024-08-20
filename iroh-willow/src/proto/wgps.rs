//! Types and helpers for the Willow General Purpose Sync protocol.

mod challenge;
mod channels;
mod fingerprint;
mod handles;
mod messages;

pub use challenge::*;
pub use channels::*;
pub use fingerprint::*;
pub use handles::*;
pub use messages::*;

pub const MAX_PAYLOAD_SIZE_POWER: u8 = 18;

/// The maximum payload size limits when the other peer may include Payloads directly when transmitting Entries:
/// when an Entry’s payload_length is strictly greater than the maximum payload size,
/// its Payload may only be transmitted when explicitly requested.
///
/// The value is 256KiB.
pub const MAX_PAYLOAD_SIZE: usize = 2usize.pow(MAX_PAYLOAD_SIZE_POWER as u32);
