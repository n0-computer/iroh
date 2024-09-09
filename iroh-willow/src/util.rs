//! Various utilities and data structures used in this crate.

pub mod channel;
pub mod codec;
pub mod codec2;
pub mod gen_stream;
pub mod pipe;
pub mod queue;
pub mod stream;
pub mod time;

/// Increment a fixed-length byte string by one, by incrementing the last byte that is not 255 by one.
///
/// Returns None if all bytes are 255.
pub fn increment_by_one<const N: usize>(value: &[u8; N]) -> Option<[u8; N]> {
    let mut out = *value;
    for char in out.iter_mut().rev() {
        if *char != 255 {
            *char += 1;
            return Some(out);
        } else {
            *char = 0;
        }
    }
    None
}
