//! Traits for encoding and decoding values to and from bytes.

use std::{fmt, io};

/// Trait for encoding values into bytes.
pub trait Encoder: fmt::Debug {
    /// Returns the length (in bytes) of the encoded value.
    fn encoded_len(&self) -> usize;

    /// Encode [`Self`] into a writable buffer which implements `io::Write`.
    fn encode_into<W: io::Write>(&self, out: &mut W) -> anyhow::Result<()>;

    /// Encode [`Self`] into a vector of bytes.
    fn encode(&self) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut out)?;
        Ok(out)
    }
}

/// Trait for decoding values from bytes.
pub trait Decoder: Sized {
    /// Decode [`Self`] from a byte slice.
    fn decode_from(data: &[u8]) -> anyhow::Result<DecodeOutcome<Self>>;
}

/// The outcome of [`Decoder::decode_from`]
#[derive(Debug)]
pub enum DecodeOutcome<T> {
    /// Not enough data to decode the value.
    NeedMoreData,
    /// Decoded a value.
    Decoded {
        /// The decoded value.
        item: T,
        /// The number of bytes used for decoding the value.
        consumed: usize,
    },
}
