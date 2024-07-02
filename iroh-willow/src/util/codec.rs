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

pub fn compact_width(value: u64) -> u8 {
    if value < 256 {
        1
    } else if value < 256u64.pow(2) {
        2
    } else if value < 256u64.pow(4) {
        4
    } else {
        8
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CompactWidth(pub u64);

impl CompactWidth {
    fn len(self) -> u8 {
        compact_width(self.0)
    }
}

impl Encoder for CompactWidth {
    fn encoded_len(&self) -> usize {
        self.len() as usize
    }

    fn encode_into<W: io::Write>(&self, out: &mut W) -> anyhow::Result<()> {
        match self.len() {
            1 => out.write_all(&(self.0 as u8).to_be_bytes())?,
            2 => out.write_all(&(self.0 as u16).to_be_bytes())?,
            4 => out.write_all(&(self.0 as u32).to_be_bytes())?,
            8 => out.write_all(&self.0.to_be_bytes())?,
            _ => unreachable!("len is always one of the above"),
        };
        Ok(())
    }
}
