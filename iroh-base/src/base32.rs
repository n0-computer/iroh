pub use data_encoding::{DecodeError, DecodeKind};
use hex::FromHexError;

/// Convert to a base32 string
pub fn fmt(bytes: impl AsRef<[u8]>) -> String {
    let mut text = data_encoding::BASE32_NOPAD.encode(bytes.as_ref());
    text.make_ascii_lowercase();
    text
}

/// Convert to a base32 string and append out `out`
pub fn fmt_append(bytes: impl AsRef<[u8]>, out: &mut String) {
    let start = out.len();
    data_encoding::BASE32_NOPAD.encode_append(bytes.as_ref(), out);
    let end = out.len();
    out[start..end].make_ascii_lowercase();
}

/// Convert to a base32 string limited to the first 10 bytes
pub fn fmt_short(bytes: impl AsRef<[u8]>) -> String {
    let len = bytes.as_ref().len().min(10);
    let mut text = data_encoding::BASE32_NOPAD.encode(&bytes.as_ref()[..len]);
    text.make_ascii_lowercase();
    text
}

/// Parse from a base32 string into a byte array
pub fn parse_array<const N: usize>(input: &str) -> Result<[u8; N], DecodeError> {
    data_encoding::BASE32_NOPAD
        .decode(input.to_ascii_uppercase().as_bytes())?
        .try_into()
        .map_err(|_| DecodeError {
            position: N,
            kind: DecodeKind::Length,
        })
}

/// Decode form a base32 string to a vector of bytes
pub fn parse_vec(input: &str) -> Result<Vec<u8>, DecodeError> {
    data_encoding::BASE32_NOPAD.decode(input.to_ascii_uppercase().as_bytes())
}

/// Error when parsing a hex or base32 string.
#[derive(thiserror::Error, Debug)]
pub enum HexOrBase32ParseError {
    /// Error when decoding the base32.
    #[error("base32: {0}")]
    Base32(#[from] data_encoding::DecodeError),
    /// Error when decoding the public key.
    #[error("hex: {0}")]
    Hex(#[from] FromHexError),
}

/// Parse a fixed length hex or base32 string into a byte array
///
/// For fixed length we can know the encoding by the length of the string.
pub fn parse_array_hex_or_base32<const LEN: usize>(
    input: &str,
) -> std::result::Result<[u8; LEN], HexOrBase32ParseError> {
    let mut bytes = [0u8; LEN];
    if input.len() == LEN * 2 {
        hex::decode_to_slice(input, &mut bytes)?;
        Ok(bytes)
    } else {
        Ok(parse_array(input)?)
    }
}
