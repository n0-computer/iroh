//! Encoding and decoding of the data associated with an [`Opcode`].

use super::Opcode;

/// Data associated to an [`Opcode`]
#[derive(Debug, PartialEq, Eq)]
pub enum OpcodeData {
    /// Data for an [`Opcode::Announce`] request.
    Announce,
}

#[derive(Debug)]
pub struct InvalidOpcodeData;

impl OpcodeData {
    /// Get the associated [`Opcode`].
    pub fn opcode(&self) -> Opcode {
        match self {
            OpcodeData::Announce => Opcode::Announce,
        }
    }

    /// Encode this [`OpcodeData`] into the buffer.
    pub fn encode_into(&self, _buf: &mut [u8]) {
        match self {
            OpcodeData::Announce => {}
        }
    }

    /// Exact size an encoded [`OpcodeData`] will have.
    pub const fn encoded_size(&self) -> usize {
        match self {
            OpcodeData::Announce => 0,
        }
    }

    pub fn decode(opcode: Opcode, _buf: &[u8]) -> Result<Self, InvalidOpcodeData> {
        match opcode {
            Opcode::Announce => Ok(OpcodeData::Announce),
        }
    }

    #[cfg(test)]
    pub(crate) fn random<R: rand::Rng>(opcode: Opcode, _rng: &mut R) -> OpcodeData {
        match opcode {
            Opcode::Announce => OpcodeData::Announce,
        }
    }
}
