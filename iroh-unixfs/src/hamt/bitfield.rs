use anyhow::{ensure, Result};

pub const BITWIDTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct Bitfield([u64; BITWIDTH / 64]);

impl Bitfield {
    pub fn as_bytes(&self) -> [u8; BITWIDTH / 8] {
        let mut v = [0u8; BITWIDTH / 8];
        // Big endian ordering, to match go
        v[..8].copy_from_slice(&self.0[3].to_be_bytes());
        v[8..16].copy_from_slice(&self.0[2].to_be_bytes());
        v[16..24].copy_from_slice(&self.0[1].to_be_bytes());
        v[24..].copy_from_slice(&self.0[0].to_be_bytes());

        v
    }

    pub fn from_bytes(arr: [u8; BITWIDTH / 8]) -> Result<Self> {
        let mut res = Bitfield::zero();

        res.0[3] = u64::from_be_bytes(arr[..8].try_into()?);
        res.0[2] = u64::from_be_bytes(arr[8..16].try_into()?);
        res.0[1] = u64::from_be_bytes(arr[16..24].try_into()?);
        res.0[0] = u64::from_be_bytes(arr[24..].try_into()?);

        Ok(res)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 32, "bitfield too large {}", bytes.len());
        let mut arr = [0u8; BITWIDTH / 8];
        arr[32 - bytes.len()..].copy_from_slice(bytes);

        Self::from_bytes(arr)
    }
}

impl Default for Bitfield {
    fn default() -> Self {
        Bitfield::zero()
    }
}

impl Bitfield {
    pub fn clear_bit(&mut self, idx: u32) {
        let ai = idx / 64;
        let bi = idx % 64;
        self.0[ai as usize] &= u64::MAX - (1 << bi);
    }

    pub fn test_bit(&self, idx: u32) -> bool {
        let ai = idx / 64;
        let bi = idx % 64;

        self.0[ai as usize] & (1 << bi) != 0
    }

    pub fn set_bit(&mut self, idx: u32) {
        let ai = idx / 64;
        let bi = idx % 64;

        self.0[ai as usize] |= 1 << bi;
    }

    pub fn count_ones(&self) -> usize {
        self.0.iter().map(|a| a.count_ones() as usize).sum()
    }

    pub fn and(self, other: &Self) -> Self {
        Bitfield([
            self.0[0] & other.0[0],
            self.0[1] & other.0[1],
            self.0[2] & other.0[2],
            self.0[3] & other.0[3],
        ])
    }

    pub fn zero() -> Self {
        Bitfield([0, 0, 0, 0])
    }

    pub fn set_bits_le(self, bit: u32) -> Self {
        if bit == 0 {
            return self;
        }
        self.set_bits_leq(bit - 1)
    }

    pub fn set_bits_leq(mut self, bit: u32) -> Self {
        if bit < 64 {
            self.0[0] = set_bits_leq(self.0[0], bit);
        } else if bit < 128 {
            self.0[0] = std::u64::MAX;
            self.0[1] = set_bits_leq(self.0[1], bit - 64);
        } else if bit < 192 {
            self.0[0] = std::u64::MAX;
            self.0[1] = std::u64::MAX;
            self.0[2] = set_bits_leq(self.0[2], bit - 128);
        } else {
            self.0[0] = std::u64::MAX;
            self.0[1] = std::u64::MAX;
            self.0[2] = std::u64::MAX;
            self.0[3] = set_bits_leq(self.0[3], bit - 192);
        }

        self
    }
}

#[inline]
fn set_bits_leq(v: u64, bit: u32) -> u64 {
    (v as u128 | ((1u128 << (1 + bit)) - 1)) as u64
}

impl std::fmt::Binary for Bitfield {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let val = self.0;

        write!(f, "{:b}_{:b}_{:b}_{:b}", val[0], val[1], val[2], val[3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitfield() {
        let mut b = Bitfield::zero();
        b.set_bit(8);
        b.set_bit(18);
        b.set_bit(92);
        b.set_bit(255);
        assert!(b.test_bit(8));
        assert!(b.test_bit(18));
        assert!(!b.test_bit(19));
        assert!(b.test_bit(92));
        assert!(!b.test_bit(95));
        assert!(b.test_bit(255));

        b.clear_bit(18);
        assert!(!b.test_bit(18));
    }

    #[test]
    fn test_serialization() {
        let mut b0 = Bitfield::zero();
        let bz = b0.as_bytes();
        assert_eq!(&bz[..], &[0; 32]);
        assert_eq!(Bitfield::from_bytes(bz).unwrap(), b0);

        b0.set_bit(0);
        let bz = b0.as_bytes();
        let mut expected = [0; 32];
        expected[31] = 0b0000_0001;
        assert_eq!(&bz[..], &expected);
        assert_eq!(Bitfield::from_bytes(bz).unwrap(), b0);

        b0.set_bit(64);
        let bz = b0.as_bytes();
        expected[23] = 0b0000_0001;

        assert_eq!(&bz[..], &expected);
        assert_eq!(Bitfield::from_bytes(bz).unwrap(), b0);
    }
}
