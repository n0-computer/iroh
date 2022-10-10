use cid::Cid;
use ipld::codec::Codec;
use ipld_cbor::DagCborCodec;

use crate::error::Error;

/// A car header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CarHeader {
    V1(CarHeaderV1),
}

impl CarHeader {
    pub fn new_v1(roots: Vec<Cid>) -> Self {
        Self::V1(roots.into())
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, Error> {
        let header: CarHeaderV1 = DagCborCodec
            .decode(buffer)
            .map_err(|e| Error::Parsing(e.to_string()))?;

        if header.roots.is_empty() {
            return Err(Error::Parsing("empty CAR file".to_owned()));
        }

        if header.version != 1 {
            return Err(Error::InvalidFile(
                "Only CAR file version 1 is supported".to_string(),
            ));
        }

        Ok(CarHeader::V1(header))
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        match self {
            CarHeader::V1(ref header) => {
                let res = DagCborCodec.encode(header)?;
                Ok(res)
            }
        }
    }

    pub fn roots(&self) -> &[Cid] {
        match self {
            CarHeader::V1(header) => &header.roots,
        }
    }

    pub fn version(&self) -> u64 {
        match self {
            CarHeader::V1(_) => 1,
        }
    }
}

/// CAR file header version 1.
#[derive(Debug, Clone, Default, ipld::DagCbor, PartialEq, Eq)]
pub struct CarHeaderV1 {
    #[ipld]
    pub roots: Vec<Cid>,
    #[ipld]
    pub version: u64,
}

impl CarHeaderV1 {
    /// Creates a new CAR file header
    pub fn new(roots: Vec<Cid>, version: u64) -> Self {
        Self { roots, version }
    }
}

impl From<Vec<Cid>> for CarHeaderV1 {
    fn from(roots: Vec<Cid>) -> Self {
        Self { roots, version: 1 }
    }
}

#[cfg(test)]
mod tests {
    use ipld::codec::{Decode, Encode};
    use ipld_cbor::DagCborCodec;
    use multihash::MultihashDigest;

    use super::*;

    #[test]
    fn symmetric_header_v1() {
        let digest = multihash::Code::Blake2b256.digest(b"test");
        let cid = Cid::new_v1(DagCborCodec.into(), digest);

        let header = CarHeaderV1::from(vec![cid]);

        let mut bytes = Vec::new();
        header.encode(DagCborCodec, &mut bytes).unwrap();

        assert_eq!(
            CarHeaderV1::decode(DagCborCodec, &mut std::io::Cursor::new(&bytes)).unwrap(),
            header
        );
    }
}
