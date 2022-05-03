use futures::Stream;
use tokio::io::AsyncRead;

use crate::{
    error::Error,
    header::CarHeader,
    util::{ld_read, read_node},
    Block,
};

/// Reads CAR files that are in a BufReader
pub struct CarReader<R> {
    reader: R,
    header: CarHeader,
    buffer: Vec<u8>,
}

impl<R> CarReader<R>
where
    R: AsyncRead + Send + Unpin,
{
    /// Creates a new CarReader and parses the CarHeader
    pub async fn new(mut reader: R) -> Result<Self, Error> {
        let mut buffer = Vec::new();

        if !ld_read(&mut reader, &mut buffer).await? {
            return Err(Error::Parsing(
                "failed to parse uvarint for header".to_string(),
            ));
        }

        let header = CarHeader::decode(&buffer)?;

        Ok(CarReader {
            reader,
            header,
            buffer,
        })
    }

    /// Returns the header of this car file.
    pub fn header(&self) -> &CarHeader {
        &self.header
    }

    /// Returns the next IPLD Block in the buffer
    pub async fn next_block(&mut self) -> Result<Option<Block>, Error> {
        read_node(&mut self.reader, &mut self.buffer).await
    }

    pub fn stream(self) -> impl Stream<Item = Result<Block, Error>> {
        futures::stream::try_unfold(self, |mut this| async move {
            let maybe_block = read_node(&mut this.reader, &mut this.buffer).await?;
            Ok(maybe_block.map(|b| (b, this)))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use cid::Cid;
    use futures::TryStreamExt;
    use ipld_cbor::DagCborCodec;
    use multihash::MultihashDigest;

    use crate::{header::CarHeaderV1, writer::CarWriter};

    use super::*;

    #[tokio::test]
    async fn car_write_read() {
        let digest_test = multihash::Code::Blake2b256.digest(b"test");
        let cid_test = Cid::new_v1(DagCborCodec.into(), digest_test);

        let digest_foo = multihash::Code::Blake2b256.digest(b"foo");
        let cid_foo = Cid::new_v1(DagCborCodec.into(), digest_foo);

        let header = CarHeader::V1(CarHeaderV1::from(vec![cid_foo]));

        let mut buffer = Vec::new();
        let mut writer = CarWriter::new(header, &mut buffer);
        writer.write(cid_test, b"test").await.unwrap();
        writer.write(cid_foo, b"foo").await.unwrap();
        writer.finish().await.unwrap();

        let reader = Cursor::new(&buffer);
        let car_reader = CarReader::new(reader).await.unwrap();
        let files: Vec<Block> = car_reader.stream().try_collect().await.unwrap();

        assert_eq!(files.len(), 2);
        assert_eq!(files[0].cid, cid_test);
        assert_eq!(files[0].data, b"test");
        assert_eq!(files[1].cid, cid_foo);
        assert_eq!(files[1].data, b"foo");
    }
}
