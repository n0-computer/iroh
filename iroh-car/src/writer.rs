use cid::Cid;
use integer_encoding::VarIntAsyncWriter;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{error::Error, header::CarHeader};

#[derive(Debug)]
pub struct CarWriter<W> {
    header: CarHeader,
    writer: W,
    cid_buffer: Vec<u8>,
    is_header_written: bool,
}

impl<W> CarWriter<W>
where
    W: AsyncWrite + Send + Unpin,
{
    pub fn new(header: CarHeader, writer: W) -> Self {
        CarWriter {
            header,
            writer,
            cid_buffer: Vec::new(),
            is_header_written: false,
        }
    }

    /// Writes header and stream of data to writer in Car format.
    pub async fn write<T>(&mut self, cid: Cid, data: T) -> Result<(), Error>
    where
        T: AsRef<[u8]>,
    {
        if !self.is_header_written {
            // Write header bytes
            let header_bytes = self.header.encode()?;
            self.writer.write_varint_async(header_bytes.len()).await?;
            self.writer.write_all(&header_bytes).await?;
            self.is_header_written = true;
        }

        // Write the given block.
        self.cid_buffer.clear();
        cid.write_bytes(&mut self.cid_buffer).expect("vec write");

        let data = data.as_ref();
        let len = self.cid_buffer.len() + data.len();

        self.writer.write_varint_async(len).await?;
        self.writer.write_all(&self.cid_buffer).await?;
        self.writer.write_all(data).await?;

        Ok(())
    }

    /// Finishes writing, including flushing and returns the writer.
    pub async fn finish(mut self) -> Result<W, Error> {
        self.flush().await?;
        Ok(self.writer)
    }

    /// Flushes the underlying writer.
    pub async fn flush(&mut self) -> Result<(), Error> {
        self.writer.flush().await?;
        Ok(())
    }

    /// Consumes the [`CarWriter`] and returns the underlying writer.
    pub fn into_inner(self) -> W {
        self.writer
    }
}
