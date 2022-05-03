use cid::Cid;
use integer_encoding::VarIntAsyncReader;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::error::Error;
pub(crate) async fn ld_read<R>(mut reader: R, buf: &mut Vec<u8>) -> Result<bool, Error>
where
    R: AsyncRead + Send + Unpin,
{
    let l: usize = match VarIntAsyncReader::read_varint_async(&mut reader).await {
        Ok(len) => len,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(false);
            }
            return Err(Error::Parsing(e.to_string()));
        }
    };

    buf.clear();
    reader
        .take(l as u64)
        .read_to_end(buf)
        .await
        .map_err(|e| Error::Parsing(e.to_string()))?;
    Ok(true)
}

pub(crate) async fn read_node<R>(
    buf_reader: &mut R,
    buf: &mut Vec<u8>,
) -> Result<Option<(Cid, Vec<u8>)>, Error>
where
    R: AsyncRead + Send + Unpin,
{
    if ld_read(buf_reader, buf).await? {
        let mut cursor = std::io::Cursor::new(&buf);
        let c = Cid::read_bytes(&mut cursor)?;
        let pos = cursor.position() as usize;

        return Ok(Some((c, buf[pos..].to_vec())));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use integer_encoding::VarIntAsyncWriter;
    use tokio::io::{AsyncWrite, AsyncWriteExt};

    use super::*;

    async fn ld_write<'a, W>(writer: &mut W, bytes: &[u8]) -> Result<(), Error>
    where
        W: AsyncWrite + Send + Unpin,
    {
        writer.write_varint_async(bytes.len()).await?;
        writer.write_all(bytes).await?;
        writer.flush().await?;
        Ok(())
    }

    #[tokio::test]
    async fn ld_read_write() {
        let mut buffer = Vec::<u8>::new();
        ld_write(&mut buffer, b"test bytes").await.unwrap();
        let reader = std::io::Cursor::new(buffer);
        let mut buffer = Vec::new();
        let read = ld_read(reader, &mut buffer).await.unwrap();
        assert!(read);
        assert_eq!(&buffer, b"test bytes");
    }
}
