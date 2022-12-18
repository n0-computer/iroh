use std::io;

use bytes::{Bytes, BytesMut};
use futures::{stream::BoxStream, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Default size for chunks.
pub const DEFAULT_CHUNKS_SIZE: usize = 1024 * 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixed {
    pub chunk_size: usize,
}

impl Default for Fixed {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNKS_SIZE,
        }
    }
}

impl Fixed {
    pub fn new(chunk_size: usize) -> Self {
        assert!(chunk_size > 0);

        Self { chunk_size }
    }

    pub fn chunks<'a, R: AsyncRead + Unpin + Send + 'a>(
        self,
        mut source: R,
    ) -> BoxStream<'a, io::Result<Bytes>> {
        let chunk_size = self.chunk_size;
        async_stream::stream! {
            let mut buffer = BytesMut::with_capacity(chunk_size);
            let mut current_len = 0;

            loop {
                if current_len == 0 {
                    buffer.clear();
                }
                match source.read_buf(&mut buffer).await {
                    Ok(len) => {
                        current_len += len;
                        if current_len == chunk_size {
                            // read a full chunk
                            current_len = 0;
                            yield Ok(buffer.clone().freeze());
                        } else if current_len < chunk_size && len > 0 {
                            // not done reading, read again
                            continue;
                        } else if current_len > chunk_size {
                            // read more than a chunk, emit only a single chunk
                            let out = buffer.split_to(chunk_size);
                            current_len -= chunk_size;
                            yield Ok(out.freeze());
                        } else {
                            // finished reading
                            debug_assert!(len == 0);
                            if current_len > 0 {
                                yield Ok(buffer.clone().freeze());
                            }
                            break;
                        }
                    }
                    Err(err) => {
                        yield Err(err);
                    }
                }
            }
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use futures::TryStreamExt;

    use super::*;

    #[tokio::test]
    async fn test_fixed_chunker() {
        // exact match
        {
            let mut content = Vec::with_capacity(1024);
            content.resize(256, 1);
            content.resize(512, 2);
            content.resize(768, 3);
            content.resize(1024, 4);
            let bytes = std::io::Cursor::new(content);

            let chunks: Vec<_> = Fixed::new(256).chunks(bytes).try_collect().await.unwrap();
            assert_eq!(chunks.len(), 4);
            assert_eq!(&chunks[0], &[1u8; 256][..]);
            assert_eq!(&chunks[1], &[2u8; 256][..]);
            assert_eq!(&chunks[2], &[3u8; 256][..]);
            assert_eq!(&chunks[3], &[4u8; 256][..]);
        }

        // overflow
        {
            let mut content = Vec::with_capacity(1024);
            content.resize(256, 1);
            content.resize(512, 2);
            content.resize(768, 3);
            content.resize(1024, 4);
            content.push(5);
            content.push(5);

            let bytes = std::io::Cursor::new(content);
            let chunks: Vec<_> = Fixed::new(256).chunks(bytes).try_collect().await.unwrap();
            assert_eq!(chunks.len(), 5);
            assert_eq!(&chunks[0], &[1u8; 256][..]);
            assert_eq!(&chunks[1], &[2u8; 256][..]);
            assert_eq!(&chunks[2], &[3u8; 256][..]);
            assert_eq!(&chunks[3], &[4u8; 256][..]);
            assert_eq!(&chunks[4], &[5u8; 2][..]);
        }
    }
}
