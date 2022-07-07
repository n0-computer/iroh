use std::io;

use bytes::BytesMut;
use futures::Stream;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Default size for chunks.
pub const DEFAULT_CHUNKS_SIZE: usize = 1024 * 256;

/// Chunks are limited to 1MiB by default
pub const DEFAULT_CHUNK_SIZE_LIMIT: usize = 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum Chunker {
    /// Chunker that splits the given content
    FixedSize { chunk_size: usize },
}

impl Chunker {
    pub fn fixed_size() -> Self {
        Self::fixed_with_size(DEFAULT_CHUNKS_SIZE)
    }

    pub fn fixed_with_size(size: usize) -> Self {
        Chunker::FixedSize { chunk_size: size }
    }

    pub fn chunks<'a, R: AsyncRead + Unpin + 'a>(
        &self,
        mut source: R,
    ) -> impl Stream<Item = io::Result<BytesMut>> + 'a {
        match self {
            Chunker::FixedSize { chunk_size } => {
                let chunk_size = *chunk_size;
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
                                    yield Ok(buffer.clone());
                                } else if current_len < chunk_size && len > 0 {
                                    // not done reading, read again
                                    continue;
                                } else if current_len > chunk_size {
                                    // read more than a chunk, emit only a single chunk
                                    let out = buffer.split_to(chunk_size);
                                    current_len -= chunk_size;
                                    yield Ok(out);
                                } else {
                                    // finished reading
                                    debug_assert!(len == 0);
                                    if current_len > 0 {
                                        yield Ok(buffer.clone());
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
            }
        }
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
            for _ in 0..256 {
                content.push(1);
            }
            for _ in 0..256 {
                content.push(2);
            }
            for _ in 0..256 {
                content.push(3);
            }
            for _ in 0..256 {
                content.push(4);
            }
            let bytes = std::io::Cursor::new(content);

            let chunker = Chunker::fixed_with_size(256);
            let chunks: Vec<_> = chunker.chunks(bytes).try_collect().await.unwrap();
            assert_eq!(chunks.len(), 4);
            assert_eq!(&chunks[0], &[1u8; 256][..]);
            assert_eq!(&chunks[1], &[2u8; 256][..]);
            assert_eq!(&chunks[2], &[3u8; 256][..]);
            assert_eq!(&chunks[3], &[4u8; 256][..]);
        }

        // overflow
        {
            let mut content = Vec::with_capacity(1024);
            for _ in 0..256 {
                content.push(1);
            }
            for _ in 0..256 {
                content.push(2);
            }
            for _ in 0..256 {
                content.push(3);
            }
            for _ in 0..256 {
                content.push(4);
            }
            content.push(5);
            content.push(5);

            let bytes = std::io::Cursor::new(content);
            let chunker = Chunker::fixed_with_size(256);
            let chunks: Vec<_> = chunker.chunks(bytes).try_collect().await.unwrap();
            assert_eq!(chunks.len(), 5);
            assert_eq!(&chunks[0], &[1u8; 256][..]);
            assert_eq!(&chunks[1], &[2u8; 256][..]);
            assert_eq!(&chunks[2], &[3u8; 256][..]);
            assert_eq!(&chunks[3], &[4u8; 256][..]);
            assert_eq!(&chunks[4], &[5u8; 2][..]);
        }
    }
}
