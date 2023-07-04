use super::{AsyncSliceReader, AsyncSliceWriter};
use bytes::{Bytes, BytesMut};
use futures::future;
use std::io;

impl AsyncSliceReader for bytes::Bytes {
    type ReadAtFuture<'a> = future::Ready<io::Result<Bytes>>;
    fn read_at(&mut self, offset: u64, len: usize) -> Self::ReadAtFuture<'_> {
        future::ok(get_limited_slice(self, offset, len))
    }

    type LenFuture<'a> = future::Ready<io::Result<u64>>;
    fn len(&mut self) -> Self::LenFuture<'_> {
        future::ok(Bytes::len(self) as u64)
    }
}

impl AsyncSliceReader for bytes::BytesMut {
    type ReadAtFuture<'a> = future::Ready<io::Result<Bytes>>;
    fn read_at(&mut self, offset: u64, len: usize) -> Self::ReadAtFuture<'_> {
        future::ok(copy_limited_slice(self, offset, len))
    }

    type LenFuture<'a> = future::Ready<io::Result<u64>>;
    fn len(&mut self) -> Self::LenFuture<'_> {
        future::ok(BytesMut::len(self) as u64)
    }
}

impl AsyncSliceWriter for bytes::BytesMut {
    type WriteBytesAtFuture<'a> = future::Ready<io::Result<()>>;
    fn write_bytes_at(&mut self, offset: u64, data: Bytes) -> Self::WriteBytesAtFuture<'_> {
        future::ready(write_extend(self, offset, &data))
    }

    type WriteAtFuture<'a> = future::Ready<io::Result<()>>;
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Self::WriteAtFuture<'_> {
        future::ready(write_extend(self, offset, data))
    }

    type SetLenFuture<'a> = future::Ready<io::Result<()>>;
    fn set_len(&mut self, len: u64) -> Self::SetLenFuture<'_> {
        let len = len.try_into().unwrap_or(usize::MAX);
        self.resize(len, 0);
        future::ok(())
    }

    type SyncFuture<'a> = future::Ready<io::Result<()>>;
    fn sync(&mut self) -> Self::SyncFuture<'_> {
        future::ok(())
    }
}

pub(crate) fn limited_range(offset: u64, len: usize, buf_len: usize) -> std::ops::Range<usize> {
    if offset < buf_len as u64 {
        let start = offset as usize;
        let end = start.saturating_add(len).min(buf_len);
        start..end
    } else {
        0..0
    }
}

fn get_limited_slice(bytes: &Bytes, offset: u64, len: usize) -> Bytes {
    bytes.slice(limited_range(offset, len, bytes.len()))
}

fn copy_limited_slice(bytes: &[u8], offset: u64, len: usize) -> Bytes {
    bytes[limited_range(offset, len, bytes.len())]
        .to_vec()
        .into()
}

fn write_extend(bytes: &mut BytesMut, offset: u64, data: &[u8]) -> io::Result<()> {
    let start = usize::try_from(offset).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "start is too large to fit in usize",
        )
    })?;
    let end = start.checked_add(data.len()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "offset + data.len() is too large to fit in usize",
        )
    })?;
    if data.is_empty() {
        return Ok(());
    }
    if end > BytesMut::len(bytes) {
        bytes.resize(start, 0);
        bytes.extend_from_slice(data);
    } else {
        bytes[start..end].copy_from_slice(data);
    }

    Ok(())
}
