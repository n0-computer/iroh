//! Blocking io for [std::fs::File], using the tokio blocking task pool.
use bytes::Bytes;
use futures::Future;
use pin_project::pin_project;
use std::{
    io::{self, Read, Seek, SeekFrom},
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::task::{spawn_blocking, JoinHandle};

use super::{make_io_error, AsyncSliceReader, AsyncSliceWriter};

/// A wrapper around a [std::fs::File] that implements [AsyncSliceReader] and [AsyncSliceWriter]
#[derive(Debug)]
pub struct FileAdapter(Option<FileAdapterFsm>);

impl FileAdapter {
    /// Create a new [FileAdapter] from a function that creates a [std::fs::File]
    pub async fn create(
        create_file: impl Fn() -> io::Result<std::fs::File> + Send + 'static,
    ) -> io::Result<Self> {
        let inner = spawn_blocking(create_file).await.map_err(make_io_error)??;
        Ok(Self::from_std(inner))
    }

    /// Create a new [FileAdapter] from a [std::fs::File]
    ///
    /// This is fine if you already have a [std::fs::File] and want to use it with [FileAdapter],
    /// but opening a file is a blocking op that you probably don't want to do in an async context.
    pub fn from_std(file: std::fs::File) -> Self {
        Self(Some(FileAdapterFsm(file)))
    }

    /// Open a [FileAdapter] from a path
    pub async fn open(path: PathBuf) -> io::Result<Self> {
        Self::create(move || std::fs::File::open(&path)).await
    }

    #[cfg(test)]
    pub fn read_contents(&self) -> Vec<u8> {
        let mut std_file = &self.0.as_ref().unwrap().0;
        let mut t = Vec::new();
        // this is not needed since at least for POSIX IO "read your own writes"
        // is guaranteed.
        // std_file.sync_all().unwrap();
        std_file.rewind().unwrap();
        std_file.read_to_end(&mut t).unwrap();
        t
    }
}

/// Futures for the [FileAdapter]
pub mod file_adapter {
    use bytes::Bytes;

    use super::*;

    newtype_future!(
        /// The future returned by [FileAdapter::read_at]
        #[derive(Debug)]
        ReadAtFuture,
        Asyncify<'a, Bytes, FileAdapterFsm>,
        io::Result<Bytes>
    );
    newtype_future!(
        /// The future returned by [FileAdapter::len]
        #[derive(Debug)]
        LenFuture,
        Asyncify<'a, u64, FileAdapterFsm>,
        io::Result<u64>
    );
    newtype_future!(
        /// The future returned by [FileAdapter::write_at]
        #[derive(Debug)]
        WriteAtFuture,
        Asyncify<'a, (), FileAdapterFsm>,
        io::Result<()>
    );
    newtype_future!(
        /// The future returned by [FileAdapter::write_array_at]
        #[derive(Debug)]
        WriteArrayAtFuture,
        Asyncify<'a, (), FileAdapterFsm>,
        io::Result<()>
    );
    newtype_future!(
        /// The future returned by [FileAdapter::set_len]
        #[derive(Debug)]
        SetLenFuture,
        Asyncify<'a, (), FileAdapterFsm>,
        io::Result<()>
    );
    newtype_future!(
        /// The future returned by [FileAdapter::sync]
        #[derive(Debug)]
        SyncFuture,
        Asyncify<'a, (), FileAdapterFsm>,
        io::Result<()>
    );

    impl AsyncSliceReader for FileAdapter {
        type ReadAtFuture<'a> = file_adapter::ReadAtFuture<'a>;

        fn read_at(&mut self, offset: u64, len: usize) -> Self::ReadAtFuture<'_> {
            let fut = self
                .0
                .take()
                .map(|t| (t.read_at(offset, len), &mut self.0))
                .into();
            ReadAtFuture(fut)
        }

        type LenFuture<'a> = LenFuture<'a>;

        fn len(&mut self) -> Self::LenFuture<'_> {
            let fut = self.0.take().map(|t| (t.len(), &mut self.0)).into();
            LenFuture(fut)
        }
    }

    impl AsyncSliceWriter for FileAdapter {
        type WriteAtFuture<'a> = WriteAtFuture<'a>;

        fn write_at(&mut self, offset: u64, data: Bytes) -> Self::WriteAtFuture<'_> {
            let fut = self
                .0
                .take()
                .map(|t| (t.write_at(offset, data), &mut self.0))
                .into();
            WriteAtFuture(fut)
        }

        type WriteArrayAtFuture<'a> = WriteArrayAtFuture<'a>;
        fn write_array_at<const N: usize>(
            &mut self,
            offset: u64,
            data: [u8; N],
        ) -> Self::WriteArrayAtFuture<'_> {
            let fut = self
                .0
                .take()
                .map(|t| (t.write_array_at(offset, data), &mut self.0))
                .into();
            WriteArrayAtFuture(fut)
        }

        type SyncFuture<'a> = SyncFuture<'a>;
        fn sync(&mut self) -> Self::SyncFuture<'_> {
            let fut = self.0.take().map(|t| (t.sync(), &mut self.0)).into();
            SyncFuture(fut)
        }

        type SetLenFuture<'a> = SetLenFuture<'a>;
        fn set_len(&mut self, len: u64) -> Self::SetLenFuture<'_> {
            let fut = self.0.take().map(|t| (t.set_len(len), &mut self.0)).into();
            SetLenFuture(fut)
        }
    }
}

/// A future wrapper to unpack the result of a sync computation and store the
/// state on completion, making the io object available again.
#[derive(Debug)]
#[pin_project(project = AsyncifyProj)]
enum Asyncify<'a, R, T> {
    /// we got a future and a handle where we can store the state on completion
    Ok(
        #[pin] tokio::task::JoinHandle<(T, io::Result<R>)>,
        &'a mut Option<T>,
    ),
    /// the handle was busy
    BusyErr,
}

impl<'a, R, T> From<Option<(JoinHandle<(T, io::Result<R>)>, &'a mut Option<T>)>>
    for Asyncify<'a, R, T>
{
    fn from(value: Option<(JoinHandle<(T, io::Result<R>)>, &'a mut Option<T>)>) -> Self {
        match value {
            Some((f, h)) => Self::Ok(f, h),
            None => Self::BusyErr,
        }
    }
}

impl<'a, T: 'a, R> Future for Asyncify<'a, R, T> {
    type Output = io::Result<R>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            AsyncifyProj::Ok(f, h) => f.poll(cx).map(|x| {
                match x {
                    Ok((state, r)) => {
                        // we got a result, so we can store the state
                        **h = Some(state);
                        r
                    }
                    Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
                }
            }),
            AsyncifyProj::BusyErr => Poll::Ready(io::Result::Err(io::Error::new(
                io::ErrorKind::Other,
                "previous io op not polled to completion",
            ))),
        }
    }
}

/// A wrapper around a [std::fs::File] that defines IO operations that spawn blocking tasks.
///
/// This implements all operations of [AsyncSliceReader] and [AsyncSliceWriter] in state
/// passing style.
#[derive(Debug)]
struct FileAdapterFsm(std::fs::File);

impl FileAdapterFsm {
    fn read_at(mut self, offset: u64, len: usize) -> JoinHandle<(Self, io::Result<Bytes>)> {
        fn inner<R: std::io::Read + std::io::Seek>(
            this: &mut R,
            offset: u64,
            len: usize,
            buf: &mut Vec<u8>,
        ) -> io::Result<()> {
            this.seek(SeekFrom::Start(offset))?;
            this.take(len as u64).read_to_end(buf)?;
            Ok(())
        }
        spawn_blocking(move || {
            // len is just the expected len, so if it is too big, we should not allocate
            // the entire size.
            let mut buf = Vec::with_capacity(len.min(1024));
            let res = inner(&mut self.0, offset, len, &mut buf);
            (self, res.map(|_| buf.into()))
        })
    }

    fn len(mut self) -> JoinHandle<(Self, io::Result<u64>)> {
        spawn_blocking(move || {
            let res = self.0.seek(SeekFrom::End(0));
            (self, res)
        })
    }
}

impl FileAdapterFsm {
    fn write_at(mut self, offset: u64, data: Bytes) -> JoinHandle<(Self, io::Result<()>)> {
        fn inner<W: std::io::Write + std::io::Seek>(
            this: &mut W,
            offset: u64,
            buf: &[u8],
        ) -> io::Result<()> {
            this.seek(SeekFrom::Start(offset))?;
            this.write_all(buf)?;
            Ok(())
        }
        spawn_blocking(move || {
            let res = inner(&mut self.0, offset, &data);
            (self, res)
        })
    }

    fn write_array_at<const N: usize>(
        mut self,
        offset: u64,
        bytes: [u8; N],
    ) -> JoinHandle<(Self, io::Result<()>)> {
        fn inner<W: std::io::Write + std::io::Seek>(
            this: &mut W,
            offset: u64,
            buf: &[u8],
        ) -> io::Result<()> {
            this.seek(SeekFrom::Start(offset))?;
            this.write_all(buf)?;
            Ok(())
        }
        spawn_blocking(move || {
            let res = inner(&mut self.0, offset, &bytes);
            (self, res)
        })
    }

    fn set_len(self, len: u64) -> JoinHandle<(Self, io::Result<()>)> {
        spawn_blocking(move || {
            let res = self.0.set_len(len);
            (self, res)
        })
    }

    fn sync(self) -> JoinHandle<(Self, io::Result<()>)> {
        spawn_blocking(move || {
            let res = self.0.sync_all();
            (self, res)
        })
    }
}
