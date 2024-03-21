//! Utilities for reporting progress.
//!
//! The main entry point is the [ProgressSender] trait.
use std::{io, marker::PhantomData, ops::Deref, sync::Arc};

use bytes::Bytes;
use futures::{future::BoxFuture, Future, FutureExt};
use iroh_io::AsyncSliceWriter;

/// A general purpose progress sender. This should be usable for reporting progress
/// from both blocking and non-blocking contexts.
///
/// # Id generation
///
/// Any good progress protocol will refer to entities by means of a unique id.
/// E.g. if you want to report progress about some file operation, including details
/// such as the full path of the file would be very wasteful. It is better to
/// introduce a unique id for the file and then report progress using that id.
///
/// The [IdGenerator] trait provides a method to generate such ids, [IdGenerator::new_id].
///
/// # Sending important messages
///
/// Some messages are important for the receiver to receive. E.g. start and end
/// messages for some operation. If the receiver would miss one of these messages,
/// it would lose the ability to make sense of the progress message stream.
///
/// This trait provides a method to send such important messages, in both blocking
/// contexts where you have to block until the message is sent [ProgressSender::blocking_send],
/// and non-blocking contexts where you have to yield until the message is sent [ProgressSender::send].
///
/// # Sending unimportant messages
///
/// Some messages are self-contained and not important for the receiver to receive.
/// E.g. if you send millions of progress messages for copying a file that each
/// contain an id and the number of bytes copied so far, it is not important for
/// the receiver to receive every single one of these messages. In fact it is
/// useful to drop some of these messages because waiting for the progress events
/// to be sent can slow down the actual operation.
///
/// This trait provides a method to send such unimportant messages that can be
/// used in both blocking and non-blocking contexts, [ProgressSender::try_send].
///
/// # Errors
///
/// When the receiver is dropped, sending a message will fail. This provides a way
/// for the receiver to signal that the operation should be stopped.
///
/// E.g. for a blocking copy operation that reports frequent progress messages,
/// as soon as the receiver is dropped, this is a signal to stop the copy operation.
///
/// The error type is [ProgressSendError], which can be converted to an [std::io::Error]
/// for convenience.
///
/// # Transforming the message type
///
/// Sometimes you have a progress sender that sends a message of type `A` but an
/// operation that reports progress of type `B`. If you have a transformation for
/// every `B` to an `A`, you can use the [ProgressSender::with_map] method to transform the message.
///
/// This is similar to the [futures::SinkExt::with] method.
///
/// # Filtering the message type
///
/// Sometimes you have a progress sender that sends a message of enum `A` but an
/// operation that reports progress of type `B`. You are interested only in some
/// enum cases of `A` that can be transformed to `B`. You can use the [ProgressSender::with_filter_map]
/// method to filter and transform the message.
///
/// # No-op progress sender
///
/// If you don't want to report progress, you can use the [IgnoreProgressSender] type.
///
/// # Flume progress sender
///
/// If you want to use a flume channel, you can use the [FlumeProgressSender] type.
///
/// # Implementing your own progress sender
///
/// Progress senders will frequently be used in a multi-threaded context.
///
/// They must be **cheap** to clone and send between threads.
/// They must also be thread safe, which is ensured by the [Send] and [Sync] bounds.
/// They must also be unencumbered by lifetimes, which is ensured by the `'static` bound.
///
/// A typical implementation will wrap the sender part of a channel and an id generator.
pub trait ProgressSender: std::fmt::Debug + Clone + Send + Sync + 'static {
    ///
    type Msg: Send + Sync + 'static;

    /// Send a message and wait if the receiver is full.
    ///
    /// Use this to send important progress messages where delivery must be guaranteed.
    #[must_use]
    fn send(&self, msg: Self::Msg) -> impl Future<Output = ProgressSendResult<()>> + Send;

    /// Try to send a message and drop it if the receiver is full.
    ///
    /// Use this to send progress messages where delivery is not important, e.g. a self contained progress message.
    fn try_send(&self, msg: Self::Msg) -> ProgressSendResult<()>;

    /// Send a message and block if the receiver is full.
    ///
    /// Use this to send important progress messages where delivery must be guaranteed.
    fn blocking_send(&self, msg: Self::Msg) -> ProgressSendResult<()>;

    /// Transform the message type by mapping to the type of this sender.
    fn with_map<U: Send + Sync + 'static, F: Fn(U) -> Self::Msg + Send + Sync + Clone + 'static>(
        self,
        f: F,
    ) -> WithMap<Self, U, F> {
        WithMap(self, f, PhantomData)
    }

    /// Transform the message type by filter-mapping to the type of this sender.
    fn with_filter_map<
        U: Send + Sync + 'static,
        F: Fn(U) -> Option<Self::Msg> + Send + Sync + Clone + 'static,
    >(
        self,
        f: F,
    ) -> WithFilterMap<Self, U, F> {
        WithFilterMap(self, f, PhantomData)
    }

    /// Create a boxed progress sender to get rid of the concrete type.
    fn boxed(self) -> BoxedProgressSender<Self::Msg>
    where
        Self: IdGenerator,
    {
        BoxedProgressSender(Arc::new(BoxableProgressSenderWrapper(self)))
    }
}

/// A boxed progress sender
pub struct BoxedProgressSender<T>(Arc<dyn BoxableProgressSender<T>>);

impl<T> Clone for BoxedProgressSender<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> std::fmt::Debug for BoxedProgressSender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BoxedProgressSender").field(&self.0).finish()
    }
}

/// Boxable progress sender
trait BoxableProgressSender<T>: IdGenerator + std::fmt::Debug + Send + Sync + 'static {
    /// Send a message and wait if the receiver is full.
    ///
    /// Use this to send important progress messages where delivery must be guaranteed.
    #[must_use]
    fn send(&self, msg: T) -> BoxFuture<ProgressSendResult<()>>;

    /// Try to send a message and drop it if the receiver is full.
    ///
    /// Use this to send progress messages where delivery is not important, e.g. a self contained progress message.
    fn try_send(&self, msg: T) -> ProgressSendResult<()>;

    /// Send a message and block if the receiver is full.
    ///
    /// Use this to send important progress messages where delivery must be guaranteed.
    fn blocking_send(&self, msg: T) -> ProgressSendResult<()>;
}

impl<I: ProgressSender + IdGenerator> BoxableProgressSender<I::Msg>
    for BoxableProgressSenderWrapper<I>
{
    fn send(&self, msg: I::Msg) -> BoxFuture<ProgressSendResult<()>> {
        self.0.send(msg).boxed()
    }

    fn try_send(&self, msg: I::Msg) -> ProgressSendResult<()> {
        self.0.try_send(msg)
    }

    fn blocking_send(&self, msg: I::Msg) -> ProgressSendResult<()> {
        self.0.blocking_send(msg)
    }
}

/// Boxable progress sender wrapper, used internally.
#[derive(Debug)]
#[repr(transparent)]
struct BoxableProgressSenderWrapper<I>(I);

impl<I: ProgressSender + IdGenerator> IdGenerator for BoxableProgressSenderWrapper<I> {
    fn new_id(&self) -> u64 {
        self.0.new_id()
    }
}

impl<T: Send + Sync + 'static> ProgressSender for Arc<dyn BoxableProgressSender<T>> {
    type Msg = T;

    fn send(&self, msg: T) -> impl Future<Output = ProgressSendResult<()>> + Send {
        self.deref().send(msg)
    }

    fn try_send(&self, msg: T) -> ProgressSendResult<()> {
        self.deref().try_send(msg)
    }

    fn blocking_send(&self, msg: T) -> ProgressSendResult<()> {
        self.deref().blocking_send(msg)
    }
}

impl<T: Send + Sync + 'static> ProgressSender for BoxedProgressSender<T> {
    type Msg = T;

    async fn send(&self, msg: T) -> ProgressSendResult<()> {
        self.0.send(msg).await
    }

    fn try_send(&self, msg: T) -> ProgressSendResult<()> {
        self.0.try_send(msg)
    }

    fn blocking_send(&self, msg: T) -> ProgressSendResult<()> {
        self.0.blocking_send(msg)
    }
}

impl<T: ProgressSender> ProgressSender for Option<T> {
    type Msg = T::Msg;

    async fn send(&self, msg: Self::Msg) -> ProgressSendResult<()> {
        if let Some(inner) = self {
            inner.send(msg).await
        } else {
            Ok(())
        }
    }

    fn try_send(&self, msg: Self::Msg) -> ProgressSendResult<()> {
        if let Some(inner) = self {
            inner.try_send(msg)
        } else {
            Ok(())
        }
    }

    fn blocking_send(&self, msg: Self::Msg) -> ProgressSendResult<()> {
        if let Some(inner) = self {
            inner.blocking_send(msg)
        } else {
            Ok(())
        }
    }
}

/// An id generator, to be combined with a progress sender.
pub trait IdGenerator {
    /// Get a new unique id
    fn new_id(&self) -> u64;
}

/// A no-op progress sender.
pub struct IgnoreProgressSender<T>(PhantomData<T>);

impl<T> Default for IgnoreProgressSender<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T> Clone for IgnoreProgressSender<T> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<T> std::fmt::Debug for IgnoreProgressSender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IgnoreProgressSender").finish()
    }
}

impl<T: Send + Sync + 'static> ProgressSender for IgnoreProgressSender<T> {
    type Msg = T;

    async fn send(&self, _msg: T) -> std::result::Result<(), ProgressSendError> {
        Ok(())
    }

    fn try_send(&self, _msg: T) -> std::result::Result<(), ProgressSendError> {
        Ok(())
    }

    fn blocking_send(&self, _msg: T) -> std::result::Result<(), ProgressSendError> {
        Ok(())
    }
}

impl<T> IdGenerator for IgnoreProgressSender<T> {
    fn new_id(&self) -> u64 {
        0
    }
}

/// Transform the message type by mapping to the type of this sender.
///
/// See [ProgressSender::with_map].
pub struct WithMap<
    I: ProgressSender,
    U: Send + Sync + 'static,
    F: Fn(U) -> I::Msg + Clone + Send + Sync + 'static,
>(I, F, PhantomData<U>);

impl<
        I: ProgressSender,
        U: Send + Sync + 'static,
        F: Fn(U) -> I::Msg + Clone + Send + Sync + 'static,
    > std::fmt::Debug for WithMap<I, U, F>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("With").field(&self.0).finish()
    }
}

impl<
        I: ProgressSender,
        U: Send + Sync + 'static,
        F: Fn(U) -> I::Msg + Clone + Send + Sync + 'static,
    > Clone for WithMap<I, U, F>
{
    fn clone(&self) -> Self {
        Self(self.0.clone(), self.1.clone(), PhantomData)
    }
}

impl<
        I: ProgressSender,
        U: Send + Sync + 'static,
        F: Fn(U) -> I::Msg + Clone + Send + Sync + 'static,
    > ProgressSender for WithMap<I, U, F>
{
    type Msg = U;

    async fn send(&self, msg: U) -> std::result::Result<(), ProgressSendError> {
        let msg = (self.1)(msg);
        self.0.send(msg).await
    }

    fn try_send(&self, msg: U) -> std::result::Result<(), ProgressSendError> {
        let msg = (self.1)(msg);
        self.0.try_send(msg)
    }

    fn blocking_send(&self, msg: U) -> std::result::Result<(), ProgressSendError> {
        let msg = (self.1)(msg);
        self.0.blocking_send(msg)
    }
}

/// Transform the message type by filter-mapping to the type of this sender.
///
/// See [ProgressSender::with_filter_map].
pub struct WithFilterMap<I, U, F>(I, F, PhantomData<U>);

impl<
        I: ProgressSender,
        U: Send + Sync + 'static,
        F: Fn(U) -> Option<I::Msg> + Clone + Send + Sync + 'static,
    > std::fmt::Debug for WithFilterMap<I, U, F>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FilterWith").field(&self.0).finish()
    }
}

impl<
        I: ProgressSender,
        U: Send + Sync + 'static,
        F: Fn(U) -> Option<I::Msg> + Clone + Send + Sync + 'static,
    > Clone for WithFilterMap<I, U, F>
{
    fn clone(&self) -> Self {
        Self(self.0.clone(), self.1.clone(), PhantomData)
    }
}

impl<I: IdGenerator, U, F> IdGenerator for WithFilterMap<I, U, F> {
    fn new_id(&self) -> u64 {
        self.0.new_id()
    }
}

impl<
        I: IdGenerator + ProgressSender,
        U: Send + Sync + 'static,
        F: Fn(U) -> I::Msg + Clone + Send + Sync + 'static,
    > IdGenerator for WithMap<I, U, F>
{
    fn new_id(&self) -> u64 {
        self.0.new_id()
    }
}

impl<
        I: ProgressSender,
        U: Send + Sync + 'static,
        F: Fn(U) -> Option<I::Msg> + Clone + Send + Sync + 'static,
    > ProgressSender for WithFilterMap<I, U, F>
{
    type Msg = U;

    async fn send(&self, msg: U) -> std::result::Result<(), ProgressSendError> {
        if let Some(msg) = (self.1)(msg) {
            self.0.send(msg).await
        } else {
            Ok(())
        }
    }

    fn try_send(&self, msg: U) -> std::result::Result<(), ProgressSendError> {
        if let Some(msg) = (self.1)(msg) {
            self.0.try_send(msg)
        } else {
            Ok(())
        }
    }

    fn blocking_send(&self, msg: U) -> std::result::Result<(), ProgressSendError> {
        if let Some(msg) = (self.1)(msg) {
            self.0.blocking_send(msg)
        } else {
            Ok(())
        }
    }
}

/// A progress sender that uses a flume channel.
pub struct FlumeProgressSender<T> {
    sender: flume::Sender<T>,
    id: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl<T> std::fmt::Debug for FlumeProgressSender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlumeProgressSender")
            .field("id", &self.id)
            .field("sender", &self.sender)
            .finish()
    }
}

impl<T> Clone for FlumeProgressSender<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            id: self.id.clone(),
        }
    }
}

impl<T> FlumeProgressSender<T> {
    /// Create a new progress sender from a tokio mpsc sender.
    pub fn new(sender: flume::Sender<T>) -> Self {
        Self {
            sender,
            id: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }
}

impl<T> IdGenerator for FlumeProgressSender<T> {
    fn new_id(&self) -> u64 {
        self.id.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }
}

impl<T: Send + Sync + 'static> ProgressSender for FlumeProgressSender<T> {
    type Msg = T;

    async fn send(&self, msg: Self::Msg) -> std::result::Result<(), ProgressSendError> {
        self.sender
            .send_async(msg)
            .await
            .map_err(|_| ProgressSendError::ReceiverDropped)
    }

    fn try_send(&self, msg: Self::Msg) -> std::result::Result<(), ProgressSendError> {
        match self.sender.try_send(msg) {
            Ok(_) => Ok(()),
            Err(flume::TrySendError::Full(_)) => Ok(()),
            Err(flume::TrySendError::Disconnected(_)) => Err(ProgressSendError::ReceiverDropped),
        }
    }

    fn blocking_send(&self, msg: Self::Msg) -> std::result::Result<(), ProgressSendError> {
        match self.sender.send(msg) {
            Ok(_) => Ok(()),
            Err(_) => Err(ProgressSendError::ReceiverDropped),
        }
    }
}

/// An error that can occur when sending progress messages.
///
/// Really the only error that can occur is if the receiver is dropped.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProgressSendError {
    /// The receiver was dropped.
    #[error("receiver dropped")]
    ReceiverDropped,
}

/// A result type for progress sending.
pub type ProgressSendResult<T> = std::result::Result<T, ProgressSendError>;

impl From<ProgressSendError> for std::io::Error {
    fn from(e: ProgressSendError) -> Self {
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)
    }
}

/// A slice writer that adds a synchronous progress callback.
///
/// This wraps any `AsyncSliceWriter`, passes through all operations to the inner writer, and
/// calls the passed `on_write` callback whenever data is written.
#[derive(Debug)]
pub struct ProgressSliceWriter<W, F>(W, F);

impl<W: AsyncSliceWriter, F: FnMut(u64)> ProgressSliceWriter<W, F> {
    /// Create a new `ProgressSliceWriter` from an inner writer and a progress callback
    ///
    /// The `on_write` function is called for each write, with the `offset` as the first and the
    /// length of the data as the second param.
    pub fn new(inner: W, on_write: F) -> Self {
        Self(inner, on_write)
    }

    /// Return the inner writer
    pub fn into_inner(self) -> W {
        self.0
    }
}

impl<W: AsyncSliceWriter + 'static, F: FnMut(u64, usize) + 'static> AsyncSliceWriter
    for ProgressSliceWriter<W, F>
{
    async fn write_bytes_at(&mut self, offset: u64, data: Bytes) -> io::Result<()> {
        (self.1)(offset, data.len());
        self.0.write_bytes_at(offset, data).await
    }

    async fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        (self.1)(offset, data.len());
        self.0.write_at(offset, data).await
    }

    async fn sync(&mut self) -> io::Result<()> {
        self.0.sync().await
    }

    async fn set_len(&mut self, size: u64) -> io::Result<()> {
        self.0.set_len(size).await
    }
}

/// A slice writer that adds a fallible progress callback.
///
/// This wraps any `AsyncSliceWriter`, passes through all operations to the inner writer, and
/// calls the passed `on_write` callback whenever data is written. `on_write` must return an
/// `io::Result`, and can abort the download by returning an error.
#[derive(Debug)]
pub struct FallibleProgressSliceWriter<W, F>(W, F);

impl<W: AsyncSliceWriter, F: Fn(u64, usize) -> io::Result<()> + 'static>
    FallibleProgressSliceWriter<W, F>
{
    /// Create a new `ProgressSliceWriter` from an inner writer and a progress callback
    ///
    /// The `on_write` function is called for each write, with the `offset` as the first and the
    /// length of the data as the second param. `on_write` must return a future which resolves to
    /// an `io::Result`. If `on_write` returns an error, the download is aborted.
    pub fn new(inner: W, on_write: F) -> Self {
        Self(inner, on_write)
    }

    /// Return the inner writer.
    pub fn into_inner(self) -> W {
        self.0
    }
}

impl<W: AsyncSliceWriter + 'static, F: Fn(u64, usize) -> io::Result<()> + 'static> AsyncSliceWriter
    for FallibleProgressSliceWriter<W, F>
{
    async fn write_bytes_at(&mut self, offset: u64, data: Bytes) -> io::Result<()> {
        (self.1)(offset, data.len())?;
        self.0.write_bytes_at(offset, data).await
    }

    async fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        (self.1)(offset, data.len())?;
        self.0.write_at(offset, data).await
    }

    async fn sync(&mut self) -> io::Result<()> {
        self.0.sync().await
    }

    async fn set_len(&mut self, size: u64) -> io::Result<()> {
        self.0.set_len(size).await
    }
}
