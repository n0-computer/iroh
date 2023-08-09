//! Utilities for reporting progress.
//!
//! The main entry point is the [ProgressSender] trait.
use futures::FutureExt;
use std::marker::PhantomData;

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
/// # Tokio progress sender
///
/// If you want to report progress over a tokio channel, you can use the [TokioProgressSender] type.
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

    ///
    type SendFuture<'a>: futures::Future<Output = std::result::Result<(), ProgressSendError>>
        + Send
        + 'a
    where
        Self: 'a;

    /// Send a message and wait if the receiver is full.
    ///
    /// Use this to send important progress messages where delivery must be guaranteed.
    #[must_use]
    fn send(&self, msg: Self::Msg) -> Self::SendFuture<'_>;

    /// Try to send a message and drop it if the receiver is full.
    ///
    /// Use this to send progress messages where delivery is not important, e.g. a self contained progress message.
    fn try_send(&self, msg: Self::Msg) -> std::result::Result<(), ProgressSendError>;

    /// Send a message and block if the receiver is full.
    ///
    /// Use this to send important progress messages where delivery must be guaranteed.
    fn blocking_send(&self, msg: Self::Msg) -> std::result::Result<(), ProgressSendError>;

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
}

/// An id generator, to be combined with a progress sender.
pub trait IdGenerator {
    /// Get a new unique id
    fn new_id(&self) -> u64;
}

/// A no-op progress sender.
#[derive(Default)]
pub struct IgnoreProgressSender<T>(PhantomData<T>);

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

    type SendFuture<'a> = futures::future::Ready<std::result::Result<(), ProgressSendError>>;

    fn send(&self, _msg: T) -> Self::SendFuture<'_> {
        futures::future::ready(Ok(()))
    }

    fn try_send(&self, _msg: T) -> std::result::Result<(), ProgressSendError> {
        Ok(())
    }

    fn blocking_send(&self, _msg: T) -> std::result::Result<(), ProgressSendError> {
        Ok(())
    }
}

impl IdGenerator for IgnoreProgressSender<()> {
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

    type SendFuture<'a> = I::SendFuture<'a>;

    fn send(&self, msg: U) -> Self::SendFuture<'_> {
        let msg = (self.1)(msg);
        self.0.send(msg)
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
        I: ProgressSender,
        U: Send + Sync + 'static,
        F: Fn(U) -> Option<I::Msg> + Clone + Send + Sync + 'static,
    > ProgressSender for WithFilterMap<I, U, F>
{
    type Msg = U;

    type SendFuture<'a> = futures::future::Either<
        I::SendFuture<'a>,
        futures::future::Ready<std::result::Result<(), ProgressSendError>>,
    >;

    fn send(&self, msg: U) -> Self::SendFuture<'_> {
        if let Some(msg) = (self.1)(msg) {
            self.0.send(msg).left_future()
        } else {
            futures::future::ok(()).right_future()
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

impl<T> IdGenerator for TokioProgressSender<T> {
    fn new_id(&self) -> u64 {
        TokioProgressSender::new_id(self)
    }
}

impl<T: Send + Sync + 'static> ProgressSender for TokioProgressSender<T> {
    type Msg = T;

    type SendFuture<'a> =
        futures::future::BoxFuture<'a, std::result::Result<(), ProgressSendError>>;

    fn send(&self, msg: T) -> Self::SendFuture<'_> {
        let t: T = msg;
        TokioProgressSender::send(self, t).boxed()
    }

    fn try_send(&self, msg: T) -> std::result::Result<(), ProgressSendError> {
        TokioProgressSender::try_send(self, msg)
    }

    fn blocking_send(&self, msg: T) -> std::result::Result<(), ProgressSendError> {
        TokioProgressSender::blocking_send(self, msg)
    }
}

/// A convenience type for sending progress messages.
pub struct TokioProgressSender<T> {
    sender: tokio::sync::mpsc::Sender<T>,
    id: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl<T> std::fmt::Debug for TokioProgressSender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokioProgressSender")
            .field("id", &self.id)
            .field("sender", &self.sender)
            .finish()
    }
}

impl<T> Clone for TokioProgressSender<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            id: self.id.clone(),
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

impl From<ProgressSendError> for std::io::Error {
    fn from(e: ProgressSendError) -> Self {
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)
    }
}

impl<T> TokioProgressSender<T> {
    /// Create a new progress sender from a tokio mpsc sender.
    pub fn new(sender: tokio::sync::mpsc::Sender<T>) -> Self {
        Self {
            sender,
            id: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// allocate a new id for progress reports for this transfer
    pub(crate) fn new_id(&self) -> u64 {
        self.id.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// send a message and yield if the receiver is full.
    /// this will only fail if the receiver is dropped.
    /// It can be used to send important progress messages where delivery must be guaranteed.
    /// E.g. start(id)/end(id)
    pub(crate) async fn send(
        &self,
        msg: impl Into<T>,
    ) -> std::result::Result<(), ProgressSendError> {
        let msg = msg.into();
        self.sender
            .send(msg)
            .await
            .map_err(|_| ProgressSendError::ReceiverDropped)
    }

    /// try to send a message and drop it if the receiver is full.
    /// this will only fail if the receiver is dropped.
    /// It can be used to send progress messages where delivery is not important, e.g.
    /// a self contained progress message.
    pub(crate) fn try_send(&self, msg: impl Into<T>) -> std::result::Result<(), ProgressSendError> {
        let msg = msg.into();
        match self.sender.try_send(msg) {
            Ok(_) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                Err(ProgressSendError::ReceiverDropped)
            }
        }
    }

    ///
    pub(crate) fn blocking_send(
        &self,
        msg: impl Into<T>,
    ) -> std::result::Result<(), ProgressSendError> {
        let msg = msg.into();
        match self.sender.blocking_send(msg) {
            Ok(_) => Ok(()),
            Err(_) => Err(ProgressSendError::ReceiverDropped),
        }
    }
}
