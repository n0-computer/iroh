//! Utility for rpc interactions
use std::{fmt, sync::Arc};

use futures::{
    future::{self, BoxFuture},
    Future, FutureExt, SinkExt, StreamExt,
};
use quic_rpc::{
    client::RpcClientError,
    message::{InteractionPattern, Msg},
    server::{RpcChannel, RpcServerError},
    RpcClient, Service, ServiceConnection, ServiceEndpoint,
};

/// Interaction pattern for rpc messages that can report progress
#[derive(Debug, Clone, Copy)]
pub struct RpcWithProgress;

impl InteractionPattern for RpcWithProgress {}

/// A rpc message with progress updates
///
/// This can be useful for long running operations where the client wants to
/// display progress to the user.
pub trait RpcWithProgressMsg<S: Service>: Msg<S> {
    /// The final response
    type Response: Into<S::Res> + TryFrom<S::Res> + Send + 'static;
    /// The self contained progress updates
    type Progress: Into<S::Res> + ConvertOrKeep<S::Res> + Send + 'static;
}

/// Helper trait to attempt a conversion and keep the original value if it fails
///
/// To implement this you have to implement TryFrom for the type and the reference.
/// This can be done with derive_more using #[derive(TryInto)].
pub trait ConvertOrKeep<T>: TryFrom<T> + Sized {
    /// Convert the value or keep it if it can't be converted
    fn convert_or_keep(s: T) -> std::result::Result<Self, T>;
}

impl<T, U> ConvertOrKeep<U> for T
where
    for<'a> &'a Self: TryFrom<&'a U>,
    Self: TryFrom<U>,
{
    fn convert_or_keep(x: U) -> std::result::Result<Self, U> {
        let can_convert = (<&Self>::try_from(&x)).is_ok();
        if can_convert {
            Ok(Self::try_from(x)
                .unwrap_or_else(|_| panic!("TryFrom inconsistent for byref and byval")))
        } else {
            Err(x)
        }
    }
}

/// Extension trait for rpc clients that adds rpc_with_progress helper method
pub trait RpcClientExt<S: Service, C: ServiceConnection<S>> {
    /// Perform a rpc call that returns a stream of progress updates.
    ///
    /// The progress updates are sent to the progress callback.
    /// Delivery is not guaranteed for progress updates, so the progress
    /// message should be self contained.
    ///
    /// Also, progress updates will be dropped on the client side if the client
    /// is not fast enough to process them.
    fn rpc_with_progress<M, F, Fut>(
        &self,
        msg: M,
        progress: F,
    ) -> BoxFuture<'_, std::result::Result<M::Response, RpcClientError<C>>>
    where
        M: RpcWithProgressMsg<S>,
        F: (Fn(M::Progress) -> Fut) + Send + 'static,
        Fut: Future<Output = ()> + Send;
}

impl<S: Service, C: ServiceConnection<S>> RpcClientExt<S, C> for RpcClient<S, C> {
    fn rpc_with_progress<M, F, Fut>(
        &self,
        msg: M,
        progress: F,
    ) -> BoxFuture<'_, std::result::Result<M::Response, RpcClientError<C>>>
    where
        M: RpcWithProgressMsg<S>,
        F: (Fn(M::Progress) -> Fut) + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        let (psend, mut precv) = tokio::sync::mpsc::channel(5);
        // future that does the call and filters the results
        let worker = async move {
            let (mut send, mut recv) = self
                .as_ref()
                .open_bi()
                .await
                .map_err(RpcClientError::Open)?;
            send.send(msg.into())
                .await
                .map_err(RpcClientError::<C>::Send)?;
            // read the results
            while let Some(msg) = recv.next().await {
                // handle recv errors
                let msg = msg.map_err(RpcClientError::RecvError)?;
                // first check if it is a progress message
                match M::Progress::convert_or_keep(msg) {
                    Ok(p) => {
                        // we got a progress message. Pass it on.
                        if psend.try_send(p).is_err() {
                            tracing::debug!("progress message dropped");
                        }
                    }
                    Err(msg) => {
                        // we got the response message.
                        // Convert it to the response type and return it.
                        // if the conversion fails, return an error.
                        let res = M::Response::try_from(msg)
                            .map_err(|_| RpcClientError::DowncastError)?;
                        return Ok(res);
                    }
                }
            }
            // The server closed the connection before sending a response.
            Err(RpcClientError::EarlyClose)
        };
        let forwarder = async move {
            // forward progress messages to the client.
            while let Some(msg) = precv.recv().await {
                let f = progress(msg);
                f.await;
            }
            // wait forever. we want the other future to complete first.
            future::pending::<std::result::Result<M::Response, RpcClientError<C>>>().await
        };
        async move {
            tokio::select! {
                res = worker => res,
                res = forwarder => res,
            }
        }
        .boxed()
    }
}

/// Extension trait for rpc channels that adds rpc_with_progress helper method
pub trait RpcChannelExt<S: Service, C: ServiceEndpoint<S>> {
    /// Perform an rpc that will send progress messages to the client.
    ///
    /// Progress messages, unlike other messages, can be dropped if the client
    /// is not ready to receive them. So the progress messages should be
    /// self-contained.
    fn rpc_with_progress<M, T, F, Fut>(
        self,
        msg: M,
        target: T,
        f: F,
    ) -> BoxFuture<'static, std::result::Result<(), RpcServerError<C>>>
    where
        M: RpcWithProgressMsg<S>,
        F: FnOnce(T, M, ProgressCb<M::Progress>) -> Fut + Send + Clone + 'static,
        Fut: Future<Output = M::Response> + Send,
        T: Send + 'static;
}

/// A callback that can be used to send progress messages to the client.
pub struct ProgressCb<T>(Arc<dyn Fn(T) + Send + Sync + 'static>);

impl<T> Clone for ProgressCb<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> fmt::Debug for ProgressCb<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProgressCb").finish()
    }
}

impl<T> ProgressCb<T> {
    fn new(f: impl Fn(T) + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    /// Send a progress message to the client.
    pub fn call(&self, t: T) {
        (self.0)(t)
    }
}

impl<S: Service, C: ServiceEndpoint<S>> RpcChannelExt<S, C> for RpcChannel<S, C> {
    fn rpc_with_progress<M, T, F, Fut>(
        mut self,
        msg: M,
        target: T,
        f: F,
    ) -> BoxFuture<'static, std::result::Result<(), RpcServerError<C>>>
    where
        M: RpcWithProgressMsg<S>,
        F: FnOnce(T, M, ProgressCb<M::Progress>) -> Fut + Send + Clone + 'static,
        Fut: Future<Output = M::Response> + Send,
        T: Send + 'static,
    {
        let (send, mut recv) = tokio::sync::mpsc::channel(5);
        let send2 = send.clone();

        // call the function that will actually perform the rpc, then send the result
        // to the forwarder, which will forward it to the rpc channel.
        let fut = async move {
            let progress = ProgressCb::new(move |progress| {
                if send.try_send(Err(progress)).is_err() {
                    // The forwarder is not ready to receive the message.
                    // Drop it, it is just a self contained progress message.
                    tracing::debug!("progress message dropped");
                }
            });
            let res = f(target, msg, progress).await;
            send2
                .send(Ok(res))
                .await
                .map_err(|_| RpcServerError::EarlyClose)?;
            // wait forever. we want the other future to complete first.
            future::pending::<std::result::Result<(), RpcServerError<C>>>().await
        };
        // forwarder future that will forward messages to the rpc channel.
        let forwarder = async move {
            // this will run until the rpc future completes and drops the send.
            while let Some(msg) = recv.recv().await {
                // if we get a response, we are immediately done.
                let done = msg.is_ok();
                let msg = match msg {
                    Ok(msg) => msg.into(),
                    Err(msg) => msg.into(),
                };
                self.send
                    .send(msg)
                    .await
                    .map_err(RpcServerError::SendError)?;
                if done {
                    break;
                }
            }
            Ok(())
        };
        // wait until either the rpc future or the forwarder future completes.
        //
        // the forwarder will complete only when there is a send error.
        // the rpc future will complete when the rpc is done.
        async move {
            tokio::select! {
                res = fut => res,
                res = forwarder => res,
            }
        }
        .boxed()
    }
}
