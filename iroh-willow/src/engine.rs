//! Engine for driving a willow store and synchronisation sessions.

use anyhow::Result;
use futures_util::{
    future::{MapErr, Shared},
    FutureExt, TryFutureExt,
};
use iroh_net::{endpoint::Connection, Endpoint, NodeId};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinError,
};
use tokio_util::task::AbortOnDropHandle;
use tracing::{debug, error, error_span, Instrument};

use crate::{
    session::{
        intents::{Intent, IntentHandle},
        SessionInit,
    },
    store::traits::Storage,
};

mod actor;
mod peer_manager;

use self::peer_manager::PeerManager;

pub use self::actor::ActorHandle;
pub use self::peer_manager::AcceptOpts;

const PEER_MANAGER_INBOX_CAP: usize = 128;

/// The [`Engine`] is the main handle onto a Willow store with networking.
///
/// It runs a dedicated thread for all storage operations, and a peer manager to coordinate network
/// connections to other peers.
///
/// The engine does not establish any peer connections on its own. Synchronisation sessions can be
/// started with [`Engine::sync_with_peer`].
#[derive(Debug, Clone)]
pub struct Engine {
    actor_handle: ActorHandle,
    peer_manager_inbox: mpsc::Sender<peer_manager::Input>,
    // `Engine` needs to be `Clone + Send`, and we need to `task.await` in its `shutdown()` impl.
    // So we need
    // - `Shared` so we can `task.await` from all `Node` clones
    // - `MapErr` to map the `JoinError` to a `String`, because `JoinError` is `!Clone`
    // - `AbortOnDropHandle` to make sure that the `task` is cancelled when all `Node`s are dropped
    //   (`Shared` acts like an `Arc` around its inner future).
    peer_manager_task: Shared<MapErr<AbortOnDropHandle<Result<(), String>>, JoinErrToStr>>,
}

pub(crate) type JoinErrToStr = Box<dyn Fn(JoinError) -> String + Send + Sync + 'static>;

impl Engine {
    /// Start the Willow engine.
    ///
    /// This needs an `endpoint` to connect to other peers, and a `create_store` closure which
    /// returns a [`Storage`] instance.
    ///
    /// You also need to pass [`AcceptOpts`] to configure what to do with incoming connections.
    /// Its default implementation will accept all connections and run sync with all our interests.
    ///
    /// To actually accept connections, an [`Endpoint::accept`] loop has to be run outside of the
    /// engine, passing all connections that match [`crate::net::ALPN`] to the engine with
    /// [`Engine::handle_connection`].
    ///
    /// The engine will spawn a dedicated storage thread, and the `create_store` closure will be called on
    /// this thread, so that the [`Storage`] does not have to be `Send`.
    pub fn spawn<S: Storage>(
        endpoint: Endpoint,
        create_store: impl 'static + Send + FnOnce() -> S,
        accept_opts: AcceptOpts,
    ) -> Self {
        let me = endpoint.node_id();
        let actor_handle = ActorHandle::spawn(create_store, me);
        let (pm_inbox_tx, pm_inbox_rx) = mpsc::channel(PEER_MANAGER_INBOX_CAP);
        let peer_manager =
            PeerManager::new(actor_handle.clone(), endpoint, pm_inbox_rx, accept_opts);
        let peer_manager_task = tokio::task::spawn(
            async move { peer_manager.run().await.map_err(|e| e.to_string()) }
                .instrument(error_span!("peer_manager", me=%me.fmt_short())),
        );
        let peer_manager_task = AbortOnDropHandle::new(peer_manager_task)
            .map_err(Box::new(|e: JoinError| e.to_string()) as JoinErrToStr)
            .shared();
        Engine {
            actor_handle,
            peer_manager_inbox: pm_inbox_tx,
            peer_manager_task,
        }
    }

    /// Handle an incoming connection.
    pub async fn handle_connection(&self, conn: Connection) -> Result<()> {
        self.peer_manager_inbox
            .send(peer_manager::Input::HandleConnection { conn })
            .await?;
        Ok(())
    }

    /// Synchronises with a peer.
    ///
    /// Will try to establish a connection to `peer` if there is none already, and then open a
    /// synchronisation session.
    ///
    /// `init` contains the initialisation options for this synchronisation intent.
    ///
    /// Returns an [`IntentHandle`] which receives events and can submit updates into the session.
    ///
    /// This can freely be called multiple times for the same peer. The engine will merge the
    /// intents and make sure that only a single session is opened per peer.
    pub async fn sync_with_peer(&self, peer: NodeId, init: SessionInit) -> Result<IntentHandle> {
        let (intent, handle) = Intent::new(init);
        self.peer_manager_inbox
            .send(peer_manager::Input::SubmitIntent { peer, intent })
            .await?;
        Ok(handle)
    }

    /// Shutdown the engine.
    ///
    /// This will try to close all connections gracefully for up to 10 seconds,
    /// and abort them otherwise.
    pub async fn shutdown(mut self) -> Result<()> {
        debug!("shutdown engine");
        let (reply, reply_rx) = oneshot::channel();
        self.peer_manager_inbox
            .send(peer_manager::Input::Shutdown { reply })
            .await?;
        reply_rx.await?;
        let res = (&mut self.peer_manager_task).await;
        match res {
            Err(err) => error!(?err, "peer manager task panicked"),
            Ok(Err(err)) => error!(?err, "peer manager task failed"),
            Ok(Ok(())) => {}
        };
        debug!("shutdown engine: peer manager terminated");
        self.actor_handle.shutdown().await?;
        debug!("shutdown engine: willow actor terminated");
        Ok(())
    }
}

impl std::ops::Deref for Engine {
    type Target = ActorHandle;

    fn deref(&self) -> &Self::Target {
        &self.actor_handle
    }
}
