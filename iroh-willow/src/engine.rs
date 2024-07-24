use anyhow::Result;
use iroh_net::{endpoint::Connection, util::SharedAbortingJoinHandle, Endpoint, NodeId};
use tokio::sync::mpsc;
use tracing::{error_span, Instrument};

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

#[derive(Debug, Clone)]
pub struct Engine {
    actor_handle: ActorHandle,
    peer_manager_inbox: mpsc::Sender<peer_manager::Input>,
    _peer_manager_handle: SharedAbortingJoinHandle<Result<(), String>>,
}

impl Engine {
    pub fn spawn<S: Storage>(
        endpoint: Endpoint,
        create_store: impl 'static + Send + FnOnce() -> S,
        accept_opts: AcceptOpts,
    ) -> Self {
        let me = endpoint.node_id();
        let actor = ActorHandle::spawn(create_store, me);
        let (pm_inbox_tx, pm_inbox_rx) = mpsc::channel(PEER_MANAGER_INBOX_CAP);
        let peer_manager = PeerManager::new(actor.clone(), endpoint, pm_inbox_rx, accept_opts);
        let peer_manager_handle = tokio::task::spawn(
            async move { peer_manager.run().await.map_err(|err| format!("{err:?}")) }
                .instrument(error_span!("peer_manager", me = me.fmt_short())),
        );
        Engine {
            actor_handle: actor,
            peer_manager_inbox: pm_inbox_tx,
            _peer_manager_handle: peer_manager_handle.into(),
        }
    }

    pub async fn handle_connection(&self, conn: Connection) -> Result<()> {
        self.peer_manager_inbox
            .send(peer_manager::Input::HandleConnection { conn })
            .await?;
        Ok(())
    }

    pub async fn sync_with_peer(&self, peer: NodeId, init: SessionInit) -> Result<IntentHandle> {
        let (intent, handle) = Intent::new(init);
        self.peer_manager_inbox
            .send(peer_manager::Input::SubmitIntent { peer, intent })
            .await?;
        Ok(handle)
    }
}

impl std::ops::Deref for Engine {
    type Target = ActorHandle;

    fn deref(&self) -> &Self::Target {
        &self.actor_handle
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use anyhow::Result;
    use bytes::Bytes;
    use futures_concurrency::future::TryJoin;
    use futures_lite::StreamExt;
    use iroh_net::{Endpoint, NodeId};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use rand_core::CryptoRngCore;
    use tokio::task::JoinHandle;

    use crate::{
        auth::{CapSelector, DelegateTo},
        engine::{AcceptOpts, Engine},
        form::EntryForm,
        net::ALPN,
        proto::{
            grouping::Area,
            keys::{NamespaceId, NamespaceKind, UserId},
            meadowcap::AccessMode,
            willow::Path,
        },
        session::{intents::EventKind, Interests, SessionInit, SessionMode},
    };

    fn create_rng(seed: &str) -> ChaCha12Rng {
        let seed = iroh_base::hash::Hash::new(seed);
        ChaCha12Rng::from_seed(*(seed.as_bytes()))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_manager_two_intents() -> Result<()> {
        iroh_test::logging::setup_multithreaded();
        let mut rng = create_rng("peer_manager_two_intents");

        let [alfie, betty] = spawn_two(&mut rng).await?;
        let (namespace, _alfie_user, betty_user) = setup_and_delegate(&alfie, &betty).await?;
        let betty_node_id = betty.node_id();

        insert(&betty, namespace, betty_user, &[b"foo", b"1"], "foo 1").await?;
        insert(&betty, namespace, betty_user, &[b"bar", b"2"], "bar 2").await?;
        insert(&betty, namespace, betty_user, &[b"bar", b"3"], "bar 3").await?;

        let task_foo_path = tokio::task::spawn({
            let alfie = alfie.clone();
            async move {
                let path = Path::new(&[b"foo"]).unwrap();

                let interests = Interests::select().area(namespace, [Area::path(path.clone())]);
                let init = SessionInit::new(interests, SessionMode::ReconcileOnce);
                let mut intent = alfie.sync_with_peer(betty_node_id, init).await.unwrap();

                assert_eq!(
                    intent.next().await.unwrap(),
                    EventKind::CapabilityIntersection {
                        namespace,
                        area: Area::full(),
                    }
                );

                assert_eq!(
                    intent.next().await.unwrap(),
                    EventKind::InterestIntersection {
                        namespace,
                        area: Area::path(path.clone()).into()
                    }
                );

                assert_eq!(
                    intent.next().await.unwrap(),
                    EventKind::Reconciled {
                        namespace,
                        area: Area::path(path.clone()).into()
                    }
                );

                assert_eq!(intent.next().await.unwrap(), EventKind::ReconciledAll);

                assert!(intent.next().await.is_none());
            }
        });

        let task_bar_path = tokio::task::spawn({
            let alfie = alfie.clone();
            async move {
                let path = Path::new(&[b"bar"]).unwrap();

                let interests = Interests::select().area(namespace, [Area::path(path.clone())]);
                let init = SessionInit::new(interests, SessionMode::ReconcileOnce);

                let mut intent = alfie.sync_with_peer(betty_node_id, init).await.unwrap();

                assert_eq!(
                    intent.next().await.unwrap(),
                    EventKind::CapabilityIntersection {
                        namespace,
                        area: Area::full(),
                    }
                );

                assert_eq!(
                    intent.next().await.unwrap(),
                    EventKind::InterestIntersection {
                        namespace,
                        area: Area::path(path.clone()).into()
                    }
                );

                assert_eq!(
                    intent.next().await.unwrap(),
                    EventKind::Reconciled {
                        namespace,
                        area: Area::path(path.clone()).into()
                    }
                );

                assert_eq!(intent.next().await.unwrap(), EventKind::ReconciledAll);

                assert!(intent.next().await.is_none());
            }
        });

        task_foo_path.await.unwrap();
        task_bar_path.await.unwrap();

        [alfie, betty].map(Peer::shutdown).try_join().await?;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_manager_update_intent() -> Result<()> {
        iroh_test::logging::setup_multithreaded();
        let mut rng = create_rng("peer_manager_update_intent");

        let [alfie, betty] = spawn_two(&mut rng).await?;
        let (namespace, _alfie_user, betty_user) = setup_and_delegate(&alfie, &betty).await?;
        let betty_node_id = betty.node_id();

        insert(&betty, namespace, betty_user, &[b"foo"], "foo 1").await?;
        insert(&betty, namespace, betty_user, &[b"bar"], "bar 1").await?;

        let path = Path::new(&[b"foo"]).unwrap();
        let interests = Interests::select().area(namespace, [Area::path(path.clone())]);
        let init = SessionInit::new(interests, SessionMode::Live);
        let mut intent = alfie.sync_with_peer(betty_node_id, init).await.unwrap();

        assert_eq!(
            intent.next().await.unwrap(),
            EventKind::CapabilityIntersection {
                namespace,
                area: Area::full(),
            }
        );
        assert_eq!(
            intent.next().await.unwrap(),
            EventKind::InterestIntersection {
                namespace,
                area: Area::path(path.clone()).into()
            }
        );
        assert_eq!(
            intent.next().await.unwrap(),
            EventKind::Reconciled {
                namespace,
                area: Area::path(path.clone()).into()
            }
        );
        assert_eq!(intent.next().await.unwrap(), EventKind::ReconciledAll);

        let path = Path::new(&[b"bar"]).unwrap();
        let interests = Interests::select().area(namespace, [Area::path(path.clone())]);
        intent.add_interests(interests).await?;

        assert_eq!(
            intent.next().await.unwrap(),
            EventKind::InterestIntersection {
                namespace,
                area: Area::path(path.clone()).into()
            }
        );
        assert_eq!(
            intent.next().await.unwrap(),
            EventKind::Reconciled {
                namespace,
                area: Area::path(path.clone()).into()
            }
        );

        assert_eq!(intent.next().await.unwrap(), EventKind::ReconciledAll);

        intent.close().await;

        assert!(intent.next().await.is_none(),);

        [alfie, betty].map(Peer::shutdown).try_join().await?;
        Ok(())
    }

    #[derive(Debug, Clone)]
    struct Peer {
        endpoint: Endpoint,
        engine: Engine,
        accept_task: Arc<Mutex<Option<JoinHandle<Result<()>>>>>,
    }

    impl Peer {
        pub async fn spawn(
            secret_key: iroh_net::key::SecretKey,
            accept_opts: AcceptOpts,
        ) -> Result<Self> {
            let endpoint = Endpoint::builder()
                .secret_key(secret_key)
                .alpns(vec![ALPN.to_vec()])
                .bind(0)
                .await?;
            let payloads = iroh_blobs::store::mem::Store::default();
            let create_store = move || crate::store::memory::Store::new(payloads);
            let engine = Engine::spawn(endpoint.clone(), create_store, accept_opts);
            let accept_task = tokio::task::spawn({
                let engine = engine.clone();
                let endpoint = endpoint.clone();
                async move {
                    while let Some(mut conn) = endpoint.accept().await {
                        let alpn = conn.alpn().await?;
                        if alpn != ALPN {
                            continue;
                        }
                        let conn = conn.await?;
                        engine.handle_connection(conn).await?;
                    }
                    Result::Ok(())
                }
            });
            Ok(Self {
                endpoint,
                engine,
                accept_task: Arc::new(Mutex::new(Some(accept_task))),
            })
        }

        pub async fn shutdown(self) -> Result<()> {
            let accept_task = self.accept_task.lock().unwrap().take();
            if let Some(accept_task) = accept_task {
                accept_task.abort();
                match accept_task.await {
                    Err(err) if err.is_cancelled() => {}
                    Ok(Ok(())) => {}
                    Err(err) => Err(err)?,
                    Ok(Err(err)) => Err(err)?,
                }
            }
            self.engine.shutdown().await?;
            self.endpoint.close(0u8.into(), b"").await?;
            Ok(())
        }

        pub fn node_id(&self) -> NodeId {
            self.endpoint.node_id()
        }
    }

    impl std::ops::Deref for Peer {
        type Target = Engine;
        fn deref(&self) -> &Self::Target {
            &self.engine
        }
    }

    async fn spawn_two(rng: &mut impl CryptoRngCore) -> Result<[Peer; 2]> {
        let peers = [
            iroh_net::key::SecretKey::generate_with_rng(rng),
            iroh_net::key::SecretKey::generate_with_rng(rng),
        ]
        .map(|secret_key| Peer::spawn(secret_key, Default::default()))
        .try_join()
        .await?;

        peers[0]
            .endpoint
            .add_node_addr(peers[1].endpoint.node_addr().await?)?;

        peers[1]
            .endpoint
            .add_node_addr(peers[0].endpoint.node_addr().await?)?;

        Ok(peers)
    }

    async fn setup_and_delegate(
        alfie: &Engine,
        betty: &Engine,
    ) -> Result<(NamespaceId, UserId, UserId)> {
        let user_alfie = alfie.create_user().await?;
        let user_betty = betty.create_user().await?;

        let namespace_id = alfie
            .create_namespace(NamespaceKind::Owned, user_alfie)
            .await?;

        let cap_for_betty = alfie
            .delegate_caps(
                CapSelector::widest(namespace_id),
                AccessMode::Write,
                DelegateTo::new(user_betty, None),
            )
            .await?;

        betty.import_caps(cap_for_betty).await?;
        Ok((namespace_id, user_alfie, user_betty))
    }

    async fn insert(
        handle: &Engine,
        namespace_id: NamespaceId,
        user: UserId,
        path: &[&[u8]],
        bytes: impl Into<Bytes>,
    ) -> Result<()> {
        let path = Path::new(path)?;
        let entry = EntryForm::new_bytes(namespace_id, path, bytes);
        handle.insert(entry, user).await?;
        Ok(())
    }
}
