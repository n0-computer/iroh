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

pub use self::actor::ActorHandle;
pub use self::peer_manager::PeerManager;

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
    ) -> Self {
        let me = endpoint.node_id();
        let actor = ActorHandle::spawn(create_store, me);
        let (pm_inbox_tx, pm_inbox_rx) = mpsc::channel(PEER_MANAGER_INBOX_CAP);
        let peer_manager = PeerManager::new(actor.clone(), endpoint, pm_inbox_rx);
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
    use bytes::Bytes;
    use iroh_net::{Endpoint, NodeId};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    use crate::{
        auth::{CapSelector, DelegateTo},
        engine::Engine,
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
        rand_chacha::ChaCha12Rng::from_seed(*(seed.as_bytes()))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_manager_two_intents() -> anyhow::Result<()> {
        iroh_test::logging::setup_multithreaded();
        let mut rng = create_rng("peer_manager_two_intents");
        let (
            shutdown,
            namespace,
            (alfie, _alfie_node_id, _alfie_user),
            (betty, betty_node_id, betty_user),
        ) = create_and_setup_two(&mut rng).await?;

        insert(&betty, namespace, betty_user, &[b"foo", b"1"], "foo 1").await?;
        insert(&betty, namespace, betty_user, &[b"bar", b"2"], "bar 2").await?;
        insert(&betty, namespace, betty_user, &[b"bar", b"3"], "bar 3").await?;

        let task_foo = tokio::task::spawn({
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

        let task_bar = tokio::task::spawn({
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

        task_foo.await.unwrap();
        task_bar.await.unwrap();
        shutdown();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_manager_update_intent() -> anyhow::Result<()> {
        iroh_test::logging::setup_multithreaded();
        let mut rng = create_rng("peer_manager_update_intent");
        let (
            shutdown,
            namespace,
            (alfie, _alfie_node_id, _alfie_user),
            (betty, betty_node_id, betty_user),
        ) = create_and_setup_two(&mut rng).await?;

        insert(&betty, namespace, betty_user, &[b"foo"], "foo 1").await?;
        insert(&betty, namespace, betty_user, &[b"bar"], "bar 1").await?;

        let path = Path::new(&[b"foo"]).unwrap();
        let interests = Interests::select().area(namespace, [Area::path(path.clone())]);
        let init = SessionInit::new(interests, SessionMode::Live);
        let mut intent = alfie.sync_with_peer(betty_node_id, init).await.unwrap();

        println!("start");
        assert_eq!(
            intent.next().await.unwrap(),
            EventKind::CapabilityIntersection {
                namespace,
                area: Area::full(),
            }
        );
        println!("first in!");
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

        shutdown();
        Ok(())
    }

    pub async fn create_and_setup_two(
        rng: &mut rand_chacha::ChaCha12Rng,
    ) -> anyhow::Result<(
        impl Fn(),
        NamespaceId,
        (Engine, NodeId, UserId),
        (Engine, NodeId, UserId),
    )> {
        let (alfie, alfie_ep, alfie_addr, alfie_task) = create(rng).await?;
        let (betty, betty_ep, betty_addr, betty_task) = create(rng).await?;

        let betty_node_id = betty_addr.node_id;
        let alfie_node_id = alfie_addr.node_id;
        alfie_ep.add_node_addr(betty_addr)?;
        betty_ep.add_node_addr(alfie_addr)?;

        let (namespace_id, alfie_user, betty_user) = setup_and_delegate(&alfie, &betty).await?;

        let shutdown = move || {
            betty_task.abort();
            alfie_task.abort();
        };
        Ok((
            shutdown,
            namespace_id,
            (alfie, alfie_node_id, alfie_user),
            (betty, betty_node_id, betty_user),
        ))
    }

    pub async fn create(
        rng: &mut rand_chacha::ChaCha12Rng,
    ) -> anyhow::Result<(
        Engine,
        Endpoint,
        iroh_net::NodeAddr,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    )> {
        let endpoint = Endpoint::builder()
            .secret_key(iroh_net::key::SecretKey::generate_with_rng(rng))
            .alpns(vec![ALPN.to_vec()])
            .bind(0)
            .await?;
        let node_addr = endpoint.node_addr().await?;
        let payloads = iroh_blobs::store::mem::Store::default();
        let create_store = move || crate::store::memory::Store::new(payloads);
        let handle = Engine::spawn(endpoint.clone(), create_store);
        let accept_task = tokio::task::spawn({
            let handle = handle.clone();
            let endpoint = endpoint.clone();
            async move {
                while let Some(mut conn) = endpoint.accept().await {
                    let alpn = conn.alpn().await?;
                    if alpn != ALPN {
                        continue;
                    }
                    let conn = conn.await?;
                    handle.handle_connection(conn).await?;
                }
                Ok::<_, anyhow::Error>(())
            }
        });
        Ok((handle, endpoint, node_addr, accept_task))
    }

    async fn setup_and_delegate(
        alfie: &Engine,
        betty: &Engine,
    ) -> anyhow::Result<(NamespaceId, UserId, UserId)> {
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
    ) -> anyhow::Result<()> {
        let path = Path::new(path)?;
        let entry = EntryForm::new_bytes(namespace_id, path, bytes);
        handle.insert(entry, user).await?;
        Ok(())
    }
}
