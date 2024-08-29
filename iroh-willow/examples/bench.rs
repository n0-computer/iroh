use std::time::Instant;

use anyhow::Result;
use futures_lite::StreamExt;
use iroh_willow::{
    interest::Interests,
    proto::grouping::Range3d,
    session::{intents::Completion, SessionInit, SessionMode},
};
use tracing::info;

use self::util::{create_rng, insert, parse_env_var, setup_and_delegate, spawn_two};

#[tokio::main]
async fn main() -> Result<()> {
    let t = Instant::now();
    tracing_subscriber::fmt::init();
    let n_betty: usize = parse_env_var("N_BETTY", 100);
    let n_alfie: usize = parse_env_var("N_ALFIE", 100);
    let mut rng = create_rng("peer_manager_two_intents");

    let start = Instant::now();
    let [alfie, betty] = spawn_two(&mut rng).await?;
    let (namespace, alfie_user, betty_user) = setup_and_delegate(&alfie, &betty).await?;
    info!(t=?t.elapsed(), d=?start.elapsed(), "setup done");

    let start = Instant::now();
    for i in 0..n_alfie {
        let x = format!("{i}");
        insert(
            &alfie,
            namespace,
            alfie_user,
            &[b"alfie", x.as_bytes()],
            "foo",
        )
        .await?;
    }
    for i in 0..n_betty {
        let x = format!("{i}");
        insert(
            &betty,
            namespace,
            betty_user,
            &[b"betty", x.as_bytes()],
            "foo",
        )
        .await?;
    }
    info!(t=?t.elapsed(), d=?start.elapsed(), "insert done");

    let start = Instant::now();
    let init = SessionInit::new(Interests::all(), SessionMode::ReconcileOnce);
    let mut intent_alfie = alfie
        .sync_with_peer(betty.node_id(), init.clone())
        .await
        .unwrap();
    let mut intent_betty = betty.sync_with_peer(alfie.node_id(), init).await.unwrap();
    let completion_alfie = intent_alfie.complete().await?;
    // info!(t=?t.elapsed(), d=?start.elapsed(), "alfie done");
    // let start = Instant::now();
    let completion_betty = intent_betty.complete().await?;
    info!(t=?t.elapsed(), d=?start.elapsed(), "sync done");

    let time = start.elapsed();
    let total = n_alfie + n_betty;
    let per_entry = time.as_micros() / total as u128;
    let entries_per_second = (total as f32 / time.as_secs_f32()).round();
    info!(time=?time, ms_per_entry=per_entry, entries_per_second, "sync done");

    assert_eq!(completion_alfie, Completion::Complete);
    assert_eq!(completion_betty, Completion::Complete);
    let start = Instant::now();
    let alfie_count = alfie
        .get_entries(namespace, Range3d::new_full())
        .await?
        .count()
        .await;
    let betty_count = betty
        .get_entries(namespace, Range3d::new_full())
        .await?
        .count()
        .await;
    info!(t=?t.elapsed(), d=?start.elapsed(), "get done");
    info!("alfie has now {} entries", alfie_count);
    info!("betty has now {} entries", betty_count);
    assert_eq!(alfie_count, n_alfie + n_betty);
    assert_eq!(betty_count, n_alfie + n_betty);
    alfie.shutdown().await?;
    betty.shutdown().await?;

    Ok(())
}

mod util {
    use std::sync::{Arc, Mutex};

    use anyhow::Result;
    use bytes::Bytes;
    use futures_concurrency::future::TryJoin;
    use iroh_net::{Endpoint, NodeId};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use rand_core::CryptoRngCore;
    use tokio::task::JoinHandle;

    use iroh_willow::{
        engine::{AcceptOpts, Engine},
        form::EntryForm,
        interest::{CapSelector, DelegateTo, RestrictArea},
        proto::{
            data_model::{Path, PathExt},
            keys::{NamespaceId, NamespaceKind, UserId},
            meadowcap::AccessMode,
        },
        ALPN,
    };

    pub fn create_rng(seed: &str) -> ChaCha12Rng {
        let seed = iroh_base::hash::Hash::new(seed);
        ChaCha12Rng::from_seed(*(seed.as_bytes()))
    }

    #[derive(Debug, Clone)]
    pub struct Peer {
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
                .relay_mode(iroh_net::relay::RelayMode::Disabled)
                .alpns(vec![ALPN.to_vec()])
                .bind(0)
                .await?;
            let blobs = iroh_blobs::store::mem::Store::default();
            let create_store = move || iroh_willow::store::memory::Store::new(blobs);
            let engine = Engine::spawn(endpoint.clone(), create_store, accept_opts);
            let accept_task = tokio::task::spawn({
                let engine = engine.clone();
                let endpoint = endpoint.clone();
                async move {
                    while let Some(incoming) = endpoint.accept().await {
                        let Ok(mut connecting) = incoming.accept() else {
                            continue;
                        };
                        let Ok(alpn) = connecting.alpn().await else {
                            continue;
                        };
                        if alpn != ALPN {
                            continue;
                        }
                        let Ok(conn) = connecting.await else {
                            continue;
                        };
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

    pub async fn spawn_two(rng: &mut impl CryptoRngCore) -> Result<[Peer; 2]> {
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

    pub async fn setup_and_delegate(
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
                CapSelector::any(namespace_id),
                AccessMode::Write,
                DelegateTo::new(user_betty, RestrictArea::None),
            )
            .await?;

        betty.import_caps(cap_for_betty).await?;
        Ok((namespace_id, user_alfie, user_betty))
    }

    pub async fn insert(
        handle: &Engine,
        namespace_id: NamespaceId,
        user: UserId,
        path: &[&[u8]],
        bytes: impl Into<Bytes>,
    ) -> Result<()> {
        let path = Path::from_bytes(path)?;
        let entry = EntryForm::new_bytes(namespace_id, path, bytes);
        handle.insert_entry(entry, user).await?;
        Ok(())
    }

    pub fn parse_env_var<T>(var: &str, default: T) -> T
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Debug,
    {
        match std::env::var(var).as_deref() {
            Ok(val) => val
                .parse()
                .unwrap_or_else(|_| panic!("failed to parse environment variable {var}")),
            Err(_) => default,
        }
    }
}

// use std::{collections::BTreeSet, time::Instant};
//
// use futures_lite::StreamExt;
// use iroh_base::key::SecretKey;
// use iroh_net::{Endpoint, NodeAddr, NodeId};
// use rand::SeedableRng;
// use tracing::info;
//
// use iroh_willow::{
//     actor::ActorHandle,
//     auth::{CapSelector, DelegateTo},
//     form::{AuthForm, EntryForm, PayloadForm, SubspaceForm, TimestampForm},
//     net::run,
//     proto::{
//         grouping::ThreeDRange,
//         keys::{NamespaceId, NamespaceKind, UserId},
//         meadowcap::AccessMode,
//         willow::{Entry, InvalidPath, Path},
//     },
//     session::{Interests, Role, SessionInit, SessionMode},
// };
//
// const ALPN: &[u8] = b"iroh-willow/0";
//
// #[tokio::main(flavor = "multi_thread")]
// async fn main() -> anyhow::Result<()> {
//     tracing_subscriber::fmt::init();
//     let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(1);
//     let n_betty = parse_env_var("N_BETTY", 100);
//     let n_alfie = parse_env_var("N_ALFIE", 100);
//
//     let (ep_alfie, node_id_alfie, _) = create_endpoint(&mut rng).await?;
//     let (ep_betty, node_id_betty, addr_betty) = create_endpoint(&mut rng).await?;
//
//     let start = Instant::now();
//     let mut expected_entries = BTreeSet::new();
//
//     let handle_alfie = ActorHandle::spawn_memory(Default::default(), node_id_alfie);
//     let handle_betty = ActorHandle::spawn_memory(Default::default(), node_id_betty);
//
//     let user_alfie = handle_alfie.create_user().await?;
//     let user_betty = handle_betty.create_user().await?;
//
//     let namespace_id = handle_alfie
//         .create_namespace(NamespaceKind::Owned, user_alfie)
//         .await?;
//
//     let cap_for_betty = handle_alfie
//         .delegate_caps(
//             CapSelector::widest(namespace_id),
//             AccessMode::Write,
//             DelegateTo::new(user_betty, None),
//         )
//         .await?;
//
//     handle_betty.import_caps(cap_for_betty).await?;
//
//     insert(
//         &handle_alfie,
//         namespace_id,
//         user_alfie,
//         n_alfie,
//         |n| Path::new(&[b"alfie", n.to_string().as_bytes()]),
//         |n| format!("alfie{n}"),
//         &mut expected_entries,
//     )
//     .await?;
//
//     insert(
//         &handle_betty,
//         namespace_id,
//         user_betty,
//         n_betty,
//         |n| Path::new(&[b"betty", n.to_string().as_bytes()]),
//         |n| format!("betty{n}"),
//         &mut expected_entries,
//     )
//     .await?;
//
//     let init_alfie = SessionInit::new(Interests::All, SessionMode::ReconcileOnce);
//     let init_betty = SessionInit::new(Interests::All, SessionMode::ReconcileOnce);
//
//     info!("init took {:?}", start.elapsed());
//
//     let start = Instant::now();
//     let (conn_alfie, conn_betty) = tokio::join!(
//         async move { ep_alfie.connect(addr_betty, ALPN).await.unwrap() },
//         async move { ep_betty.accept().await.unwrap().await.unwrap() }
//     );
//     info!("connecting took {:?}", start.elapsed());
//
//     let start = Instant::now();
//     let (session_alfie, session_betty) = tokio::join!(
//         run(
//             node_id_alfie,
//             handle_alfie.clone(),
//             conn_alfie,
//             Role::Alfie,
//             init_alfie
//         ),
//         run(
//             node_id_betty,
//             handle_betty.clone(),
//             conn_betty,
//             Role::Betty,
//             init_betty
//         )
//     );
//     let mut session_alfie = session_alfie?;
//     let mut session_betty = session_betty?;
//     let (res_alfie, res_betty) = tokio::join!(session_alfie.join(), session_betty.join());
//     info!(time=?start.elapsed(), "reconciliation finished");
//
//     info!("alfie res {:?}", res_alfie);
//     info!("betty res {:?}", res_betty);
//     assert!(res_alfie.is_ok());
//     assert!(res_betty.is_ok());
//     let alfie_entries = get_entries(&handle_alfie, namespace_id).await?;
//     let betty_entries = get_entries(&handle_betty, namespace_id).await?;
//     info!("alfie has now {} entries", alfie_entries.len());
//     info!("betty has now {} entries", betty_entries.len());
//     // not using assert_eq because it would print a lot in case of failure
//     assert!(alfie_entries == expected_entries, "alfie expected entries");
//     assert!(betty_entries == expected_entries, "betty expected entries");
//
//     Ok(())
// }
//
// pub async fn create_endpoint(
//     rng: &mut rand_chacha::ChaCha12Rng,
// ) -> anyhow::Result<(Endpoint, NodeId, NodeAddr)> {
//     let ep = Endpoint::builder()
//         .secret_key(SecretKey::generate_with_rng(rng))
//         .alpns(vec![ALPN.to_vec()])
//         .bind(0)
//         .await?;
//     let addr = ep.node_addr().await?;
//     let node_id = ep.node_id();
//     Ok((ep, node_id, addr))
// }
//
// async fn get_entries(
//     store: &ActorHandle,
//     namespace: NamespaceId,
// ) -> anyhow::Result<BTreeSet<Entry>> {
//     let entries: anyhow::Result<BTreeSet<_>> = store
//         .get_entries(namespace, ThreeDRange::full())
//         .await?
//         .try_collect()
//         .await;
//     entries
// }
//
// async fn insert(
//     handle: &ActorHandle,
//     namespace_id: NamespaceId,
//     user_id: UserId,
//     count: usize,
//     path_fn: impl Fn(usize) -> Result<Path, InvalidPath>,
//     content_fn: impl Fn(usize) -> String,
//     track_entries: &mut impl Extend<Entry>,
// ) -> anyhow::Result<()> {
//     for i in 0..count {
//         let payload = content_fn(i).as_bytes().to_vec();
//         let path = path_fn(i).expect("invalid path");
//         let entry = EntryForm {
//             namespace_id,
//             subspace_id: SubspaceForm::User,
//             path,
//             timestamp: TimestampForm::Now,
//             payload: PayloadForm::Bytes(payload.into()),
//         };
//         let (entry, inserted) = handle.insert(entry, AuthForm::Any(user_id)).await?;
//         assert!(inserted);
//         track_entries.extend([entry]);
//     }
//     Ok(())
// }
//
// fn parse_env_var<T>(var: &str, default: T) -> T
// where
//     T: std::str::FromStr,
//     T::Err: std::fmt::Debug,
// {
//     match std::env::var(var).as_deref() {
//         Ok(val) => val
//             .parse()
//             .unwrap_or_else(|_| panic!("failed to parse environment variable {var}")),
//         Err(_) => default,
//     }
// }
//
// // async fn get_entries_debug(
// //     store: &StoreHandle,
// //     namespace: NamespaceId,
// // ) -> anyhow::Result<Vec<(SubspaceId, Path)>> {
// //     let entries = get_entries(store, namespace).await?;
// //     let mut entries: Vec<_> = entries
// //         .into_iter()
// //         .map(|e| (e.subspace_id, e.path))
// //         .collect();
// //     entries.sort();
// //     Ok(entries)
// // }
// //
// //
// //
// // tokio::task::spawn({
// //     let handle_alfie = handle_alfie.clone();
// //     let handle_betty = handle_betty.clone();
// //     async move {
// //         loop {
// //             info!(
// //                 "alfie count: {}",
// //                 handle_alfie
// //                     .get_entries(namespace_id, ThreeDRange::full())
// //                     .await
// //                     .unwrap()
// //                     .count()
// //                     .await
// //             );
// //             info!(
// //                 "betty count: {}",
// //                 handle_betty
// //                     .get_entries(namespace_id, ThreeDRange::full())
// //                     .await
// //                     .unwrap()
// //                     .count()
// //                     .await
// //             );
// //             tokio::time::sleep(Duration::from_secs(1)).await;
// //         }
// //     }
// // });
