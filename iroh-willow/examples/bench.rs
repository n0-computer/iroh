fn main() {}

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
