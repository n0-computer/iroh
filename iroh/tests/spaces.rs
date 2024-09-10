use std::{collections::BTreeMap, time::Duration};

use anyhow::ensure;
use futures_lite::StreamExt;
use iroh::client::{
    spaces::{EntryForm, Space},
    Iroh,
};
use iroh_net::{key::SecretKey, NodeAddr};
use iroh_willow::{
    interest::{AreaOfInterestSelector, CapSelector, DelegateTo, RestrictArea},
    proto::{
        data_model::{Path, PathExt},
        grouping::{Area, Range3d},
        keys::{NamespaceKind, UserId},
        meadowcap::AccessMode,
    },
    session::{intents::Completion, SessionMode},
    store::traits::{EntryOrigin, StoreEvent},
};
use proptest::{collection::vec, prelude::Strategy, sample::select};
use test_strategy::proptest;
use testresult::TestResult;
use tracing::info;

/// Spawn an iroh node in a separate thread and tokio runtime, and return
/// the address and client.
async fn spawn_node() -> (NodeAddr, Iroh) {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async move {
            let secret_key = SecretKey::generate();
            let node = iroh::node::Builder::default()
                .secret_key(secret_key)
                .relay_mode(iroh_net::relay::RelayMode::Disabled)
                .node_discovery(iroh::node::DiscoveryConfig::None)
                .spawn()
                .await?;
            let addr = node.net().node_addr().await?;
            sender.send((addr, node.client().clone())).unwrap();
            node.cancel_token().cancelled().await;
            anyhow::Ok(())
        })?;
        anyhow::Ok(())
    });
    receiver.await.unwrap()
}

#[derive(Debug, Clone)]
enum Operation {
    Write(String, String),
}

fn simple_key() -> impl Strategy<Value = String> {
    select(&["alpha", "beta", "gamma"]).prop_map(str::to_string)
}

fn simple_value() -> impl Strategy<Value = String> {
    select(&["red", "blue", "green"]).prop_map(str::to_string)
}

fn simple_op() -> impl Strategy<Value = Operation> {
    (simple_key(), simple_value()).prop_map(|(key, value)| Operation::Write(key, value))
}

fn role() -> impl Strategy<Value = Peer> {
    select(&[Peer::X, Peer::Y])
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Ord, PartialOrd)]
enum Peer {
    X,
    Y,
}

#[proptest]
fn test_get_many_weird_result(
    #[strategy(vec((role(), vec(simple_op(), 0..20)), 0..20))] rounds: Vec<(Peer, Vec<Operation>)>,
) {
    iroh_test::logging::setup_multithreaded();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut simulated_entries: BTreeMap<(Peer, String), String> = BTreeMap::new();

            let (addr_x, iroh_x) = spawn_node().await;
            let (addr_y, iroh_y) = spawn_node().await;
            let node_id_x = addr_x.node_id;
            let node_id_y = addr_y.node_id;
            iroh_x.net().add_node_addr(addr_y.clone()).await?;
            iroh_y.net().add_node_addr(addr_x.clone()).await?;
            let user_x = iroh_x.spaces().create_user().await?;
            let user_y = iroh_y.spaces().create_user().await?;
            info!(
                "X is node {} user {}",
                node_id_x.fmt_short(),
                user_x.fmt_short()
            );
            info!(
                "Y is node {} user {}",
                node_id_y.fmt_short(),
                user_y.fmt_short()
            );
            let space_x = iroh_x.spaces().create(NamespaceKind::Owned, user_x).await?;

            let ticket = space_x
                .share(user_y, AccessMode::Write, RestrictArea::None)
                .await?;

            // give betty access
            let (space_y, syncs) = iroh_y
                .spaces()
                .import_and_sync(ticket, SessionMode::ReconcileOnce)
                .await?;

            let mut completions = syncs.complete_all().await;
            assert_eq!(completions.len(), 1);
            let completion = completions.remove(&node_id_x).unwrap();
            assert!(completion.is_ok());
            assert_eq!(completion.unwrap(), Completion::Complete);

            let count = rounds.len();
            for (i, (peer, round)) in rounds.into_iter().enumerate() {
                let i = i + 1;
                let (space, user) = match peer {
                    Peer::X => (&space_x, user_x),
                    Peer::Y => (&space_y, user_y),
                };
                info!(active=?peer, "[{i}/{count}] round start");

                for Operation::Write(key, value) in round {
                    info!(?key, ?value, "[{i}/{count}] write");
                    space
                        .insert_bytes(
                            EntryForm::new(user, Path::from_bytes(&[key.as_bytes()])?),
                            value.clone().into_bytes(),
                        )
                        .await?;
                    simulated_entries.insert((peer, key), value);
                }

                // We sync in both directions. This will only create a single session under the hood.
                // Awaiting both intents ensures that the sync completed on both sides.
                // Alernatively, we could sync from one side only, the result must be the same, however we miss
                // an event in the client currently to know when the betty peer (accepting peer) has finished.
                let fut_x = async {
                    space_x
                        .sync_once(node_id_y, AreaOfInterestSelector::Widest)
                        .await?
                        .complete()
                        .await?;
                    anyhow::Ok(())
                };
                let fut_y = async {
                    space_y
                        .sync_once(node_id_x, AreaOfInterestSelector::Widest)
                        .await?
                        .complete()
                        .await?;
                    anyhow::Ok(())
                };
                let fut = async { tokio::try_join!(fut_x, fut_y) };
                tokio::time::timeout(Duration::from_secs(5), fut).await??;

                info!("[{i}/{count}] sync complete");

                let map_x = space_to_map(&space_x, &iroh_x, user_x, user_y).await?;
                let map_y = space_to_map(&space_y, &iroh_y, user_x, user_y).await?;
                ensure!(
                    map_x == map_y,
                    "states out of sync:\n{map_x:#?}\n !=\n{map_y:#?}"
                );

                ensure!(
                    map_x == map_y,
                    "states out of sync:\n{map_x:#?}\n !=\n{map_y:#?}"
                );
                ensure!(
                    simulated_entries == map_x,
                    "alfie in unexpected state:\n{simulated_entries:#?}\n !=\n{map_x:#?}"
                );
                // follows transitively, but still
                ensure!(
                    simulated_entries == map_y,
                    "betty in unexpected state:\n{simulated_entries:#?}\n !=\n{map_y:#?}"
                );
            }

            info!("completed {count} rounds successfully");

            tokio::try_join!(iroh_x.shutdown(false), iroh_y.shutdown(false))?;

            Ok(())
        })
        .map_err(AnyhowStdErr)?;
}

async fn space_to_map(
    space: &Space,
    node: &Iroh,
    user_x: UserId,
    user_y: UserId,
) -> anyhow::Result<BTreeMap<(Peer, String), String>> {
    let role_lookup = BTreeMap::from([(user_x, Peer::X), (user_y, Peer::Y)]);
    let entries = space
        .get_many(Range3d::new_full())
        .await?
        .try_collect::<_, _, Vec<_>>()
        .await?;
    let mut map: BTreeMap<(Peer, String), String> = BTreeMap::new();
    for auth_entry in entries {
        let (entry, auth) = auth_entry.into_parts();
        let key_component = entry
            .path()
            .get_component(0)
            .ok_or_else(|| anyhow::anyhow!("path component missing"))?;
        let key = String::from_utf8(key_component.to_vec())?;

        let value = node.blobs().read_to_bytes(entry.payload_digest().0).await?;

        let user = auth.capability.receiver();
        let peer = role_lookup
            .get(user)
            .ok_or_else(|| anyhow::anyhow!("foreign write?"))?;

        map.insert((*peer, key), String::from_utf8_lossy(&value).to_string());
    }

    Ok(map)
}

#[derive(Debug)]
struct AnyhowStdErr(anyhow::Error);

impl std::fmt::Display for AnyhowStdErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        println!("FAIL: {self:?}");
        self.0.fmt(f)
    }
}

impl std::error::Error for AnyhowStdErr {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }

    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.source()
    }
}

#[tokio::test]
async fn spaces_smoke() -> TestResult {
    iroh_test::logging::setup_multithreaded();
    let (alfie_addr, alfie) = spawn_node().await;
    let (betty_addr, betty) = spawn_node().await;
    info!("alfie is {}", alfie_addr.node_id.fmt_short());
    info!("betty is {}", betty_addr.node_id.fmt_short());

    let betty_user = betty.spaces().create_user().await?;
    let alfie_user = alfie.spaces().create_user().await?;
    let alfie_space = alfie
        .spaces()
        .create(NamespaceKind::Owned, alfie_user)
        .await?;

    let namespace = alfie_space.namespace_id();

    alfie_space
        .insert_bytes(
            EntryForm::new(alfie_user, Path::from_bytes(&[b"foo", b"bar"])?),
            "hello betty",
        )
        .await?;
    alfie_space
        .insert_bytes(
            EntryForm::new(alfie_user, Path::from_bytes(&[b"foo", b"boo"])?),
            "this is alfie",
        )
        .await?;

    let ticket = alfie_space
        .share(betty_user, AccessMode::Read, RestrictArea::None)
        .await?;

    println!("ticket {ticket:?}");
    let (betty_space, betty_sync_intent) = betty
        .spaces()
        .import_and_sync(ticket, SessionMode::ReconcileOnce)
        .await?;

    let mut completion = betty_sync_intent.complete_all().await;
    assert_eq!(completion.len(), 1);
    let alfie_completion = completion.remove(&alfie_addr.node_id).unwrap();
    assert_eq!(alfie_completion?, Completion::Complete);

    let betty_entries: Vec<_> = betty_space
        .get_many(Range3d::new_full())
        .await?
        .try_collect()
        .await?;
    assert_eq!(betty_entries.len(), 2);

    let res = betty_space
        .insert_bytes(
            EntryForm::new(betty_user, Path::from_bytes(&[b"hello"])?),
            "this is betty",
        )
        .await;
    println!("insert without cap: {res:?}");
    assert!(res.is_err());

    let area = Area::new_subspace(betty_user);
    let caps = alfie
        .spaces()
        .delegate_caps(
            CapSelector::any(namespace),
            AccessMode::Write,
            DelegateTo::new(betty_user, RestrictArea::Restrict(area)),
        )
        .await?;
    betty.spaces().import_caps(caps).await?;

    let res = betty_space
        .insert_bytes(
            EntryForm::new(betty_user, Path::from_bytes(&[b"hello"])?),
            "this is betty",
        )
        .await;
    assert!(res.is_ok());

    alfie.net().add_node_addr(betty_addr.clone()).await?;
    let mut alfie_sync_intent = alfie_space
        .sync_once(betty_addr.node_id, Default::default())
        .await?;
    alfie_sync_intent.complete().await?;

    let alfie_entries: Vec<_> = alfie_space
        .get_many(Range3d::new_full())
        .await?
        .try_collect()
        .await?;
    assert_eq!(alfie_entries.len(), 3);

    Ok(())
}

#[tokio::test]
async fn spaces_subscription() -> TestResult {
    iroh_test::logging::setup_multithreaded();
    let (alfie_addr, alfie) = spawn_node().await;
    let (betty_addr, betty) = spawn_node().await;
    info!("alfie is {}", alfie_addr.node_id.fmt_short());
    info!("betty is {}", betty_addr.node_id.fmt_short());

    let betty_user = betty.spaces().create_user().await?;
    let alfie_user = alfie.spaces().create_user().await?;
    let alfie_space = alfie
        .spaces()
        .create(NamespaceKind::Owned, alfie_user)
        .await?;

    let _namespace = alfie_space.namespace_id();

    let mut alfie_sub = alfie_space
        .subscribe_area(Area::new_full(), Default::default())
        .await?;

    let ticket = alfie_space
        .share(betty_user, AccessMode::Write, RestrictArea::None)
        .await?;

    let (betty_space, betty_sync_intent) = betty
        .spaces()
        .import_and_sync(ticket, SessionMode::Continuous)
        .await?;

    let _sync_task = tokio::task::spawn(async move {
        // TODO: We should add a "detach" method to a sync intent!
        // (leaves the sync running but stop consuming events)
        let _ = betty_sync_intent.complete_all().await;
    });

    let mut betty_sub = betty_space
        .resume_subscription(0, Area::new_full(), Default::default())
        .await?;

    betty_space
        .insert_bytes(
            EntryForm::new(betty_user, Path::from_bytes(&[b"foo"])?),
            "hi",
        )
        .await?;

    let ev = betty_sub.next().await.unwrap().unwrap();
    println!("BETTY 1 {ev:?}");
    assert!(matches!(ev, StoreEvent::Ingested(0, _, EntryOrigin::Local)));

    let ev = alfie_sub.next().await.unwrap().unwrap();
    println!("ALFIE 1 {ev:?}");
    assert!(matches!(
        ev,
        StoreEvent::Ingested(0, _, EntryOrigin::Remote(_))
    ));

    alfie_space
        .insert_bytes(
            EntryForm::new(alfie_user, Path::from_bytes(&[b"bar"])?),
            "hi!!",
        )
        .await?;

    let ev = alfie_sub.next().await.unwrap().unwrap();
    println!("ALFIE 2 {ev:?}");
    assert!(matches!(ev, StoreEvent::Ingested(1, _, EntryOrigin::Local)));

    let ev = betty_sub.next().await.unwrap().unwrap();
    println!("BETTY 2 {ev:?}");
    assert!(matches!(
        ev,
        StoreEvent::Ingested(1, _, EntryOrigin::Remote(_))
    ));

    // let resume_sub = alfie_space
    //     .resume_subscription(0, Area::new_full(), Default::default())
    //     .await?;
    // assert_eq!(resume_sub.count().await, 2);

    Ok(())
}

#[tokio::test]
async fn test_restricted_area() -> testresult::TestResult {
    iroh_test::logging::setup_multithreaded();
    const TIMEOUT: Duration = Duration::from_secs(2);
    let (alfie_addr, alfie) = spawn_node().await;
    let (betty_addr, betty) = spawn_node().await;
    info!("alfie is {}", alfie_addr.node_id.fmt_short());
    info!("betty is {}", betty_addr.node_id.fmt_short());
    let alfie_user = alfie.spaces().create_user().await?;
    let betty_user = betty.spaces().create_user().await?;
    let alfie_space = alfie
        .spaces()
        .create(NamespaceKind::Owned, alfie_user)
        .await?;
    let space_ticket = alfie_space
        .share(
            betty_user,
            AccessMode::Write,
            RestrictArea::Restrict(Area::new_subspace(betty_user)),
        )
        .await?;
    let (betty_space, syncs) = betty
        .spaces()
        .import_and_sync(space_ticket, SessionMode::ReconcileOnce)
        .await?;
    let completion = tokio::time::timeout(TIMEOUT, syncs.complete_all()).await?;
    println!("Completed syncs: {completion:#?}");
    let stream = betty_space.get_many(Range3d::new_full()).await?;
    let entries: Vec<_> = stream.try_collect().await?;
    println!("{entries:#?}");
    Ok(())
}
