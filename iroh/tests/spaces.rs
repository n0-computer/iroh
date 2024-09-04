use std::collections::BTreeMap;

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
    session::{intents::Completion, Role, SessionMode},
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

fn simple_str() -> impl Strategy<Value = String> {
    select(&["alpha", "beta", "gamma"]).prop_map(str::to_string)
}

fn simple_op() -> impl Strategy<Value = Operation> {
    (simple_str(), simple_str()).prop_map(|(key, value)| Operation::Write(key, value))
}

fn role() -> impl Strategy<Value = Role> {
    select(&[Role::Alfie, Role::Betty])
}

#[proptest]
fn test_get_many_weird_result(
    #[strategy(vec((role(), vec(simple_op(), 0..20)), 0..20))] rounds: Vec<(Role, Vec<Operation>)>,
) {
    iroh_test::logging::setup_multithreaded();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut simulated_entries: BTreeMap<(Role, String), String> = BTreeMap::new();

            let (alfie_addr, alfie) = spawn_node().await;
            let (betty_addr, betty) = spawn_node().await;
            info!("alfie is {}", alfie_addr.node_id.fmt_short());
            info!("betty is {}", betty_addr.node_id.fmt_short());
            alfie.net().add_node_addr(betty_addr.clone()).await?;
            betty.net().add_node_addr(alfie_addr.clone()).await?;
            let betty_user = betty.spaces().create_user().await?;
            let alfie_user = alfie.spaces().create_user().await?;
            let alfie_space = alfie
                .spaces()
                .create(NamespaceKind::Owned, alfie_user)
                .await?;

            let ticket = alfie_space
                .share(betty_user, AccessMode::Write, RestrictArea::None)
                .await?;

            // give betty access
            let (betty_space, syncs) = betty
                .spaces()
                .import_and_sync(ticket, SessionMode::ReconcileOnce)
                .await?;

            syncs.complete_all().await;

            for (role, round) in rounds {
                let (space, user, other_node_id) = match role {
                    Role::Alfie => (&alfie_space, alfie_user, betty_addr.node_id),
                    Role::Betty => (&betty_space, betty_user, alfie_addr.node_id),
                };

                for Operation::Write(key, value) in round {
                    space
                        .insert_bytes(
                            EntryForm::new(user, Path::from_bytes(&[key.as_bytes()])?),
                            value.clone().into_bytes(),
                        )
                        .await?;
                    simulated_entries.insert((role, key), value);
                }

                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    space
                        .sync_once(other_node_id, AreaOfInterestSelector::Widest)
                        .await?
                        .complete(),
                )
                .await??;
            }

            let alfie_map = space_to_map(&alfie_space, &alfie, alfie_user, betty_user).await?;
            let betty_map = space_to_map(&betty_space, &betty, alfie_user, betty_user).await?;

            ensure!(
                alfie_map == betty_map,
                "states out of sync:\n{alfie_map:#?}\n !=\n{betty_map:#?}"
            );
            ensure!(
                simulated_entries == alfie_map,
                "alfie in unexpected state:\n{simulated_entries:#?}\n !=\n{alfie_map:#?}"
            );
            // follows transitively, but still
            ensure!(
                simulated_entries == betty_map,
                "betty in unexpected state:\n{simulated_entries:#?}\n !=\n{betty_map:#?}"
            );

            println!("Success!");

            Ok(())
        })
        .map_err(AnyhowStdErr)?;
}

async fn space_to_map(
    space: &Space,
    node: &Iroh,
    alfie_user: UserId,
    betty_user: UserId,
) -> anyhow::Result<BTreeMap<(Role, String), String>> {
    let role_lookup = BTreeMap::from([(alfie_user, Role::Alfie), (betty_user, Role::Betty)]);
    let entries = space
        .get_many(Range3d::new_full())
        .await?
        .try_collect::<_, _, Vec<_>>()
        .await?;
    let mut map: BTreeMap<(Role, String), String> = BTreeMap::new();
    for auth_entry in entries {
        let (entry, auth) = auth_entry.into_parts();
        let key_component = entry
            .path()
            .get_component(0)
            .ok_or_else(|| anyhow::anyhow!("path component missing"))?;
        let key = String::from_utf8(key_component.to_vec())?;

        let value = node.blobs().read_to_bytes(entry.payload_digest().0).await?;

        let user = auth.capability.receiver();
        let role = role_lookup
            .get(user)
            .ok_or_else(|| anyhow::anyhow!("foreign write?"))?;

        map.insert((*role, key), String::from_utf8_lossy(&value).to_string());
    }

    Ok(map)
}

#[derive(Debug)]
struct AnyhowStdErr(anyhow::Error);

impl std::fmt::Display for AnyhowStdErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
