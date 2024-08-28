use anyhow::Result;
use futures_lite::StreamExt;
use iroh::client::{spaces::EntryForm, Iroh};
use iroh_net::{key::SecretKey, NodeAddr};
use iroh_willow::{
    interest::{CapSelector, DelegateTo, RestrictArea},
    proto::{
        data_model::{Path, PathExt},
        grouping::{Area, Range3d},
        keys::NamespaceKind,
        meadowcap::AccessMode,
    },
    session::intents::Completion,
};
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

#[tokio::test]
async fn spaces_smoke() -> Result<()> {
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
    let (betty_space, betty_sync_intent) = betty.spaces().import_and_sync(ticket).await?;

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
