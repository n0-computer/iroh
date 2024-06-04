use std::{io, time::Duration};

use bao_tree::blake3;
use bytes::Bytes;
use iroh::{
    client::blobs::{AddDirOpts, WrapOption},
    node::GcPolicy,
};
use iroh_blobs::store::mem::Store;

async fn create_node() -> anyhow::Result<iroh::node::Node<Store>> {
    iroh::node::Node::memory()
        .gc_policy(GcPolicy::Interval(Duration::from_millis(10)))
        .spawn()
        .await
}

async fn wait_for_gc() {
    // wait for multiple gc cycles to ensure that the data is actually gone
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// Test that add_bytes adds the right data
#[tokio::test]
async fn add_bytes() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let data: &[u8] = b"test";
    let tag = batch.add_bytes(data).await?;
    let hash = *tag.hash();
    let actual = client.read_to_bytes(hash).await?;
    assert_eq!(hash, blake3::hash(data).into());
    assert_eq!(actual.as_ref(), data);
    Ok(())
}

/// Test that add_bytes adds the right data
#[tokio::test]
async fn add_stream() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let data: &[u8] = b"test";
    let data_stream = futures_lite::stream::iter([io::Result::Ok(Bytes::copy_from_slice(data))]);
    let tag = batch.add_stream(data_stream).await?;
    let hash = *tag.hash();
    let actual = client.read_to_bytes(hash).await?;
    assert_eq!(hash, blake3::hash(data).into());
    assert_eq!(actual.as_ref(), data);
    Ok(())
}

/// Test that add_file adds the right data
#[tokio::test]
async fn add_file() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let dir = tempfile::tempdir()?;
    let temp_path = dir.path().join("test");
    std::fs::write(&temp_path, b"test")?;
    let (tag, _) = batch.add_file(temp_path).await?;
    let hash = *tag.hash();
    let actual = client.read_to_bytes(hash).await?;
    assert_eq!(hash, blake3::hash(b"test").into());
    assert_eq!(actual.as_ref(), b"test");
    Ok(())
}

/// Tests that add_dir adds the right data
#[tokio::test]
async fn add_dir() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let dir = tempfile::tempdir()?;
    let data: [(&str, &[u8]); 2] = [("test1", b"test1"), ("test2", b"test2")];
    for (name, content) in &data {
        let temp_path = dir.path().join(name);
        std::fs::write(&temp_path, content)?;
    }
    let tag = batch.add_dir(dir.path().to_owned()).await?;
    assert!(client.has(*tag.hash()).await?);
    for (_, content) in &data {
        let hash = blake3::hash(content).into();
        let data = client.read_to_bytes(hash).await?;
        assert_eq!(data.as_ref(), *content);
    }
    Ok(())
}

/// Tests that add_dir adds the right data
#[tokio::test]
async fn add_dir_single_file() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let dir = tempfile::tempdir()?;
    let temp_path = dir.path().join("test");
    let data: &[u8] = b"test";
    std::fs::write(&temp_path, data)?;
    let tag = batch
        .add_dir_with_opts(
            temp_path,
            AddDirOpts {
                wrap: WrapOption::Wrap { name: None },
                ..Default::default()
            },
        )
        .await?;
    assert!(client.read_to_bytes(*tag.hash()).await.is_ok());
    let hash = blake3::hash(data).into();
    let actual_data = client.read_to_bytes(hash).await?;
    assert_eq!(actual_data.as_ref(), data);
    Ok(())
}

#[tokio::test]
async fn batch_drop() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let data: &[u8] = b"test";
    let tag = batch.add_bytes(data).await?;
    let hash = *tag.hash();
    // Check that the store has the data and that it is protected from gc
    wait_for_gc().await;
    assert!(client.has(hash).await?);
    drop(batch);
    // Check that the store drops the data when the temp tag gets dropped
    wait_for_gc().await;
    assert!(!client.has(hash).await?);
    Ok(())
}

#[tokio::test]
async fn temp_tag_drop() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let data: &[u8] = b"test";
    let tag = batch.add_bytes(data).await?;
    let hash = *tag.hash();
    // Check that the store has the data and that it is protected from gc
    wait_for_gc().await;
    assert!(client.has(hash).await?);
    drop(tag);
    // Check that the store drops the data when the temp tag gets dropped
    wait_for_gc().await;
    assert!(!client.has(hash).await?);
    Ok(())
}

/// Tests that data is preserved if a second temp tag is created for it
/// before the first temp tag is dropped.
#[tokio::test]
async fn temp_tag_copy() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let data: &[u8] = b"test";
    let tag = batch.add_bytes(data).await?;
    let hash = *tag.hash();
    // Check that the store has the data and that it is protected from gc
    wait_for_gc().await;
    assert!(client.has(hash).await?);
    // Create an additional temp tag for the same data
    let tag2 = batch.temp_tag(tag.hash_and_format()).await?;
    drop(tag);
    // Check that the data is still present
    wait_for_gc().await;
    assert!(client.has(hash).await?);
    drop(tag2);
    // Check that the data is gone since both temp tags are dropped
    wait_for_gc().await;
    assert!(!client.has(hash).await?);
    Ok(())
}

/// Tests that temp tags work properly for hash sequences, using add_dir
/// to add the data.
#[tokio::test]
async fn tag_drop_hashseq() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let dir = tempfile::tempdir()?;
    let data: [(&str, &[u8]); 2] = [("test1", b"test1"), ("test2", b"test2")];
    for (name, content) in &data {
        let temp_path = dir.path().join(name);
        std::fs::write(&temp_path, content)?;
    }
    let tag = batch.add_dir(dir.path().to_owned()).await?;
    let hash = *tag.hash();
    // weird signature to avoid async move issues
    let check_present = |present: &'static bool| async {
        assert!(client.has(hash).await? == *present);
        for (_, content) in &data {
            let hash = blake3::hash(content).into();
            assert!(client.has(hash).await? == *present);
        }
        anyhow::Ok(())
    };
    // Check that the store has the data immediately after adding it
    check_present(&true).await?;
    // Check that it is protected from gc
    wait_for_gc().await;
    check_present(&true).await?;
    drop(tag);
    // Check that the store drops the data when the temp tag gets dropped
    wait_for_gc().await;
    check_present(&false).await?;
    Ok(())
}
