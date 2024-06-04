use std::time::Duration;

use bao_tree::blake3;
use iroh::node::GcPolicy;
use iroh_blobs::{store::mem::Store, BlobFormat};

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

#[tokio::test]
async fn test_batch_create_1() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let data: &[u8] = b"test";
    let tag = batch.add_bytes(data, BlobFormat::Raw).await?;
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

#[tokio::test]
async fn test_batch_create_2() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let data: &[u8] = b"test";
    let tag = batch.add_bytes(data, BlobFormat::Raw).await?;
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

/// Tests that data is preserved if a second temp tag is created for it
/// before the first temp tag is dropped.
#[tokio::test]
async fn test_batch_create_3() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let data: &[u8] = b"test";
    let tag = batch.add_bytes(data, BlobFormat::Raw).await?;
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

/// Tests that data goes away when the temp tag is dropped
#[tokio::test]
async fn test_batch_add_file_1() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let dir = tempfile::tempdir()?;
    let temp_path = dir.path().join("test");
    std::fs::write(&temp_path, b"test")?;
    let (tag, _) = batch.add_file(temp_path).await?;
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

/// Tests that data goes away when the batch is dropped
#[tokio::test]
async fn test_batch_add_file_2() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let dir = tempfile::tempdir()?;
    let temp_path = dir.path().join("test");
    std::fs::write(&temp_path, b"test")?;
    let (tag, _) = batch.add_file(temp_path).await?;
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

/// Tests that add_dir adds the right data
#[tokio::test]
async fn test_batch_add_dir_works() -> anyhow::Result<()> {
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
    assert!(client.read_to_bytes(*tag.hash()).await.is_ok());
    for (_, content) in &data {
        let hash = blake3::hash(content).into();
        let data = client.read_to_bytes(hash).await?;
        assert_eq!(data.as_ref(), *content);
    }
    Ok(())
}

/// Tests that temp tags work properly for hash sequences, using add_dir
/// to add the data.
#[tokio::test]
async fn test_batch_add_dir_2() -> anyhow::Result<()> {
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
