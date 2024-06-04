use std::time::Duration;

use bao_tree::blake3;
use iroh::client::blobs::{ImportMode, WrapOption};
use iroh::node::GcPolicy;
use iroh_blobs::{store::mem::Store, BlobFormat};

async fn create_node() -> anyhow::Result<iroh::node::Node<Store>> {
    iroh::node::Node::memory()
        .gc_policy(GcPolicy::Interval(Duration::from_millis(10)))
        .spawn()
        .await
}

async fn wait_for_gc() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

#[tokio::test]
async fn test_batch_create_1() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let expected_data: &[u8] = b"test";
    let expected_hash = blake3::hash(expected_data).into();
    let tag = batch.add_bytes(expected_data, BlobFormat::Raw).await?;
    let hash = *tag.hash();
    assert_eq!(hash, expected_hash);
    // Check that the store has the data and that it is protected from gc
    wait_for_gc().await;
    let data = client.read_to_bytes(hash).await?;
    assert_eq!(data.as_ref(), expected_data);
    drop(tag);
    // Check that the store drops the data when the temp tag gets dropped
    wait_for_gc().await;
    assert!(client.read_to_bytes(hash).await.is_err());
    Ok(())
}

#[tokio::test]
async fn test_batch_create_2() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let expected_data: &[u8] = b"test";
    let expected_hash = blake3::hash(expected_data).into();
    let tag = batch.add_bytes(expected_data, BlobFormat::Raw).await?;
    let hash = *tag.hash();
    assert_eq!(hash, expected_hash);
    // Check that the store has the data and that it is protected from gc
    wait_for_gc().await;
    let data = client.read_to_bytes(hash).await?;
    assert_eq!(data.as_ref(), expected_data);
    drop(batch);
    // Check that the store drops the data when the temp tag gets dropped
    wait_for_gc().await;
    assert!(client.read_to_bytes(hash).await.is_err());
    Ok(())
}

#[tokio::test]
async fn test_batch_create_3() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let expected_data: &[u8] = b"test";
    let expected_hash = blake3::hash(expected_data).into();
    let tag = batch.add_bytes(expected_data, BlobFormat::Raw).await?;
    let hash = *tag.hash();
    assert_eq!(hash, expected_hash);
    // Check that the store has the data and that it is protected from gc
    wait_for_gc().await;
    assert!(client.read_to_bytes(hash).await.is_ok());
    // Create an additional temp tag for the same data
    let tag2 = batch.temp_tag(tag.hash_and_format()).await?;
    drop(tag);
    // Check that the data is still present
    wait_for_gc().await;
    assert!(client.read_to_bytes(hash).await.is_ok());
    drop(tag2);
    // Check that the data is gone since both temp tags are dropped
    wait_for_gc().await;
    assert!(client.read_to_bytes(hash).await.is_err());
    Ok(())
}

#[tokio::test]
async fn test_batch_add_file_1() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let dir = tempfile::tempdir()?;
    let expected_data: &[u8] = b"test";
    let expected_hash = blake3::hash(expected_data).into();
    let temp_path = dir.path().join("test");
    std::fs::write(&temp_path, expected_data)?;
    let (tag, _) = batch
        .add_file(temp_path, ImportMode::Copy, BlobFormat::Raw)
        .await?;
    let hash = *tag.hash();
    assert_eq!(hash, expected_hash);
    // Check that the store has the data and that it is protected from gc
    wait_for_gc().await;
    let data = client.read_to_bytes(hash).await?;
    assert_eq!(data.as_ref(), expected_data);
    drop(tag);
    // Check that the store drops the data when the temp tag gets dropped
    wait_for_gc().await;
    assert!(client.read_to_bytes(hash).await.is_err());
    Ok(())
}

#[tokio::test]
async fn test_batch_add_file_2() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let dir = tempfile::tempdir()?;
    let expected_data: &[u8] = b"test";
    let expected_hash = blake3::hash(expected_data).into();
    let temp_path = dir.path().join("test");
    std::fs::write(&temp_path, expected_data)?;
    let (tag, _) = batch
        .add_file(temp_path, ImportMode::Copy, BlobFormat::Raw)
        .await?;
    let hash = *tag.hash();
    assert_eq!(hash, expected_hash);
    // Check that the store has the data and that it is protected from gc
    wait_for_gc().await;
    let data = client.read_to_bytes(hash).await?;
    assert_eq!(data.as_ref(), expected_data);
    drop(batch);
    // Check that the store drops the data when the temp tag gets dropped
    wait_for_gc().await;
    assert!(client.read_to_bytes(hash).await.is_err());
    Ok(())
}

#[tokio::test]
async fn test_batch_add_dir_1() -> anyhow::Result<()> {
    let node = create_node().await?;
    let client = &node.client().blobs;
    let batch = client.batch().await?;
    let dir = tempfile::tempdir()?;
    let data: [(&str, &[u8]); 2] = [("test1", b"test1"), ("test2", b"test2")];
    for (name, content) in &data {
        let temp_path = dir.path().join(name);
        std::fs::write(&temp_path, content)?;
    }
    let tag = batch
        .add_dir(dir.path().to_owned(), ImportMode::Copy, WrapOption::NoWrap)
        .await?;
    let check_present = || async {
        assert!(client.read_to_bytes(*tag.hash()).await.is_ok());
        for (_, content) in &data {
            let hash = blake3::hash(content).into();
            let data = client.read_to_bytes(hash).await?;
            assert_eq!(data.as_ref(), *content);
        }
        anyhow::Ok(())
    };
    // Check that the store has the data immediately
    check_present().await?;
    // Check that the store has the data and that it is protected from gc
    wait_for_gc().await;
    check_present().await?;
    drop(tag);
    // Check that the store drops the data when the temp tag gets dropped
    wait_for_gc().await;
    for (_, content) in &data {
        let hash = blake3::hash(content).into();
        assert!(client.read_to_bytes(hash).await.is_err());
    }
    Ok(())
}
