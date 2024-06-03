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
    tokio::time::sleep(Duration::from_millis(50)).await;
    let data = client.read_to_bytes(hash).await?;
    assert_eq!(data.as_ref(), expected_data);
    drop(tag);
    // Check that the store drops the data when the temp tag gets dropped
    tokio::time::sleep(Duration::from_millis(50)).await;
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
    tokio::time::sleep(Duration::from_millis(50)).await;
    let data = client.read_to_bytes(hash).await?;
    assert_eq!(data.as_ref(), expected_data);
    drop(batch);
    // Check that the store drops the data when the temp tag gets dropped
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(client.read_to_bytes(hash).await.is_err());
    Ok(())
}
