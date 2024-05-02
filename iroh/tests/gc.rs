use std::{
    io::{Cursor, Write},
    time::Duration,
};

use anyhow::Result;
use bao_tree::{blake3, io::sync::Outboard, ChunkRanges};
use bytes::Bytes;
use futures_lite::FutureExt;
use iroh::node::{self, Node};
use rand::RngCore;

use iroh_bytes::{
    hashseq::HashSeq,
    store::{EntryStatus, MapMut, Store},
    util::Tag,
    BlobFormat, HashAndFormat, IROH_BLOCK_SIZE,
};

pub fn create_test_data(size: usize) -> Bytes {
    let mut rand = rand::thread_rng();
    let mut res = vec![0u8; size];
    rand.fill_bytes(&mut res);
    res.into()
}

/// Take some data and encode it
pub fn simulate_remote(data: &[u8]) -> (blake3::Hash, Cursor<Bytes>) {
    let outboard = bao_tree::io::outboard::PostOrderMemOutboard::create(data, IROH_BLOCK_SIZE);
    let mut encoded = Vec::new();
    encoded
        .write_all(outboard.tree.size().to_le_bytes().as_ref())
        .unwrap();
    bao_tree::io::sync::encode_ranges_validated(data, &outboard, &ChunkRanges::all(), &mut encoded)
        .unwrap();
    let hash = outboard.root();
    (hash, Cursor::new(encoded.into()))
}

/// Wrap a bao store in a node that has gc enabled.
async fn wrap_in_node<S>(bao_store: S, gc_period: Duration) -> Node<S>
where
    S: iroh_bytes::store::Store,
{
    let doc_store = iroh_sync::store::Store::memory();
    node::Builder::with_db_and_store(bao_store, doc_store, iroh::node::StorageConfig::Mem)
        .gc_policy(iroh::node::GcPolicy::Interval(gc_period))
        .spawn()
        .await
        .unwrap()
}

async fn attach_db_events<D: iroh_bytes::store::Store>(
    node: &Node<D>,
) -> flume::Receiver<iroh_bytes::store::Event> {
    let (db_send, db_recv) = flume::unbounded();
    node.subscribe(move |ev| {
        let db_send = db_send.clone();
        async move {
            if let iroh::node::Event::Db(ev) = ev {
                db_send.into_send_async(ev).await.ok();
            }
        }
        .boxed()
    })
    .await
    .unwrap();
    db_recv
}

async fn gc_test_node() -> (
    Node<iroh_bytes::store::mem::Store>,
    iroh_bytes::store::mem::Store,
    flume::Receiver<iroh_bytes::store::Event>,
) {
    let bao_store = iroh_bytes::store::mem::Store::new();
    let node = wrap_in_node(bao_store.clone(), Duration::from_millis(500)).await;
    let db_recv = attach_db_events(&node).await;
    (node, bao_store, db_recv)
}

async fn step(evs: &flume::Receiver<iroh_bytes::store::Event>) {
    while evs.try_recv().is_ok() {}
    for _ in 0..3 {
        while let Ok(ev) = evs.recv_async().await {
            if let iroh_bytes::store::Event::GcCompleted = ev {
                break;
            }
        }
    }
}

/// Test the absolute basics of gc, temp tags and tags for blobs.
#[tokio::test]
async fn gc_basics() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    let (node, bao_store, evs) = gc_test_node().await;
    let data1 = create_test_data(1234);
    let tt1 = bao_store.import_bytes(data1, BlobFormat::Raw).await?;
    let data2 = create_test_data(5678);
    let tt2 = bao_store.import_bytes(data2, BlobFormat::Raw).await?;
    let h1 = *tt1.hash();
    let h2 = *tt2.hash();
    // temp tags are still there, so the entries should be there
    step(&evs).await;
    assert_eq!(bao_store.entry_status(&h1).await?, EntryStatus::Complete);
    assert_eq!(bao_store.entry_status(&h2).await?, EntryStatus::Complete);

    // drop the first tag, the entry should be gone after some time
    drop(tt1);
    step(&evs).await;
    assert_eq!(bao_store.entry_status(&h1).await?, EntryStatus::NotFound);
    assert_eq!(bao_store.entry_status(&h2).await?, EntryStatus::Complete);

    // create an explicit tag for h1 (as raw) and then delete the temp tag. Entry should still be there.
    let tag = Tag::from("test");
    bao_store
        .set_tag(tag.clone(), Some(HashAndFormat::raw(h2)))
        .await?;
    drop(tt2);
    tracing::info!("dropped tt2");
    step(&evs).await;
    assert_eq!(bao_store.entry_status(&h2).await?, EntryStatus::Complete);

    // delete the explicit tag, entry should be gone
    bao_store.set_tag(tag, None).await?;
    step(&evs).await;
    assert_eq!(bao_store.entry_status(&h2).await?, EntryStatus::NotFound);

    node.shutdown().await?;
    Ok(())
}

/// Test gc for sequences of hashes that protect their children from deletion.
#[tokio::test]
async fn gc_hashseq_impl() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    let (node, bao_store, evs) = gc_test_node().await;
    let data1 = create_test_data(1234);
    let tt1 = bao_store.import_bytes(data1, BlobFormat::Raw).await?;
    let data2 = create_test_data(5678);
    let tt2 = bao_store.import_bytes(data2, BlobFormat::Raw).await?;
    let seq = vec![*tt1.hash(), *tt2.hash()]
        .into_iter()
        .collect::<HashSeq>();
    let ttr = bao_store
        .import_bytes(seq.into_inner(), BlobFormat::HashSeq)
        .await?;
    let h1 = *tt1.hash();
    let h2 = *tt2.hash();
    let hr = *ttr.hash();
    drop(tt1);
    drop(tt2);

    // there is a temp tag for the link seq, so it and its entries should be there
    step(&evs).await;
    assert_eq!(bao_store.entry_status(&h1).await?, EntryStatus::Complete);
    assert_eq!(bao_store.entry_status(&h2).await?, EntryStatus::Complete);
    assert_eq!(bao_store.entry_status(&hr).await?, EntryStatus::Complete);

    // make a permanent tag for the link seq, then delete the temp tag. Entries should still be there.
    let tag = Tag::from("test");
    bao_store
        .set_tag(tag.clone(), Some(HashAndFormat::hash_seq(hr)))
        .await?;
    drop(ttr);
    step(&evs).await;
    assert_eq!(bao_store.entry_status(&h1).await?, EntryStatus::Complete);
    assert_eq!(bao_store.entry_status(&h2).await?, EntryStatus::Complete);
    assert_eq!(bao_store.entry_status(&hr).await?, EntryStatus::Complete);

    // change the permanent tag to be just for the linkseq itself as a blob. Only the linkseq should be there, not the entries.
    bao_store
        .set_tag(tag.clone(), Some(HashAndFormat::raw(hr)))
        .await?;
    step(&evs).await;
    assert_eq!(bao_store.entry_status(&h1).await?, EntryStatus::NotFound);
    assert_eq!(bao_store.entry_status(&h2).await?, EntryStatus::NotFound);
    assert_eq!(bao_store.entry_status(&hr).await?, EntryStatus::Complete);

    // delete the permanent tag, everything should be gone
    bao_store.set_tag(tag, None).await?;
    step(&evs).await;
    assert_eq!(bao_store.entry_status(&h1).await?, EntryStatus::NotFound);
    assert_eq!(bao_store.entry_status(&h2).await?, EntryStatus::NotFound);
    assert_eq!(bao_store.entry_status(&hr).await?, EntryStatus::NotFound);

    node.shutdown().await?;
    Ok(())
}

#[cfg(feature = "fs-store")]
mod file {
    use super::*;
    use std::{io, path::PathBuf};

    use bao_tree::{
        io::fsm::{BaoContentItem, ResponseDecoderNext},
        BaoTree,
    };

    use futures_lite::StreamExt;
    use iroh_io::AsyncSliceReaderExt;
    use testdir::testdir;

    use iroh_bytes::{
        store::{BaoBatchWriter, ConsistencyCheckProgress, Map, MapEntryMut, ReportLevel},
        util::progress::{FlumeProgressSender, ProgressSender as _},
        TempTag,
    };
    use tokio::io::AsyncReadExt;

    fn path(root: PathBuf, suffix: &'static str) -> impl Fn(&iroh_bytes::Hash) -> PathBuf {
        move |hash| root.join(format!("{}.{}", hash.to_hex(), suffix))
    }

    fn data_path(root: PathBuf) -> impl Fn(&iroh_bytes::Hash) -> PathBuf {
        // this assumes knowledge of the internal directory structure of the flat store
        path(root.join("data"), "data")
    }

    fn outboard_path(root: PathBuf) -> impl Fn(&iroh_bytes::Hash) -> PathBuf {
        // this assumes knowledge of the internal directory structure of the flat store
        path(root.join("data"), "obao4")
    }

    async fn check_consistency(store: &impl Store) -> anyhow::Result<ReportLevel> {
        let mut max_level = ReportLevel::Trace;
        let (tx, rx) = flume::bounded(1);
        let task = tokio::task::spawn(async move {
            while let Ok(ev) = rx.recv_async().await {
                if let ConsistencyCheckProgress::Update { level, .. } = &ev {
                    max_level = max_level.max(*level);
                }
            }
        });
        store
            .consistency_check(false, FlumeProgressSender::new(tx).boxed())
            .await?;
        task.await?;
        Ok(max_level)
    }

    #[tokio::test]
    async fn redb_doc_import_stress() -> Result<()> {
        let _ = tracing_subscriber::fmt::try_init();
        let dir = testdir!();
        let bao_store = iroh_bytes::store::fs::Store::load(dir.join("store")).await?;
        let node = wrap_in_node(bao_store.clone(), Duration::from_secs(10)).await;
        let client = node.client();
        let doc = client.docs.create().await?;
        let author = client.authors.create().await?;
        let temp_path = dir.join("temp");
        tokio::fs::create_dir_all(&temp_path).await?;
        let mut to_import = Vec::new();
        for i in 0..100 {
            let data = create_test_data(16 * 1024 * 3 + 1);
            let path = temp_path.join(format!("file{}", i));
            tokio::fs::write(&path, &data).await?;
            let key = Bytes::from(format!("{}", path.display()));
            to_import.push((key, path, data));
        }
        for (key, path, _) in to_import.iter() {
            let mut progress = doc.import_file(author, key.clone(), path, true).await?;
            while let Some(msg) = progress.next().await {
                tracing::info!("import progress {:?}", msg);
            }
        }
        for (i, (key, _, expected)) in to_import.iter().enumerate() {
            let Some(entry) = doc.get_exact(author, key.clone(), true).await? else {
                anyhow::bail!("doc entry not found {}", i);
            };
            let hash = entry.content_hash();
            let Some(content) = bao_store.get(&hash).await? else {
                anyhow::bail!("content not found {} {}", i, &hash.to_hex()[..8]);
            };
            let data = content.data_reader().read_to_end().await?;
            assert_eq!(data, expected);
        }
        Ok(())
    }

    /// Test gc for sequences of hashes that protect their children from deletion.
    #[tokio::test]
    async fn gc_file_basics() -> Result<()> {
        let _ = tracing_subscriber::fmt::try_init();
        let dir = testdir!();
        let path = data_path(dir.clone());
        let outboard_path = outboard_path(dir.clone());

        let bao_store = iroh_bytes::store::fs::Store::load(dir.clone()).await?;
        let node = wrap_in_node(bao_store.clone(), Duration::from_millis(100)).await;
        let evs = attach_db_events(&node).await;
        let data1 = create_test_data(10000000);
        let tt1 = bao_store
            .import_bytes(data1.clone(), BlobFormat::Raw)
            .await?;
        let data2 = create_test_data(1000000);
        let tt2 = bao_store
            .import_bytes(data2.clone(), BlobFormat::Raw)
            .await?;
        let seq = vec![*tt1.hash(), *tt2.hash()]
            .into_iter()
            .collect::<HashSeq>();
        let ttr = bao_store
            .import_bytes(seq.into_inner(), BlobFormat::HashSeq)
            .await?;

        let h1 = *tt1.hash();
        let h2 = *tt2.hash();
        let hr = *ttr.hash();

        // data is protected by the temp tag
        step(&evs).await;
        bao_store.sync().await?;
        assert!(check_consistency(&bao_store).await? <= ReportLevel::Info);
        // h1 is for a giant file, so we will have both data and outboard files
        assert!(path(&h1).exists());
        assert!(outboard_path(&h1).exists());
        // h2 is for a mid sized file, so we will have just the data file
        assert!(path(&h2).exists());
        assert!(!outboard_path(&h2).exists());
        // hr so small that data will be inlined and outboard will not exist at all
        assert!(!path(&hr).exists());
        assert!(!outboard_path(&hr).exists());

        drop(tt1);
        drop(tt2);
        let tag = Tag::from("test");
        bao_store
            .set_tag(tag.clone(), Some(HashAndFormat::hash_seq(*ttr.hash())))
            .await?;
        drop(ttr);

        // data is now protected by a normal tag, nothing should be gone
        step(&evs).await;
        bao_store.sync().await?;
        assert!(check_consistency(&bao_store).await? <= ReportLevel::Info);
        // h1 is for a giant file, so we will have both data and outboard files
        assert!(path(&h1).exists());
        assert!(outboard_path(&h1).exists());
        // h2 is for a mid sized file, so we will have just the data file
        assert!(path(&h2).exists());
        assert!(!outboard_path(&h2).exists());
        // hr so small that data will be inlined and outboard will not exist at all
        assert!(!path(&hr).exists());
        assert!(!outboard_path(&hr).exists());

        tracing::info!("changing tag from hashseq to raw, this should orphan the children");
        bao_store
            .set_tag(tag.clone(), Some(HashAndFormat::raw(hr)))
            .await?;

        // now only hr itself should be protected, but not its children
        step(&evs).await;
        bao_store.sync().await?;
        assert!(check_consistency(&bao_store).await? <= ReportLevel::Info);
        // h1 should be gone
        assert!(!path(&h1).exists());
        assert!(!outboard_path(&h1).exists());
        // h2 should still not be there
        assert!(!path(&h2).exists());
        assert!(!outboard_path(&h2).exists());
        // hr should still not be there
        assert!(!path(&hr).exists());
        assert!(!outboard_path(&hr).exists());

        bao_store.set_tag(tag, None).await?;
        step(&evs).await;
        bao_store.sync().await?;
        assert!(check_consistency(&bao_store).await? <= ReportLevel::Info);
        // h1 should be gone
        assert!(!path(&h1).exists());
        assert!(!outboard_path(&h1).exists());
        // h2 should still not be there
        assert!(!path(&h2).exists());
        assert!(!outboard_path(&h2).exists());
        // hr should still not be there
        assert!(!path(&hr).exists());
        assert!(!outboard_path(&hr).exists());

        node.shutdown().await?;

        Ok(())
    }

    /// Add a file to the store in the same way a download works.
    ///
    /// we know the hash in advance, create a partial entry, write the data to it and
    /// the outboard file, then commit it to a complete entry.
    ///
    /// During this time, the partial entry is protected by a temp tag.
    async fn simulate_download_partial<S: iroh_bytes::store::Store>(
        bao_store: &S,
        data: Bytes,
    ) -> io::Result<(S::EntryMut, TempTag)> {
        // simulate the remote side.
        let (hash, mut response) = simulate_remote(data.as_ref());
        // simulate the local side.
        // we got a hash and a response from the remote side.
        let tt = bao_store.temp_tag(HashAndFormat::raw(hash.into()));
        // get the size
        let size = response.read_u64_le().await?;
        // start reading the response
        let mut reading = bao_tree::io::fsm::ResponseDecoder::new(
            hash,
            ChunkRanges::all(),
            BaoTree::new(size, IROH_BLOCK_SIZE),
            response,
        );
        // create the partial entry
        let entry = bao_store.get_or_create(hash.into(), size).await?;
        // create the
        let mut bw = entry.batch_writer().await?;
        let mut buf = Vec::new();
        while let ResponseDecoderNext::More((next, res)) = reading.next().await {
            let item = res?;
            match &item {
                BaoContentItem::Parent(_) => {
                    buf.push(item);
                }
                BaoContentItem::Leaf(_) => {
                    buf.push(item);
                    let batch = std::mem::take(&mut buf);
                    bw.write_batch(size, batch).await?;
                }
            }
            reading = next;
        }
        bw.sync().await?;
        drop(bw);
        Ok((entry, tt))
    }

    async fn simulate_download_complete<S: iroh_bytes::store::Store>(
        bao_store: &S,
        data: Bytes,
    ) -> io::Result<TempTag> {
        let (entry, tt) = simulate_download_partial(bao_store, data).await?;
        // commit the entry
        bao_store.insert_complete(entry).await?;
        Ok(tt)
    }

    /// Test that partial files are deleted.
    #[tokio::test]
    // #[ignore = "flaky"]
    async fn gc_file_partial() -> Result<()> {
        let _ = tracing_subscriber::fmt::try_init();
        let dir = testdir!();
        let path = data_path(dir.clone());
        let outboard_path = outboard_path(dir.clone());

        let bao_store = iroh_bytes::store::fs::Store::load(dir.clone()).await?;
        let node = wrap_in_node(bao_store.clone(), Duration::from_millis(10)).await;
        let evs = attach_db_events(&node).await;

        let data1: Bytes = create_test_data(10000000);
        let (_entry, tt1) = simulate_download_partial(&bao_store, data1.clone()).await?;
        drop(_entry);
        let h1 = *tt1.hash();
        // partial data and outboard files should be there
        step(&evs).await;
        bao_store.sync().await?;
        assert!(check_consistency(&bao_store).await? <= ReportLevel::Info);
        assert!(path(&h1).exists());
        assert!(outboard_path(&h1).exists());

        drop(tt1);
        // partial data and outboard files should be gone
        step(&evs).await;
        bao_store.sync().await?;
        assert!(check_consistency(&bao_store).await? <= ReportLevel::Info);
        assert!(!path(&h1).exists());
        assert!(!outboard_path(&h1).exists());

        node.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn gc_file_stress() -> Result<()> {
        let _ = tracing_subscriber::fmt::try_init();
        let dir = testdir!();

        let bao_store = iroh_bytes::store::fs::Store::load(dir.clone()).await?;
        let node = wrap_in_node(bao_store.clone(), Duration::from_secs(1)).await;
        let evs = attach_db_events(&node).await;

        let mut deleted = Vec::new();
        let mut live = Vec::new();
        // download
        for i in 0..100 {
            let data: Bytes = create_test_data(16 * 1024 * 3 + 1);
            let tt = simulate_download_complete(&bao_store, data).await.unwrap();
            if i % 100 == 0 {
                let tag = Tag::from(format!("test{}", i));
                bao_store
                    .set_tag(tag.clone(), Some(HashAndFormat::raw(*tt.hash())))
                    .await?;
                live.push(*tt.hash());
            } else {
                deleted.push(*tt.hash());
            }
        }
        step(&evs).await;

        for h in deleted.iter() {
            assert_eq!(bao_store.entry_status(h).await?, EntryStatus::NotFound);
            assert!(!dir.join(format!("data/{}.data", h.to_hex())).exists());
        }

        for h in live.iter() {
            assert_eq!(bao_store.entry_status(h).await?, EntryStatus::Complete);
            assert!(dir.join(format!("data/{}.data", h.to_hex())).exists());
        }

        node.shutdown().await?;
        Ok(())
    }
}
