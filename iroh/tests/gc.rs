use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use futures::FutureExt;
use iroh::node::{self, Node};
use rand::RngCore;

use iroh_bytes::{
    hashseq::HashSeq,
    store::{EntryStatus, MapMut, Store},
    util::Tag,
    BlobFormat, HashAndFormat,
};
use tokio_util::task::LocalPoolHandle;

fn create_test_data(n: usize) -> Bytes {
    let mut rng = rand::thread_rng();
    let mut data = vec![0; n];
    rng.fill_bytes(&mut data);
    data.into()
}

/// Wrap a bao store in a node that has gc enabled.
async fn wrap_in_node<S>(bao_store: S, gc_period: Duration) -> Node<S>
where
    S: iroh_bytes::store::Store,
{
    let doc_store = iroh_sync::store::memory::Store::default();
    node::Builder::with_db_and_store(bao_store, doc_store, iroh::node::StorageConfig::Mem)
        .gc_policy(iroh::node::GcPolicy::Interval(gc_period))
        .local_pool(&LocalPoolHandle::new(1))
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
    step(&evs).await;
    assert_eq!(bao_store.entry_status(&h2).await?, EntryStatus::Complete);

    // delete the explicit tag, entry should be gone
    bao_store.set_tag(tag, None).await?;
    step(&evs).await;
    assert_eq!(bao_store.entry_status(&h2).await?, EntryStatus::NotFound);

    node.shutdown();
    node.await?;
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

    node.shutdown();
    node.await?;
    Ok(())
}

#[cfg(feature = "flat-db")]
mod flat {
    use super::*;
    use std::{
        io::{self, Cursor},
        path::{Path, PathBuf},
        time::Duration,
    };

    use anyhow::Result;
    use bao_tree::{
        blake3,
        io::fsm::{BaoContentItem, Outboard, ResponseDecoderReadingNext},
        ChunkRanges,
    };
    use bytes::Bytes;
    use testdir::testdir;

    use iroh_bytes::{
        hashseq::HashSeq,
        store::{BaoBatchWriter, MapEntryMut, MapMut, Store},
        BlobFormat, HashAndFormat, Tag, TempTag, IROH_BLOCK_SIZE,
    };

    fn path(root: PathBuf, suffix: &'static str) -> impl Fn(&iroh_bytes::Hash) -> PathBuf {
        move |hash| root.join(format!("{}.{}", hash.to_hex(), suffix))
    }

    fn data_path(root: PathBuf) -> impl Fn(&iroh_bytes::Hash) -> PathBuf {
        // this assumes knowledge of the internal directory structure of the flat store
        path(root.join("complete"), "data")
    }

    fn outboard_path(root: PathBuf) -> impl Fn(&iroh_bytes::Hash) -> PathBuf {
        // this assumes knowledge of the internal directory structure of the flat store
        path(root.join("complete"), "obao4")
    }

    async fn sync_directory(dir: impl AsRef<Path>) -> io::Result<()> {
        // sync the directory to make sure the metadata is written
        // does not work on windows
        if let Ok(dir) = std::fs::File::open(dir) {
            dir.sync_all().ok();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(())
    }

    /// count the number of partial files for a hash. partial files are <hash>-<uuid>.<suffix>
    fn count_partial(
        root: PathBuf,
        suffix: &'static str,
    ) -> impl Fn(&iroh_bytes::Hash) -> std::io::Result<usize> {
        move |hash| {
            let valid_names = std::fs::read_dir(&root)?
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    if e.metadata().ok()?.is_file() {
                        e.file_name().into_string().ok()
                    } else {
                        None
                    }
                });
            let prefix = format!("{}-", hash.to_hex());
            Ok(valid_names
                .filter(|x| x.starts_with(&prefix) && x.ends_with(suffix))
                .count())
        }
    }

    /// count the number of partial data files for a hash
    fn count_partial_data(root: PathBuf) -> impl Fn(&iroh_bytes::Hash) -> std::io::Result<usize> {
        count_partial(root.join("partial"), "data")
    }

    /// count the number of partial outboard files for a hash
    fn count_partial_outboard(
        root: PathBuf,
    ) -> impl Fn(&iroh_bytes::Hash) -> std::io::Result<usize> {
        count_partial(root.join("partial"), "obao4")
    }

    /// Test gc for sequences of hashes that protect their children from deletion.
    #[tokio::test]
    async fn gc_flat_basics() -> Result<()> {
        let _ = tracing_subscriber::fmt::try_init();
        let dir = testdir!();
        let path = data_path(dir.clone());
        let outboard_path = outboard_path(dir.clone());

        let bao_store = iroh_bytes::store::flat::Store::load(dir.clone()).await?;
        let node = wrap_in_node(bao_store.clone(), Duration::from_millis(0)).await;
        let evs = attach_db_events(&node).await;
        let data1 = create_test_data(123456);
        let tt1 = bao_store
            .import_bytes(data1.clone(), BlobFormat::Raw)
            .await?;
        let data2 = create_test_data(567890);
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

        step(&evs).await;
        assert!(path(&h1).exists());
        assert!(outboard_path(&h1).exists());
        assert!(path(&h2).exists());
        assert!(outboard_path(&h2).exists());
        assert!(path(&hr).exists());
        // hr is too small to have an outboard file

        drop(tt1);
        drop(tt2);
        let tag = Tag::from("test");
        bao_store
            .set_tag(tag.clone(), Some(HashAndFormat::hash_seq(*ttr.hash())))
            .await?;
        drop(ttr);

        step(&evs).await;
        assert!(path(&h1).exists());
        assert!(outboard_path(&h1).exists());
        assert!(path(&h2).exists());
        assert!(outboard_path(&h2).exists());
        assert!(path(&hr).exists());
        assert!(!outboard_path(&hr).exists());

        tracing::info!("changing tag from hashseq to raw, this should orphan the children");
        bao_store
            .set_tag(tag.clone(), Some(HashAndFormat::raw(hr)))
            .await?;
        step(&evs).await;
        sync_directory(&dir).await?;
        assert!(
            !path(&h1).exists(),
            "h1 data should be gone {}",
            path(&h1).display()
        );
        assert!(
            !outboard_path(&h1).exists(),
            "h1 outboard should be gone {}",
            outboard_path(&h1).display()
        );
        assert!(!path(&h2).exists());
        assert!(!outboard_path(&h2).exists());
        assert!(path(&hr).exists());

        bao_store.set_tag(tag, None).await?;
        step(&evs).await;
        sync_directory(&dir).await?;
        assert!(!path(&hr).exists());

        node.shutdown();
        node.await?;
        Ok(())
    }

    /// Take some data and encode it
    #[allow(dead_code)]
    fn simulate_remote(data: &[u8]) -> (blake3::Hash, Cursor<Bytes>) {
        let outboard = bao_tree::io::outboard::PostOrderMemOutboard::create(data, IROH_BLOCK_SIZE);
        let mut encoded = Vec::new();
        bao_tree::io::sync::encode_ranges_validated(
            data,
            &outboard,
            &ChunkRanges::all(),
            &mut encoded,
        )
        .unwrap();
        let hash = outboard.root();
        (hash, Cursor::new(encoded.into()))
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
        let (hash, response) = simulate_remote(data.as_ref());
        // simulate the local side.
        // we got a hash and a response from the remote side.
        let tt = bao_store.temp_tag(HashAndFormat::raw(hash.into()));
        // start reading the response
        let at_start = bao_tree::io::fsm::ResponseDecoderStart::new(
            hash,
            ChunkRanges::all(),
            IROH_BLOCK_SIZE,
            response,
        );
        // get the size
        let (mut reading, size) = at_start.next().await?;
        // create the partial entry
        let entry = bao_store.get_or_create(hash.into(), size).await?;
        // create the
        let mut bw = entry.batch_writer().await?;
        let mut buf = Vec::new();
        while let ResponseDecoderReadingNext::More((next, res)) = reading.next().await {
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
    async fn gc_flat_partial() -> Result<()> {
        let _ = tracing_subscriber::fmt::try_init();
        let dir = testdir!();
        let count_partial_data = count_partial_data(dir.clone());
        let count_partial_outboard = count_partial_outboard(dir.clone());

        let bao_store = iroh_bytes::store::flat::Store::load(dir.clone()).await?;
        let node = wrap_in_node(bao_store.clone(), Duration::from_millis(0)).await;
        let evs = attach_db_events(&node).await;

        let data1: Bytes = create_test_data(123456);
        let (_entry, tt1) = simulate_download_partial(&bao_store, data1.clone()).await?;
        drop(_entry);
        let h1 = *tt1.hash();
        // partial data and outboard files should be there
        step(&evs).await;
        assert!(count_partial_data(&h1)? == 1);
        assert!(count_partial_outboard(&h1)? == 1);

        drop(tt1);
        // partial data and outboard files should be gone
        step(&evs).await;
        assert!(count_partial_data(&h1)? == 0);
        assert!(count_partial_outboard(&h1)? == 0);

        node.shutdown();
        node.await?;
        Ok(())
    }

    ///
    #[tokio::test]
    async fn gc_flat_stress() -> Result<()> {
        let _ = tracing_subscriber::fmt::try_init();
        let dir = testdir!();
        let count_partial_data = count_partial_data(dir.clone());
        let count_partial_outboard = count_partial_outboard(dir.clone());

        let bao_store = iroh_bytes::store::flat::Store::load(dir.clone()).await?;
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
            assert!(count_partial_data(h)? == 0);
            assert!(count_partial_outboard(h)? == 0);
            assert_eq!(bao_store.entry_status(h).await?, EntryStatus::NotFound);
        }

        for h in live.iter() {
            assert!(count_partial_data(h)? == 0);
            assert!(count_partial_outboard(h)? == 0);
            assert_eq!(bao_store.entry_status(h).await?, EntryStatus::Complete);
        }

        node.shutdown();
        node.await?;
        Ok(())
    }
}
