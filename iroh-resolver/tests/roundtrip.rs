use super::*;
use crate::resolver::Resolver;
use anyhow::Result;
use futures::TryStreamExt;
use iroh_content::{
    content::{Out, OutMetrics, ResponseClip},
    content_loader::ContentLoader,
};
use proptest::prelude::*;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use std::{collections::BTreeMap, io::prelude::*};
use tokio::io::AsyncReadExt;

/// Read a stream of (cid, block) pairs into an in memory store and return the store and the root cid.
#[doc(hidden)]
pub async fn stream_to_resolver(
    stream: impl Stream<Item = Result<Block>>,
) -> Result<(
    Cid,
    crate::resolver::Resolver<Arc<fnv::FnvHashMap<Cid, Bytes>>>,
)> {
    tokio::pin!(stream);
    let blocks: Vec<_> = stream.try_collect().await?;
    for block in &blocks {
        block.validate()?;
    }
    let root_block = blocks.last().context("no root")?.clone();
    let store: fnv::FnvHashMap<Cid, Bytes> = blocks
        .into_iter()
        .map(|block| {
            let (cid, bytes, _) = block.into_parts();
            (cid, bytes)
        })
        .collect();
    let resolver = crate::resolver::Resolver::new(Arc::new(store));
    Ok((*root_block.cid(), resolver))
}

#[tokio::test]
async fn test_builder_basics() -> Result<()> {
    // Create a directory
    let mut dir = DirectoryBuilder::new();
    dir.name("foo");

    // Add a file
    let bar = FileBuilder::new()
        .name("bar.txt")
        .content_bytes(b"bar".to_vec())
        .build()
        .await?;
    let bar_encoded: Vec<_> = {
        let bar = FileBuilder::new()
            .name("bar.txt")
            .content_bytes(b"bar".to_vec())
            .build()
            .await?;
        bar.encode().await?.try_collect().await?
    };
    assert_eq!(bar_encoded.len(), 1);

    // Add a symlink
    let mut baz = SymlinkBuilder::new("baz.txt");
    baz.target("bat.txt");
    let baz = baz.build().await?;
    let baz_encoded: Block = {
        let mut baz = SymlinkBuilder::new("baz.txt");
        baz.target("bat.txt");
        let baz = baz.build().await?;
        baz.encode()?
    };

    dir.add_file(bar).add_symlink(baz);

    let dir = dir.build()?;

    let dir_block = dir.encode_root().await?;
    let decoded_dir = UnixfsNode::decode(dir_block.cid(), dir_block.data().clone())?;

    let links = decoded_dir.links().collect::<Result<Vec<_>>>().unwrap();
    assert_eq!(links[0].name.unwrap(), "bar.txt");
    assert_eq!(links[0].cid, *bar_encoded[0].cid());
    assert_eq!(links[1].name.unwrap(), "baz.txt");
    assert_eq!(links[1].cid, *baz_encoded.cid());

    // TODO: check content
    Ok(())
}

#[tokio::test]
async fn test_recursive_dir_builder() -> Result<()> {
    let dir = DirectoryBuilder::new();
    let dir = dir.build()?;

    let mut recursive_dir_builder = DirectoryBuilder::new();
    recursive_dir_builder
        .add_dir(dir)
        .expect("recursive directories allowed");
    Ok(())
}

#[tokio::test]
async fn test_builder_stream_small() -> Result<()> {
    // Create a directory
    let mut dir = DirectoryBuilder::new();
    dir.name("foo");

    // Add a file
    let bar_reader = std::io::Cursor::new(b"bar");
    let bar = FileBuilder::new()
        .name("bar.txt")
        .content_reader(bar_reader)
        .build()
        .await?;
    let bar_encoded: Vec<_> = {
        let bar_reader = std::io::Cursor::new(b"bar");
        let bar = FileBuilder::new()
            .name("bar.txt")
            .content_reader(bar_reader)
            .build()
            .await?;
        bar.encode().await?.try_collect().await?
    };
    assert_eq!(bar_encoded.len(), 1);

    // Add a symlink
    let mut baz = SymlinkBuilder::new("baz.txt");
    baz.target("bat.txt");
    let baz = baz.build().await?;
    let baz_encoded: Block = {
        let mut baz = SymlinkBuilder::new("baz.txt");
        baz.target("bat.txt");
        let baz = baz.build().await?;
        baz.encode()?
    };

    dir.add_file(bar).add_symlink(baz);

    let dir = dir.build()?;

    let dir_block = dir.encode_root().await?;
    let decoded_dir = UnixfsNode::decode(dir_block.cid(), dir_block.data().clone())?;

    let links = decoded_dir.links().collect::<Result<Vec<_>>>().unwrap();
    assert_eq!(links[0].name.unwrap(), "bar.txt");
    assert_eq!(links[0].cid, *bar_encoded[0].cid());
    assert_eq!(links[1].name.unwrap(), "baz.txt");
    assert_eq!(links[1].cid, *baz_encoded.cid());

    // TODO: check content
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TestDirEntry {
    File(Bytes),
    Directory(TestDir),
}
type TestDir = BTreeMap<String, TestDirEntry>;

/// builds an unixfs directory out of a TestDir
#[async_recursion(?Send)]
async fn build_directory(name: &str, dir: &TestDir) -> Result<Directory> {
    let mut builder = DirectoryBuilder::new();
    builder.name(name);
    for (name, entry) in dir {
        match entry {
            TestDirEntry::File(content) => {
                let file = FileBuilder::new()
                    .name(name)
                    .content_bytes(content.to_vec())
                    .build()
                    .await?;
                builder.add_file(file);
            }
            TestDirEntry::Directory(dir) => {
                let dir = build_directory(name, dir).await?;
                builder.add_dir(dir)?;
            }
        }
    }
    builder.build()
}

/// builds a TestDir out of a stream of blocks and a resolver
async fn build_testdir(
    stream: impl Stream<Item = Result<(iroh_content::content::Path, Out)>>,
    resolver: Resolver<impl ContentLoader + Unpin>,
) -> Result<TestDir> {
    tokio::pin!(stream);

    /// recursively create directories for a path
    fn mkdir(dir: &mut TestDir, path: &[String]) -> Result<()> {
        if let Some((first, rest)) = path.split_first() {
            if let TestDirEntry::Directory(child) = dir
                .entry(first.clone())
                .or_insert_with(|| TestDirEntry::Directory(Default::default()))
            {
                mkdir(child, rest)?;
            } else {
                anyhow::bail!("not a directory");
            }
        }
        Ok(())
    }

    /// create a file in a directory hierarchy
    fn mkfile(dir: &mut TestDir, path: &[String], data: Bytes) -> Result<()> {
        if let Some((first, rest)) = path.split_first() {
            if rest.is_empty() {
                dir.insert(first.clone(), TestDirEntry::File(data));
            } else if let TestDirEntry::Directory(child) = dir
                .entry(first.clone())
                .or_insert_with(|| TestDirEntry::Directory(Default::default()))
            {
                mkfile(child, rest, data)?;
            } else {
                anyhow::bail!("not a directory");
            }
        }
        Ok(())
    }

    let reference = stream
        .try_fold(TestDir::default(), move |mut agg, (path, item)| {
            let resolver = resolver.clone();
            async move {
                if item.is_dir() {
                    mkdir(&mut agg, path.tail())?;
                } else {
                    let reader = item.pretty(
                        resolver.clone(),
                        OutMetrics::default(),
                        ResponseClip::NoClip,
                    )?;
                    let data = read_to_vec(reader).await?;
                    mkfile(&mut agg, path.tail(), data.into())?;
                }
                Ok(agg)
            }
        })
        .await?;
    Ok(reference)
}

/// a roundtrip test that converts a dir to an unixfs DAG and back
async fn dir_roundtrip_test(dir: TestDir) -> Result<bool> {
    let directory = build_directory("", &dir).await?;
    let stream = directory.encode();
    let (root, resolver) = stream_to_resolver(stream).await?;
    let stream = resolver.resolve_recursive_with_paths(iroh_content::content::Path::from_cid(root));
    let reference = build_testdir(stream, resolver).await?;
    Ok(dir == reference)
}

/// sync version of dir_roundtrip_test for use in proptest
fn dir_roundtrip_test_sync(dir: TestDir) -> bool {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(dir_roundtrip_test(dir))
        .unwrap()
}

/// a roundtrip test that converts a file to an unixfs DAG and back
async fn file_roundtrip_test(data: Bytes, chunk_size: usize, degree: usize) -> Result<bool> {
    let file = FileBuilder::new()
        .name("file.bin")
        .fixed_chunker(chunk_size)
        .degree(degree)
        .content_bytes(data.clone())
        .build()
        .await?;
    let stream = file.encode().await?;
    let (root, resolver) = stream_to_resolver(stream).await?;
    let out = resolver
        .resolve(iroh_content::content::Path::from_cid(root))
        .await?;
    let t = read_to_vec(out.pretty(resolver, OutMetrics::default(), ResponseClip::NoClip)?).await?;
    println!("{}", data.len());
    Ok(t == data)
}

/// a roundtrip test that converts a symlink to a unixfs DAG and back
#[tokio::test]
async fn symlink_roundtrip_test() -> Result<()> {
    let mut builder = SymlinkBuilder::new("foo");
    let target = "../../bar.txt";
    builder.target(target);
    let sym = builder.build().await?;
    let block = sym.encode()?;
    let stream = async_stream::try_stream! {
        yield block;
    };
    let (root, resolver) = stream_to_resolver(stream).await?;
    let out = resolver
        .resolve(iroh_content::content::Path::from_cid(root))
        .await?;
    let mut reader = out.pretty(resolver, OutMetrics::default(), ResponseClip::NoClip)?;
    let mut t = String::new();
    reader.read_to_string(&mut t).await?;
    println!("{}", t);
    assert_eq!(target, t);
    Ok(())
}

#[cfg(not(windows))]
#[tokio::test]
async fn symlink_from_disk_test() -> Result<()> {
    let temp_dir = ::tempfile::tempdir()?;
    let expect_name = "path_to_symlink";
    let expect_target = temp_dir.path().join("path_to_target");
    let expect_path = temp_dir.path().join(expect_name);

    tokio::fs::symlink(expect_target.clone(), expect_path.clone()).await?;

    let got_symlink = SymlinkBuilder::new(expect_path).build().await?;
    assert_eq!(expect_name, got_symlink.name());
    assert_eq!(expect_target, got_symlink.target);
    Ok(())
}

/// sync version of file_roundtrip_test for use in proptest
fn file_roundtrip_test_sync(data: Bytes, chunk_size: usize, degree: usize) -> bool {
    let f = file_roundtrip_test(data, chunk_size, degree);
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
        .unwrap()
}

fn arb_test_dir() -> impl Strategy<Value = TestDir> {
    // create an arbitrary nested directory structure
    fn arb_dir_entry() -> impl Strategy<Value = TestDirEntry> {
        let leaf = any::<Vec<u8>>().prop_map(|x| TestDirEntry::File(Bytes::from(x)));
        leaf.prop_recursive(3, 64, 10, |inner| {
            prop::collection::btree_map(".*", inner, 0..10).prop_map(TestDirEntry::Directory)
        })
    }
    prop::collection::btree_map(".*", arb_dir_entry(), 0..10)
}

fn arb_degree() -> impl Strategy<Value = usize> {
    // use either the smallest possible degree for complex tree structures, or the default value for realism
    prop_oneof![Just(2), Just(DEFAULT_DEGREE)]
}

fn arb_chunk_size() -> impl Strategy<Value = usize> {
    // use either the smallest possible chunk size for complex tree structures, or the default value for realism
    prop_oneof![Just(1), Just(DEFAULT_CHUNKS_SIZE)]
}

proptest! {
    #[test]
    fn test_file_roundtrip(data in proptest::collection::vec(any::<u8>(), 0usize..1024), chunk_size in arb_chunk_size(), degree in arb_degree()) {
        assert!(file_roundtrip_test_sync(data.into(), chunk_size, degree));
    }

    #[test]
    fn test_dir_roundtrip(data in arb_test_dir()) {
        assert!(dir_roundtrip_test_sync(data));
    }
}

#[tokio::test]
async fn test_builder_roundtrip_complex_tree_1() -> Result<()> {
    // fill with random data so we get distinct cids for all blocks
    let mut rng = ChaCha8Rng::from_seed([0; 32]);
    let mut data = vec![0u8; 1024 * 128];
    rng.fill(data.as_mut_slice());
    assert!(file_roundtrip_test(data.into(), 1024, 4).await?);
    Ok(())
}

#[tokio::test]
async fn test_builder_roundtrip_128m() -> Result<()> {
    // fill with random data so we get distinct cids for all blocks
    let mut rng = ChaCha8Rng::from_seed([0; 32]);
    let mut data = vec![0u8; 128 * 1024 * 1024];
    rng.fill(data.as_mut_slice());
    assert!(file_roundtrip_test(data.into(), DEFAULT_CHUNKS_SIZE, DEFAULT_DEGREE).await?);
    Ok(())
}

#[tokio::test]
async fn test_builder_stream_large() -> Result<()> {
    // Create a directory
    let mut dir = DirectoryBuilder::new();
    dir.name("foo");

    // Add a file
    let bar_reader = std::io::Cursor::new(vec![1u8; 1024 * 1024]);
    let bar = FileBuilder::new()
        .name("bar.txt")
        .content_reader(bar_reader)
        .build()
        .await?;
    let bar_encoded: Vec<_> = {
        let bar_reader = std::io::Cursor::new(vec![1u8; 1024 * 1024]);
        let bar = FileBuilder::new()
            .name("bar.txt")
            .content_reader(bar_reader)
            .build()
            .await?;
        bar.encode().await?.try_collect().await?
    };
    assert_eq!(bar_encoded.len(), 5);

    // Add a file
    let mut baz_content = Vec::with_capacity(1024 * 1024 * 2);
    for i in 0..2 {
        for _ in 0..(1024 * 1024) {
            baz_content.push(i);
        }
    }

    let baz_reader = std::io::Cursor::new(baz_content.clone());
    let baz = FileBuilder::new()
        .name("baz.txt")
        .content_reader(baz_reader)
        .build()
        .await?;
    let baz_encoded: Vec<_> = {
        let baz_reader = std::io::Cursor::new(baz_content);
        let baz = FileBuilder::new()
            .name("baz.txt")
            .content_reader(baz_reader)
            .build()
            .await?;
        baz.encode().await?.try_collect().await?
    };
    assert_eq!(baz_encoded.len(), 9);

    dir.add_file(bar).add_file(baz);

    let dir = dir.build()?;

    let dir_block = dir.encode_root().await?;
    let decoded_dir = UnixfsNode::decode(dir_block.cid(), dir_block.data().clone())?;

    let links = decoded_dir.links().collect::<Result<Vec<_>>>().unwrap();
    assert_eq!(links[0].name.unwrap(), "bar.txt");
    assert_eq!(links[0].cid, *bar_encoded[4].cid());
    assert_eq!(links[1].name.unwrap(), "baz.txt");
    assert_eq!(links[1].cid, *baz_encoded[8].cid());

    for (i, encoded) in baz_encoded.iter().enumerate() {
        let node = UnixfsNode::decode(encoded.cid(), encoded.data().clone())?;
        if i == 8 {
            assert_eq!(node.typ(), Some(DataType::File));
            assert_eq!(node.links().count(), 8);
        } else {
            assert_eq!(node.typ(), None); // raw leaves
            assert!(node.size().unwrap() > 0);
            assert_eq!(node.links().count(), 0);
        }
    }

    // TODO: check content
    // TODO: add nested directory

    Ok(())
}

#[tokio::test]
async fn test_hamt_detection() -> Result<()> {
    // allow hamt override
    let mut builder = DirectoryBuilder::new();
    builder.hamt();
    assert_eq!(DirectoryType::Hamt, builder.typ);

    let mut builder = DirectoryBuilder::new();

    for _i in 0..DIRECTORY_LINK_LIMIT {
        let file = FileBuilder::new()
            .name("foo.txt")
            .content_bytes(Bytes::from("hello world"))
            .build()
            .await?;
        builder.add_file(file);
    }

    // under DIRECTORY_LINK_LIMIT should still be a basic directory
    assert_eq!(DirectoryType::Basic, builder.typ);

    let file = FileBuilder::new()
        .name("foo.txt")
        .content_bytes(Bytes::from("hello world"))
        .build()
        .await?;
    builder.add_file(file);

    // at directory link limit should be processed as a hamt
    assert_eq!(DirectoryType::Hamt, builder.typ);
    if (builder.build()).is_ok() {
        panic!("expected builder to error when attempting to build a hamt directory")
    }
    Ok(())
}

#[tokio::test]
async fn test_make_dir_from_path() -> Result<()> {
    let temp_dir = std::env::temp_dir();
    let dir = temp_dir.join("test_dir");
    std::fs::DirBuilder::new()
        .recursive(true)
        .create(dir.clone())
        .unwrap();

    // create directory and nested file
    let nested_dir_path = dir.join("nested_dir");
    let nested_file_path = nested_dir_path.join("bar.txt");

    std::fs::DirBuilder::new()
        .recursive(true)
        .create(nested_dir_path.clone())
        .unwrap();

    let mut file = std::fs::File::create(nested_file_path.clone()).unwrap();
    file.write_all(b"hello world again").unwrap();

    // create another file in the "test_dir" directory
    let file_path = dir.join("foo.txt");
    let mut file = std::fs::File::create(file_path.clone()).unwrap();
    file.write_all(b"hello world").unwrap();

    // create directory manually
    let nested_file = FileBuilder::new().path(nested_file_path).build().await?;
    let nested_dir = Directory {
        name: String::from(
            nested_dir_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap(),
        ),
        entries: vec![Entry::File(nested_file)],
    };

    let file = FileBuilder::new().path(file_path).build().await?;

    let expected = Directory {
        name: String::from(dir.clone().file_name().and_then(|s| s.to_str()).unwrap()),
        entries: vec![Entry::File(file), Entry::Directory(nested_dir)],
    };

    let mut got = make_dir_from_path(dir, Chunker::Fixed(chunker::Fixed::default())).await?;

    // Before comparison sort entries to make test deterministic.
    // The readdir_r function is used in the underlying platform which
    // gives no guarantee to return in a specific order.
    // https://stackoverflow.com/questions/40021882/how-to-sort-readdir-iterator
    got.entries.sort_by_key(|entry| match entry {
        Entry::Directory(dir) => dir.name.clone(),
        Entry::File(file) => file.name.clone(),
        Entry::Symlink(sym) => sym.name().to_string(),
    });

    assert_eq!(expected, got);
    Ok(())
}

#[test]
fn test_chunk_config_from_str() {
    assert_eq!(
        "fixed".parse::<ChunkerConfig>().unwrap(),
        ChunkerConfig::Fixed(DEFAULT_CHUNKS_SIZE)
    );
    assert_eq!(
        "fixed-123".parse::<ChunkerConfig>().unwrap(),
        ChunkerConfig::Fixed(123)
    );

    assert!("fixed-".parse::<ChunkerConfig>().is_err());
    assert!(format!("fixed-{}", DEFAULT_CHUNK_SIZE_LIMIT + 1)
        .parse::<ChunkerConfig>()
        .is_err());
    assert!("foo-123".parse::<ChunkerConfig>().is_err());
    assert!("foo".parse::<ChunkerConfig>().is_err());

    assert_eq!(
        "rabin".parse::<ChunkerConfig>().unwrap(),
        ChunkerConfig::Rabin
    );
}
