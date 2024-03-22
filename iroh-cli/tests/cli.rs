#![cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result};
use bao_tree::blake3;
use duct::{cmd, ReaderHandle};
use iroh::bytes::Hash;
use iroh::bytes::HashAndFormat;
use iroh::ticket::BlobTicket;
use iroh::util::path::IrohPaths;
use rand::distributions::{Alphanumeric, DistString};
use rand::SeedableRng;
use regex::Regex;
use testdir::testdir;
use walkdir::WalkDir;

fn make_rand_file(size: usize, path: &Path) -> Result<Hash> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    let content = Alphanumeric.sample_string(&mut rng, size);

    let hash = blake3::hash(content.as_bytes());
    std::fs::write(path, content)?;
    Ok(hash.into())
}

#[test]
#[ignore = "flaky"]
fn cli_provide_one_file_basic() -> Result<()> {
    let dir = testdir!();
    let path = dir.join("foo");
    make_rand_file(1000, &path)?;
    // provide a path to a file, do not pipe from stdin, do not pipe to stdout
    test_provide_get_loop(Input::Path(path), Output::Path)
}

#[test]
#[ignore = "flaky"]
fn cli_provide_one_file_large() -> Result<()> {
    let dir = testdir!();
    let path = dir.join("foo");
    make_rand_file(1024 * 1024 * 1024, &path)?;
    // provide a path to a file, do not pipe from stdin, do not pipe to stdout
    test_provide_get_loop(Input::Path(path), Output::Path)
}

/// Test single file download to a path
#[test]
#[ignore = "flaky"]
fn cli_provide_one_file_single_path() -> Result<()> {
    let dir = testdir!();
    let path = dir.join("foo");
    let hash = make_rand_file(1000, &path)?;

    test_provide_get_loop_single(Input::Path(path), Output::Path, hash)?;
    Ok(())
}

/// test single file download to stdout
#[test]
#[ignore = "flaky"]
fn cli_provide_one_file_single_stdout() -> Result<()> {
    let dir = testdir!();
    let path = dir.join("foo");
    let hash = make_rand_file(1000, &path)?;

    test_provide_get_loop_single(Input::Path(path.clone()), Output::Stdout, hash)?;

    Ok(())
}

#[test]
#[ignore = "flaky"]
fn cli_provide_folder() -> Result<()> {
    let path = testdir!().join("src");
    std::fs::create_dir(&path)?;
    let foo_path = path.join("foo");
    let bar_path = path.join("bar");
    make_rand_file(1000, &foo_path)?;
    make_rand_file(10000, &bar_path)?;
    // provide a path to a folder, do not pipe from stdin, do not pipe to stdout
    test_provide_get_loop(Input::Path(path), Output::Path)
}

#[test]
#[ignore = "flaky"]
fn cli_provide_tree() -> Result<()> {
    let path = testdir!().join("src");
    std::fs::create_dir(&path)?;
    let foo_path = path.join("foo");
    let bar_path = path.join("bar");
    let file1 = foo_path.join("file1");
    let file2 = bar_path.join("file2");
    let file3 = bar_path.join("file3");
    std::fs::create_dir(&foo_path)?;
    std::fs::create_dir(&bar_path)?;
    make_rand_file(1000, &file1)?;
    make_rand_file(10000, &file2)?;
    make_rand_file(5000, &file3)?;

    // provide a path to a folder, do not pipe from stdin, do not pipe to stdout
    test_provide_get_loop(Input::Path(path), Output::Path)
}

#[cfg(feature = "fs-store")]
#[test]
#[ignore = "flaky"]
fn cli_provide_tree_resume() -> Result<()> {
    use iroh_bytes::store::file::test_support::{make_partial, MakePartialResult};

    /// Get all matches for match group 1 (an explicitly defined match group)
    fn explicit_matches(matches: Vec<(usize, Vec<String>)>) -> Vec<String> {
        matches
            .iter()
            .filter_map(|(_, m)| m.get(1).cloned())
            .collect::<Vec<_>>()
    }

    let tmp = testdir!();
    let src = tmp.join("src");
    std::fs::create_dir(&src)?;
    let src_iroh_data_dir = tmp.join("src_iroh_data_dir");
    let tgt = tmp.join("tgt");
    {
        let foo_path = src.join("foo");
        let bar_path = src.join("bar");
        let file1 = foo_path.join("file1");
        let file2 = bar_path.join("file2");
        let file3 = bar_path.join("file3");
        std::fs::create_dir(&foo_path)?;
        std::fs::create_dir(&bar_path)?;
        make_rand_file(10000, &file1)?;
        make_rand_file(100000, &file2)?;
        make_rand_file(5000, &file3)?;
    }
    // leave the provider running for the entire test
    let provider = make_provider_in(&src_iroh_data_dir, Input::Path(src.clone()), false)?;
    let count = count_input_files(&src);
    let ticket = match_provide_output(&provider, count, BlobOrCollection::Collection)?;
    {
        println!("first test - empty work dir");
        let get_iroh_data_dir = tmp.join("get_iroh_data_dir_01");
        let get = make_get_cmd(&get_iroh_data_dir, &ticket, Some(tgt.clone()));
        let get_output = get.unchecked().run()?;
        assert!(get_output.status.success());
        let matches = explicit_matches(match_get_stderr(get_output.stderr)?);
        assert_eq!(matches, vec!["112.89 KiB"]);
        compare_files(&src, &tgt)?;
        std::fs::remove_dir_all(&tgt)?;
    }

    // second test - full work dir
    {
        println!("second test - full work dir");
        let get_iroh_data_dir = tmp.join("get_iroh_data_dir_02");
        copy_blob_dirs(&src_iroh_data_dir, &get_iroh_data_dir)?;
        let get = make_get_cmd(&get_iroh_data_dir, &ticket, Some(tgt.clone()));
        let get_output = get.unchecked().run()?;
        assert!(get_output.status.success());
        let matches = explicit_matches(match_get_stderr(get_output.stderr)?);
        assert_eq!(matches, vec!["0 B"]);
        compare_files(&src, &tgt)?;
        std::fs::remove_dir_all(&tgt)?;
    }

    // third test - partial work dir - remove some large files
    {
        println!("third test - partial work dir - remove some large files");
        let get_iroh_data_dir = tmp.join("get_iroh_data_dir_03");
        copy_blob_dirs(&src_iroh_data_dir, &get_iroh_data_dir)?;
        make_partial(&get_iroh_data_dir, |_hash, size| {
            if size == 100000 {
                MakePartialResult::Remove
            } else {
                MakePartialResult::Retain
            }
        })?;
        let get = make_get_cmd(&get_iroh_data_dir, &ticket, Some(tgt.clone()));
        let get_output = get.unchecked().run()?;
        assert!(get_output.status.success());
        let matches = explicit_matches(match_get_stderr(get_output.stderr)?);
        assert_eq!(matches, vec!["98.04 KiB"]);
        compare_files(&src, &tgt)?;
        std::fs::remove_dir_all(&tgt)?;
    }

    // fourth test - partial work dir - truncate some large files
    {
        println!("fourth test - partial work dir - truncate some large files");
        let get_iroh_data_dir = tmp.join("get_iroh_data_dir_04");
        copy_blob_dirs(&src_iroh_data_dir, &get_iroh_data_dir)?;
        make_partial(&get_iroh_data_dir, |_hash, size| {
            if size == 100000 {
                MakePartialResult::Truncate(1024 * 32)
            } else {
                MakePartialResult::Retain
            }
        })?;
        let get = make_get_cmd(&get_iroh_data_dir, &ticket, Some(tgt.clone()));
        let get_output = get.unchecked().run()?;
        assert!(get_output.status.success());
        let matches = explicit_matches(match_get_stderr(get_output.stderr)?);
        assert_eq!(matches, vec!["65.98 KiB"]);
        compare_files(&src, &tgt)?;
        std::fs::remove_dir_all(&tgt)?;
    }
    drop(provider);
    Ok(())
}

#[cfg(feature = "fs-store")]
#[test]
#[ignore = "flaky"]
fn cli_provide_file_resume() -> Result<()> {
    use iroh_bytes::store::file::test_support::{make_partial, MakePartialResult};

    /// Get all matches for match group 1 (an explicitly defined match group)
    fn explicit_matches(matches: Vec<(usize, Vec<String>)>) -> Vec<String> {
        matches
            .iter()
            .filter_map(|(_, m)| m.get(1).cloned())
            .collect::<Vec<_>>()
    }

    let tmp = testdir!();
    let src = tmp.join("src");
    let tgt = tmp.join("tgt");
    std::fs::create_dir(&src)?;
    let src_iroh_data_dir = tmp.join("src_iroh_data_dir");
    let file = src.join("file");
    let hash = make_rand_file(100000, &file)?;
    // leave the provider running for the entire test
    let provider = make_provider_in(&src_iroh_data_dir, Input::Path(file.clone()), false)?;
    let count = count_input_files(&src);
    let ticket = match_provide_output(&provider, count, BlobOrCollection::Blob)?;
    {
        println!("first test - empty work dir");
        let get_iroh_data_dir = tmp.join("get_iroh_data_dir_01");
        let get = make_get_cmd(&get_iroh_data_dir, &ticket, Some(tgt.clone()));
        let get_output = get.unchecked().run()?;
        assert!(get_output.status.success());
        let matches = explicit_matches(match_get_stderr(get_output.stderr)?);
        assert_eq!(matches, vec!["98.04 KiB"]);
        assert_eq!(Hash::new(std::fs::read(&tgt)?), hash);
        // compare_files(&src, &tgt)?;
        std::fs::remove_file(&tgt)?;
    }

    // second test - full work dir
    {
        println!("second test - full work dir");
        let get_iroh_data_dir = tmp.join("get_iroh_data_dir_02");
        copy_blob_dirs(&src_iroh_data_dir, &get_iroh_data_dir)?;
        let get = make_get_cmd(&get_iroh_data_dir, &ticket, Some(tgt.clone()));
        let get_output = get.unchecked().run()?;
        assert!(get_output.status.success());
        let matches = explicit_matches(match_get_stderr(get_output.stderr)?);
        assert_eq!(matches, vec!["0 B"]);
        assert_eq!(Hash::new(std::fs::read(&tgt)?), hash);
        std::fs::remove_file(&tgt)?;
    }

    // third test - partial work dir - truncate some large files
    {
        println!("fourth test - partial work dir - truncate some large files");
        let get_iroh_data_dir = tmp.join("get_iroh_data_dir_04");
        copy_blob_dirs(&src_iroh_data_dir, &get_iroh_data_dir)?;
        make_partial(&get_iroh_data_dir, |_hash, _size| {
            MakePartialResult::Truncate(1024 * 32)
        })?;
        let get = make_get_cmd(&get_iroh_data_dir, &ticket, Some(tgt.clone()));
        let get_output = get.unchecked().run()?;
        assert!(get_output.status.success());
        let matches = explicit_matches(match_get_stderr(get_output.stderr)?);
        assert_eq!(matches, vec!["65.98 KiB"]);
        assert_eq!(Hash::new(std::fs::read(&tgt)?), hash);
        std::fs::remove_file(&tgt)?;
    }
    drop(provider);
    Ok(())
}

#[test]
#[ignore = "flaky"]
fn cli_provide_from_stdin_to_stdout() -> Result<()> {
    let dir = testdir!();
    let path = dir.join("foo");
    make_rand_file(1000, &path)?;
    // provide a file, pipe content to the provider's stdin, pipe content to the getter's stdout
    test_provide_get_loop(Input::Stdin(path), Output::Stdout)
}

/// Creates a v0 flat store in the given directory.
fn init_v0_blob_store(iroh_data_dir: &Path) -> anyhow::Result<()> {
    let complete_v0 = iroh_data_dir.join("blobs.v0");
    let partial_v0 = iroh_data_dir.join("blobs-partial.v0");
    let meta_v0 = iroh_data_dir.join("blobs-meta.v0");
    std::fs::create_dir_all(&complete_v0)?;
    std::fs::create_dir_all(&partial_v0)?;
    std::fs::create_dir_all(&meta_v0)?;
    let complete = b"complete";
    let partial = vec![0u8; 1024 * 17];
    let complete_hash = blake3::hash(complete).into();
    let partial_hash = blake3::hash(&partial).into();
    let mut tags = BTreeMap::<String, HashAndFormat>::new();
    tags.insert("complete".to_string(), HashAndFormat::raw(complete_hash));
    tags.insert("partial".to_string(), HashAndFormat::raw(partial_hash));
    let tags = postcard::to_stdvec(&tags)?;
    let uuid = [0u8; 16];
    std::fs::write(
        complete_v0.join(format!("{}.data", complete_hash.to_hex())),
        complete,
    )?;
    std::fs::write(
        partial_v0.join(format!(
            "{}-{}.data",
            partial_hash.to_hex(),
            hex::encode(uuid)
        )),
        partial,
    )?;
    std::fs::write(
        partial_v0.join(format!(
            "{}-{}.obao4",
            partial_hash.to_hex(),
            hex::encode(uuid)
        )),
        vec![],
    )?;
    std::fs::write(meta_v0.join("tags.meta"), tags)?;
    Ok(())
}

fn run_cli(
    iroh_data_dir: impl Into<OsString>,
    args: impl IntoIterator<Item = impl Into<OsString>>,
) -> anyhow::Result<String> {
    let output = cmd(iroh_bin(), args)
        .env_remove("RUST_LOG")
        .env("IROH_DATA_DIR", iroh_data_dir)
        // .stderr_file(std::io::stderr().as_raw_fd()) // for debug output
        .stdout_capture()
        .run()?;
    let text = String::from_utf8(output.stdout)?;
    Ok(text)
}

#[test]
#[ignore = "flaky"]
fn cli_bao_store_migration() -> anyhow::Result<()> {
    let dir = testdir!();
    let iroh_data_dir = dir.join("iroh_data_dir");
    init_v0_blob_store(&iroh_data_dir)?;
    let mut reader_handle = cmd(iroh_bin(), ["start"])
        .env_remove("RUST_LOG")
        .env("IROH_DATA_DIR", &iroh_data_dir)
        .stderr_to_stdout()
        .reader()?;

    assert_matches_line(
        BufReader::new(&mut reader_handle),
        [(r"Iroh is running", 1), (r"Node ID: [_\w\d-]*", 1)],
    );

    println!("iroh started up.");
    let tags_output = run_cli(&iroh_data_dir, ["tag", "list"])?;
    let expected = r#""complete": 2vfkw5gcrtbybfsczoxq4mae47svtgcgsniwcvoz7xf36nz45yfa (Raw)
"partial": 4yny3v7anmzzsajv2amm3nxpqd2owfw4dqnjwq6anv7nj2djmt2q (Raw)
"#;
    assert_eq!(tags_output, expected);

    let blob_output = run_cli(&iroh_data_dir, ["blob", "list", "blobs"])?;
    let expected = r#" 2vfkw5gcrtbybfsczoxq4mae47svtgcgsniwcvoz7xf36nz45yfa (8 B)
"#;
    assert_eq!(blob_output, expected);

    let incomplete_blob_output = run_cli(iroh_data_dir, ["blob", "list", "incomplete-blobs"])?;
    let expected = r#"4yny3v7anmzzsajv2amm3nxpqd2owfw4dqnjwq6anv7nj2djmt2q (0 B)
"#;
    assert_eq!(incomplete_blob_output, expected);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "flaky"]
async fn cli_provide_persistence() -> anyhow::Result<()> {
    use iroh::bytes::store::ReadableStore;
    use nix::{
        sys::signal::{self, Signal},
        unistd::Pid,
    };
    use std::time::Duration;

    let dir = testdir!();
    let iroh_data_dir = dir.join("iroh_data_dir");

    let foo_path = dir.join("foo");
    std::fs::write(&foo_path, b"foo")?;
    let bar_path = dir.join("bar");
    std::fs::write(&bar_path, b"bar")?;

    // spawn iroh in provide mode
    let iroh_provide = |path: &PathBuf| {
        cmd(
            iroh_bin(),
            ["start", "--add", path.to_str().unwrap(), "--wrap"],
        )
        .env("IROH_DATA_DIR", &iroh_data_dir)
        .env_remove("RUST_LOG")
        .stdin_null()
        .stderr_to_stdout()
        .reader()
    };
    // start provide until we got the ticket, then stop with control-c
    let provide = |path| {
        let mut child = iroh_provide(path)?;
        // wait for the provider to start
        let _ticket = match_provide_output(&mut child, 1, BlobOrCollection::Collection)?;
        println!("got ticket, stopping provider {}", _ticket);
        // kill the provider via Control-C
        for pid in child.pids() {
            signal::kill(Pid::from_raw(pid as i32), Signal::SIGINT).unwrap();
        }
        // wait for the provider to stop
        loop {
            if let Some(_output) = child.try_wait()? {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        anyhow::Ok(())
    };
    provide(&foo_path)?;
    // should have some data now
    let db_path = IrohPaths::BaoStoreDir.with_root(&iroh_data_dir);
    let db = iroh::bytes::store::fs::Store::persistent(&db_path).await?;
    let blobs: Vec<std::io::Result<Hash>> = db.blobs().await.unwrap().collect::<Vec<_>>();
    drop(db);
    assert_eq!(blobs.len(), 3);

    provide(&bar_path)?;
    // should have more data now
    let db = iroh::bytes::store::fs::Store::persistent(&db_path).await?;
    let blobs = db.blobs().await.unwrap().collect::<Vec<_>>();
    drop(db);
    assert_eq!(blobs.len(), 6);

    Ok(())
}

#[test]
#[ignore = "flaky"]
fn cli_provide_addresses() -> Result<()> {
    let dir = testdir!();
    let path = dir.join("foo");
    make_rand_file(1000, &path)?;

    let iroh_data_dir = dir.join("iroh-data-dir");
    let mut provider = make_provider_in(&iroh_data_dir, Input::Path(path), true)?;
    // wait for the provider to start
    let _ticket = match_provide_output(&mut provider, 1, BlobOrCollection::Collection)?;

    // test output
    let get_output = cmd(iroh_bin(), ["node", "status"])
        .env_remove("RUST_LOG")
        .env("IROH_DATA_DIR", iroh_data_dir)
        // .stderr_file(std::io::stderr().as_raw_fd()) // for debug output
        .stdout_capture()
        .run()?;
    let stdout = String::from_utf8(get_output.stdout).unwrap();
    assert!(get_output.status.success());
    assert!(stdout.starts_with("Listening addresses:"));
    //parse the output to get the addresses
    let addresses = stdout
        .split('[')
        .nth(1)
        .unwrap()
        .split(']')
        .next()
        .unwrap()
        .split(',')
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .map(|x| SocketAddr::from_str(x).unwrap())
        .collect::<Vec<_>>();
    assert!(!addresses.is_empty());
    Ok(())
}

#[test]
#[ignore = "flaky"]
fn cli_rpc_lock_restart() -> Result<()> {
    let dir = testdir!();
    let iroh_data_dir = dir.join("data-dir");

    println!("start");
    let mut reader_handle = cmd(iroh_bin(), ["start"])
        .env_remove("RUST_LOG")
        .env("IROH_DATA_DIR", &iroh_data_dir)
        .stderr_to_stdout()
        .reader()?;

    assert_matches_line(
        BufReader::new(&mut reader_handle),
        [(r"Iroh is running", 1), (r"Node ID: [_\w\d-]*", 1)],
    );

    // check for the lock file
    assert!(
        IrohPaths::RpcLock.with_root(&iroh_data_dir).exists(),
        "missing lock file"
    );

    // kill process
    println!("killing process");
    reader_handle.kill()?;

    // File should still be there
    assert!(
        IrohPaths::RpcLock.with_root(&iroh_data_dir).exists(),
        "missing lock file"
    );

    // Restart should work fine
    println!("restart");
    let mut reader_handle = cmd(iroh_bin(), ["start"])
        .env_remove("RUST_LOG")
        .env("IROH_DATA_DIR", &iroh_data_dir)
        .stderr_to_stdout()
        .reader()?;

    assert_matches_line(
        BufReader::new(&mut reader_handle),
        [(r"Iroh is running", 1), (r"Node ID: [_\w\d-]*", 1)],
    );

    println!("double start");
    let output = cmd(iroh_bin(), ["start"])
        .env_remove("RUST_LOG")
        .env("IROH_DATA_DIR", &iroh_data_dir)
        .stderr_capture()
        .unchecked()
        .run()?;

    let output = std::str::from_utf8(&output.stderr).unwrap();
    println!("{}", output);
    assert!(output.contains("iroh is already running on port"));

    Ok(())
}

/// Parameter for `test_provide_get_loop`, that determines how we handle the fetched data from the
/// `iroh get` command
#[derive(Debug, PartialEq)]
enum Output {
    /// Indicates we should save the content as a file in the given directory, by passing the path
    /// to the `--out` argument in `iroh get`
    Path,
    /// Indicates we should pipe the content to `stdout` of the `iroh get` process
    Stdout,
    /// Custom output
    #[allow(dead_code)]
    Custom(PathBuf),
}

/// Parameter for `test_provide_get_loop`, that determines how we send the data to the `provide`
/// command.
#[derive(Debug, PartialEq, Clone)]
enum Input {
    /// Indicates we should pass the content as an argument to the `iroh start` command
    Path(PathBuf),
    /// Idincates we should pipe the content via `stdin` to the `iroh start` command
    /// should point to a file, never to a directory
    Stdin(PathBuf),
}

impl Input {
    fn as_path(&self) -> &PathBuf {
        match self {
            Input::Path(ref p) => p,
            Input::Stdin(ref p) => p,
        }
    }

    fn as_arg(&self) -> String {
        match self {
            Input::Path(path) => path.to_str().unwrap().to_string(),
            Input::Stdin(_) => "STDIN".into(),
        }
    }

    fn should_wrap(&self) -> bool {
        match self {
            Input::Path(path) => path.as_path().is_file(),
            Input::Stdin(_) => false,
        }
    }

    fn is_blob_or_collection(&self) -> BlobOrCollection {
        match self {
            // we currently always create a collection because single files will be wrapped
            Input::Path(_) => BlobOrCollection::Collection,
            Input::Stdin(_) => BlobOrCollection::Blob,
        }
    }
}

fn iroh_bin() -> &'static str {
    env!("CARGO_BIN_EXE_iroh")
}

/// Makes a provider process with it's home directory in `iroh_data_dir`.
fn make_provider_in(iroh_data_dir: &Path, input: Input, wrap: bool) -> Result<ReaderHandle> {
    let mut args = vec!["start"];
    if wrap {
        args.push("--wrap");
    }
    args.push("--add");
    let arg = input.as_arg();
    args.push(&arg);

    // spawn a provider & optionally provide from stdin
    println!(
        "running iroh {:?} in dir: {}",
        args,
        iroh_data_dir.display()
    );
    let res = cmd(iroh_bin(), &args)
        .env_remove("RUST_LOG")
        .env("IROH_DATA_DIR", iroh_data_dir)
        .stderr_to_stdout();

    let provider = match input {
        Input::Stdin(ref p) => res.stdin_path(p),
        Input::Path(_) => res.stdin_null(),
    }
    .reader()?;

    // wrap in `ProvideProcess` to ensure the spawned process is killed on drop
    Ok(provider)
}

/// Count the number of files in the given path, for matching the output text in
/// [match_provide_output]
fn count_input_files(path: impl AsRef<Path>) -> usize {
    let path = path.as_ref();
    if path.is_dir() {
        WalkDir::new(path)
            .into_iter()
            .filter_map(|x| x.ok().filter(|x| x.file_type().is_file()))
            .count()
    } else {
        1
    }
}

/// Translate output into an optional out path
fn to_out_dir(output: Output) -> Option<PathBuf> {
    match output {
        Output::Path => {
            let dir = testdir!();
            Some(dir.join("out"))
        }
        Output::Custom(out) => Some(out),
        Output::Stdout => None,
    }
}

/// Create a get command given a ticket and an output mode
fn make_get_cmd(iroh_data_dir: &Path, ticket: &str, out: Option<PathBuf>) -> duct::Expression {
    // create a `get-ticket` cmd & optionally provide out path
    let out = out
        .map(|ref o| o.to_str().unwrap().to_string())
        .unwrap_or("STDOUT".into());
    let args = vec!["--start", "blob", "get", ticket, "--out", &out];

    println!(
        "running iroh {:?} in dir: {}",
        args,
        iroh_data_dir.display()
    );

    cmd(iroh_bin(), &args)
        .env_remove("RUST_LOG")
        .env("IROH_DATA_DIR", iroh_data_dir)
        .stdout_capture()
        .stderr_capture()
}

/// Test the provide and get loop for success, stderr output, and file contents.
///
/// Can optionally pipe the given `path` content to the provider from stdin & can optionally
/// save the output to an `out` path.
///
/// Runs the provider as a child process that stays alive until the getter has
/// completed. Then checks the output of the "provide" and "get" processes against expected
/// regex output. Finally, test the content fetched from the "get" process is the same as
/// the "provided" content.
fn test_provide_get_loop(input: Input, output: Output) -> Result<()> {
    let num_blobs = count_input_files(input.as_path());
    let wrap = input.should_wrap();

    let dir = testdir!();
    let iroh_data_dir = dir.join("iroh-data-dir");
    let mut provider = make_provider_in(&iroh_data_dir, input.clone(), wrap)?;

    // test provide output & scrape the ticket from stderr
    let ticket = match_provide_output(&mut provider, num_blobs, input.is_blob_or_collection())?;
    let out_dir = to_out_dir(output);
    let get_iroh_data_dir = dir.join("get-iroh-data-dir");
    let get_cmd = make_get_cmd(&get_iroh_data_dir, &ticket, out_dir.clone());

    // test get stderr output
    let get_output = get_cmd.unchecked().run()?;
    drop(provider);

    // checking the output first, so you can still view any logging
    println!("STDOUT: {:?}", std::str::from_utf8(&get_output.stdout),);
    println!(
        "STDERR: {}",
        std::str::from_utf8(&get_output.stderr).unwrap()
    );
    match_get_stderr(get_output.stderr)?;
    assert!(get_output.status.success());

    // test output
    match out_dir {
        None => {
            let path = input.as_path();
            assert!(!get_output.stdout.is_empty());
            let expect_content = std::fs::read_to_string(path)?;
            assert_eq!(
                expect_content,
                std::string::String::from_utf8_lossy(&get_output.stdout)
            );
        }
        Some(out) => compare_files(input.as_path(), out)?,
    };
    Ok(())
}

/// Test the provide and get loop for success, stderr output, and file contents.
///
/// Can optionally pipe the given `path` content to the provider from stdin & can optionally save the output to an `out` path.
///
/// Runs the provider as a child process that stays alive until the getter has completed. Then
/// checks the output of the "provide" and "get" processes against expected regex output. Finally,
/// test the content fetched from the "get" process is the same as the "provided" content.
fn test_provide_get_loop_single(input: Input, output: Output, hash: Hash) -> Result<()> {
    let out = match output {
        Output::Stdout => "STDOUT".to_string(),
        Output::Path => {
            let dir = testdir!();
            dir.join("out").display().to_string()
        }
        Output::Custom(ref out) => out.display().to_string(),
    };

    let num_blobs = if input.as_path().is_dir() {
        WalkDir::new(input.as_path())
            .into_iter()
            .filter_map(|x| x.ok().filter(|x| x.file_type().is_file()))
            .count()
    } else {
        1
    };

    let dir = testdir!();
    let iroh_data_dir = dir.join("iroh-data-dir");

    let mut provider = make_provider_in(&iroh_data_dir, input.clone(), true)?;

    // test provide output & get all in one ticket from stderr
    let ticket = match_provide_output(&mut provider, num_blobs, BlobOrCollection::Collection)?;
    let ticket = BlobTicket::from_str(&ticket).unwrap();
    let addrs = ticket
        .node_addr()
        .direct_addresses()
        .map(|x| x.to_string())
        .collect::<Vec<_>>();
    let node = ticket.node_addr().node_id.to_string();
    let relay_url = ticket
        .node_addr()
        .relay_url()
        .context("should have relay url in ticket")?
        .to_string();

    // create a `get-ticket` cmd & optionally provide out path
    let mut args = vec!["--start", "blob", "get", "--node", &node];
    for addr in &addrs {
        args.push("--address");
        args.push(addr);
    }
    args.push("--out");
    args.push(&out);

    args.push("--relay-url");
    args.push(&relay_url);
    let hash_str = hash.to_string();
    args.push(&hash_str);
    let get_iroh_data_dir = dir.join("get-iroh-data-dir");
    let cmd = cmd(iroh_bin(), args)
        .env_remove("RUST_LOG")
        .env("IROH_DATA_DIR", get_iroh_data_dir)
        .stdout_capture()
        .stderr_capture()
        .unchecked();

    // test get stderr output
    let get_output = cmd.run()?;
    println!("{}", std::str::from_utf8(&get_output.stdout).unwrap());
    println!("{}", std::str::from_utf8(&get_output.stderr).unwrap());

    provider.kill().expect("failed to kill provider");
    assert!(get_output.status.success());

    // test output
    let expect_content = std::fs::read_to_string(input.as_path())?;
    match output {
        Output::Stdout => {
            assert!(!get_output.stdout.is_empty());
            assert_eq!(
                expect_content,
                std::string::String::from_utf8_lossy(&get_output.stdout)
            );
        }
        _ => {
            let content = std::fs::read_to_string(out)?;
            assert_eq!(expect_content, content);
        }
    };
    Ok(())
}

fn compare_files(expect_path: impl AsRef<Path>, got_dir_path: impl AsRef<Path>) -> Result<()> {
    let expect_path = expect_path.as_ref();
    let got_dir_path = got_dir_path.as_ref();
    if expect_path.is_dir() {
        let paths = WalkDir::new(expect_path).into_iter().filter(|x| {
            x.as_ref()
                .ok()
                .map(|x| x.file_type().is_file())
                .unwrap_or(false)
        });
        for entry in paths {
            let entry = entry?;
            let file_path = entry.path();
            let rel = file_path.strip_prefix(expect_path)?;
            let expected_file_path = got_dir_path.join(rel);
            let got = std::fs::read(file_path)?;
            let expect = std::fs::read(expected_file_path)?;
            assert_eq!(expect, got);
        }
    } else {
        let file_name = expect_path.file_name().unwrap();
        let expect = std::fs::read(expect_path)?;
        let got = std::fs::read(got_dir_path.join(file_name))?;
        assert_eq!(expect, got);
    }

    Ok(())
}

/// Looks for regex matches on stderr output for the getter.
///
/// Errors on the first regex mismatch or if the stderr output has fewer lines than expected
fn match_get_stderr(stderr: Vec<u8>) -> Result<Vec<(usize, Vec<String>)>> {
    let captures = assert_matches_line(
        std::io::Cursor::new(stderr),
        [
            (r"Iroh is running", 1),
            (r"Node ID: [_\w\d-]*", 1),
            (r"", 1),
            (r"Fetching: [\da-z]{52}", 1),
            (
                r"Transferred (\d*.?\d*? ?[BKMGT]i?B?) in \d* seconds?, \d*.?\d* ?(?:B|KiB|MiB|GiB|TiB)/s",
                1,
            ),
        ],
    );
    Ok(captures)
}

enum BlobOrCollection {
    Blob,
    Collection,
}

/// Asserts provider output, returning the all-in-one ticket.
///
/// The provider output is asserted to check if it matches expected output.  The all-in-one
/// ticket is parsed out and returned as a string.
///
/// Returns an error on the first regex mismatch or if the stderr output has fewer lines
/// than expected.
fn match_provide_output<T: Read>(
    reader: T,
    num_blobs: usize,
    kind: BlobOrCollection,
) -> Result<String> {
    let reader = BufReader::new(reader);

    let blob_or_collection_matcher = match kind {
        BlobOrCollection::Collection => (r"Collection: [\da-z]{52}", 1),
        BlobOrCollection::Blob => (r"Blob: [\da-z]{52}", 1),
    };

    let mut caps = assert_matches_line(
        reader,
        [
            (r"Iroh is running", 1),
            (r"Node ID: [_\w\d-]*", 1),
            (r"", 1),
            (r"Adding .*", 1),
            (r"- \S*: \d*.?\d*? ?[BKMGT]i?B?", num_blobs as i64),
            (r"Total: [_\w\d-]*", 1),
            (r"", 1),
            blob_or_collection_matcher,
            (r"All-in-one ticket: ([_a-zA-Z\d-]*)", 1),
        ],
    );

    // return the capture of the all in one ticket, should be the last capture
    let (_, mut last) = caps.pop().context("Expected at least one capture.")?;
    let ticket = last.pop().context("expected ticket")?;
    Ok(ticket)
}

/// Ensures each line of the first expression matches the regex of each following expression. Each
/// regex expression is followed by the number of consecutive lines it should match.
///
/// A match number of `-1` indicates that the regex should match at least once.
///
/// Returns a vec of `String`s of any captures made against the regex on each line.
///
/// # Examples
/// ```
/// let expr = b"hello world!\nNice to meet you!\n02/23/2023\n02/23/2023\n02/23/2023";
/// let buf_reader = std::io::BufReader::new(&expr[..]);
/// assert_matches_line(
///     buf_reader,
///     [
///         (r"hello world!", 1),
///         (r"\S*$", 1),
///         (r"\d{2}/\d{2}/\d{4}", 3),
///     ]);
/// ```
fn assert_matches_line<R: BufRead, I>(reader: R, expressions: I) -> Vec<(usize, Vec<String>)>
where
    I: IntoIterator<Item = (&'static str, i64)>,
{
    let mut lines = reader.lines().peekable();
    let mut caps = Vec::new();

    for (ei, (regex_str, num_matches)) in expressions.into_iter().enumerate() {
        let rx = Regex::new(regex_str).expect("invalid regex");
        let mut matches = 0;

        loop {
            if num_matches > 0 && matches == num_matches as usize {
                break;
            }

            match lines.peek() {
                Some(Ok(line)) => {
                    println!("|{}", line);

                    let mut line_caps = Vec::new();
                    if let Some(cap) = rx.captures(line) {
                        for i in 0..cap.len() {
                            if let Some(capture_group) = cap.get(i) {
                                line_caps.push(capture_group.as_str().to_string());
                            }
                        }

                        matches += 1;
                    } else {
                        break;
                    }
                    caps.push((ei, line_caps));
                }
                Some(Err(err)) => {
                    panic!("Error from reader: {err:#}");
                }
                None => {
                    panic!("All lines read but no match found for /{rx}/");
                }
            }

            let _ = lines.next();
        }

        if num_matches == -1 {
            if matches == 0 {
                println!("Expected at least one match for regex: {}", regex_str);
                panic!("no matches found");
            }
        } else if matches != num_matches as usize {
            println!("Expected {} matches for regex: {}", num_matches, regex_str);
            panic!("invalid number of matches");
        }
    }

    caps
}
