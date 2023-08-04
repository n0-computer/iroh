#![cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
#![cfg(feature = "cli")]
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{env, io};

use anyhow::{Context, Result};
use bao_tree::blake3;
use duct::{cmd, ReaderHandle};
use iroh::bytes::Hash;
use iroh::dial::Ticket;
use rand::{Rng, RngCore, SeedableRng};
use regex::Regex;
use testdir::testdir;
use walkdir::WalkDir;

const ADDR: &str = "127.0.0.1:0";
const RPC_PORT: &str = "4999";

fn make_rand_file(size: usize, path: &Path) -> Result<Hash> {
    let mut content = vec![0u8; size];
    rand::rngs::StdRng::seed_from_u64(1).fill_bytes(&mut content);
    let hash = blake3::hash(&content);
    std::fs::write(path, content)?;
    Ok(hash.into())
}

#[test]
fn cli_provide_one_file_basic() -> Result<()> {
    let dir = testdir!();
    let path = dir.join("foo");
    make_rand_file(1000, &path)?;
    // provide a path to a file, do not pipe from stdin, do not pipe to stdout
    test_provide_get_loop(&path, Input::Path, Output::Path)
}

#[test]
#[ignore]
fn cli_provide_one_file_large() -> Result<()> {
    let dir = testdir!();
    let path = dir.join("foo");
    make_rand_file(1024 * 1024 * 1024, &path)?;
    // provide a path to a file, do not pipe from stdin, do not pipe to stdout
    test_provide_get_loop(&path, Input::Path, Output::Path)
}

#[test]
fn cli_provide_one_file_single() -> Result<()> {
    let dir = testdir!();
    let path = dir.join("foo");
    let hash = make_rand_file(1000, &path)?;
    // test single file download to stdout
    test_provide_get_loop_single(&path, Input::Path, Output::Stdout, hash)?;
    // test single file download to a path
    test_provide_get_loop_single(&path, Input::Path, Output::Path, hash)?;
    Ok(())
}

#[test]
fn cli_provide_folder() -> Result<()> {
    let dir = testdir!().join("src");
    std::fs::create_dir(&dir)?;
    let foo_path = dir.join("foo");
    let bar_path = dir.join("bar");
    make_rand_file(1000, &foo_path)?;
    make_rand_file(10000, &bar_path)?;
    // provide a path to a folder, do not pipe from stdin, do not pipe to stdout
    test_provide_get_loop(&dir, Input::Path, Output::Path)
}

#[test]
fn cli_provide_tree() -> Result<()> {
    let dir = testdir!().join("src");
    std::fs::create_dir(&dir)?;
    let foo_path = dir.join("foo");
    let bar_path = dir.join("bar");
    let file1 = foo_path.join("file1");
    let file2 = bar_path.join("file2");
    let file3 = bar_path.join("file3");
    std::fs::create_dir(&foo_path)?;
    std::fs::create_dir(&bar_path)?;
    make_rand_file(1000, &file1)?;
    make_rand_file(10000, &file2)?;
    make_rand_file(5000, &file3)?;
    // provide a path to a folder, do not pipe from stdin, do not pipe to stdout
    test_provide_get_loop(&dir, Input::Path, Output::Path)
}

fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    std::fs::create_dir_all(&dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            let to = dst.as_ref().join(entry.file_name());
            std::fs::copy(entry.path(), to)?;
        }
    }
    Ok(())
}

#[cfg(feature = "flat-db")]
/// What do to with a file pair when making partial files
enum MakePartialResult {
    /// leave the file as is
    Retain,
    /// remove it entirely
    Remove,
    /// truncate the data file to the given size
    Truncate(u64),
}

/// take an iroh_data_dir containing a flat file database and convert some of the files to partial files
///
/// Note that this assumes that both complete and partial files are in the same directory
#[cfg(feature = "flat-db")]
fn make_partial(
    dir: impl AsRef<Path>,
    op: impl Fn(Hash, u64) -> MakePartialResult,
) -> io::Result<()> {
    use iroh::database::flat::FileName;
    let dir = dir.as_ref();
    let mut files = BTreeMap::<Hash, (Option<u64>, bool)>::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(name) = iroh::database::flat::FileName::from_str(name) else { continue };
        match name {
            iroh::database::flat::FileName::Data(hash) => {
                let data = files.entry(hash).or_default();
                data.0 = Some(entry.metadata()?.len());
            }
            iroh::database::flat::FileName::Outboard(hash) => {
                let data = files.entry(hash).or_default();
                data.1 = true;
            }
            _ => continue,
        }
    }
    files.retain(|_hash, (size, _ob)| size.is_some());
    for (hash, (size, ob)) in files {
        match op(hash, size.unwrap()) {
            MakePartialResult::Retain => {}
            MakePartialResult::Remove => {
                let src = dir.join(FileName::Data(hash).to_string());
                std::fs::remove_file(src)?;
                if ob {
                    let src = dir.join(FileName::Outboard(hash).to_string());
                    std::fs::remove_file(src)?;
                }
            }
            MakePartialResult::Truncate(truncated_size) => {
                let uuid = rand::thread_rng().gen();
                let src = dir.join(FileName::Data(hash).to_string());
                let tgt = dir.join(FileName::PartialData(hash, uuid).to_string());
                std::fs::rename(src, &tgt)?;
                let file = std::fs::OpenOptions::new().write(true).open(tgt)?;
                file.set_len(truncated_size)?;
                drop(file);
                if ob {
                    let src = dir.join(FileName::Outboard(hash).to_string());
                    let tgt = dir.join(FileName::PartialOutboard(hash, uuid).to_string());
                    std::fs::rename(src, tgt)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(feature = "flat-db")]
#[test]
fn cli_provide_tree_resume() -> Result<()> {
    /// Get all matches for match group 1 (an explicitly defined match group)
    fn explicit_matches(matches: Vec<(usize, Vec<String>)>) -> Vec<String> {
        matches
            .iter()
            .filter_map(|(_, m)| m.get(1).cloned())
            .collect::<Vec<_>>()
    }

    let tmp = testdir!();
    let src = tmp.join("src");
    let src_iroh_data_dir = tmp.join("src_iroh_data_dir");
    let tgt = tmp.join("tgt");
    let tgt_work_dir = tmp.join(".iroh-tmp");
    std::fs::create_dir(&src)?;
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
    // leave the provider running for the entire test
    let provider = make_provider_in(&src_iroh_data_dir, &src, Input::Path, None, None)?;
    let count = count_input_files(&src);
    let ticket = match_provide_output(&provider, count)?;
    // first test - empty work dir
    {
        let get = make_get_cmd(&ticket, Some(tgt.clone()));
        let get_output = get.unchecked().run()?;
        assert!(get_output.status.success());
        let matches = explicit_matches(match_get_stderr(get_output.stderr)?);
        assert_eq!(matches, vec!["112.84 KiB"]);
        compare_files(&src, &tgt)?;
        std::fs::remove_dir_all(&tgt)?;
    }

    // second test - full work dir
    {
        copy_dir_all(&src_iroh_data_dir, &tgt_work_dir)?;
        let get = make_get_cmd(&ticket, Some(tgt.clone()));
        let get_output = get.unchecked().run()?;
        assert!(get_output.status.success());
        let matches = explicit_matches(match_get_stderr(get_output.stderr)?);
        assert_eq!(matches, vec!["0B"]);
        compare_files(&src, &tgt)?;
        std::fs::remove_dir_all(&tgt)?;
    }

    // third test - partial work dir - remove some large files
    {
        copy_dir_all(&src_iroh_data_dir, &tgt_work_dir)?;
        make_partial(&tgt_work_dir, |_hash, size| {
            if size == 100000 {
                MakePartialResult::Remove
            } else {
                MakePartialResult::Retain
            }
        })?;
        let get = make_get_cmd(&ticket, Some(tgt.clone()));
        let get_output = get.unchecked().run()?;
        assert!(get_output.status.success());
        let matches = explicit_matches(match_get_stderr(get_output.stderr)?);
        assert_eq!(matches, vec!["98.04 KiB"]);
        compare_files(&src, &tgt)?;
        std::fs::remove_dir_all(&tgt)?;
    }

    // fourth test - partial work dir - truncate some large files
    {
        copy_dir_all(&src_iroh_data_dir, &tgt_work_dir)?;
        make_partial(tgt_work_dir, |_hash, size| {
            if size == 100000 {
                MakePartialResult::Truncate(1024 * 32)
            } else {
                MakePartialResult::Retain
            }
        })?;
        let get = make_get_cmd(&ticket, Some(tgt.clone()));
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

#[test]
fn cli_provide_from_stdin_to_stdout() -> Result<()> {
    let dir = testdir!();
    let path = dir.join("foo");
    make_rand_file(1000, &path)?;
    // provide a file, pipe content to the provider's stdin, pipe content to the getter's stdout
    test_provide_get_loop(&path, Input::Stdin, Output::Stdout)
}

#[cfg(all(unix, feature = "cli"))]
#[test]
fn cli_provide_persistence() -> anyhow::Result<()> {
    use iroh::database::flat::Database;
    use iroh_bytes::provider::BaoReadonlyDb;
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
            [
                "provide",
                "--addr",
                ADDR,
                "--rpc-port",
                "disabled",
                path.to_str().unwrap(),
            ],
        )
        .env("IROH_DATA_DIR", &iroh_data_dir)
        .stdin_null()
        .stderr_capture()
        .reader()
    };
    // start provide until we got the ticket, then stop with control-c
    let provide = |path| {
        let mut child = iroh_provide(path)?;
        // wait for the provider to start
        let _ticket = match_provide_output(&mut child, 1)?;
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
    let db = Database::load_blocking(&iroh_data_dir, &iroh_data_dir)?;
    let blobs = db.blobs().collect::<Vec<_>>();
    assert_eq!(blobs.len(), 2);

    provide(&bar_path)?;
    // should have more data now
    let db = Database::load_blocking(&iroh_data_dir, &iroh_data_dir)?;
    let blobs = db.blobs().collect::<Vec<_>>();
    assert_eq!(blobs.len(), 4);

    Ok(())
}

#[test]
fn cli_provide_addresses() -> Result<()> {
    let dir = testdir!();
    let path = dir.join("foo");
    make_rand_file(1000, &path)?;

    let mut provider = spawn_provider(&path, Input::Path, Some("127.0.0.1:4333"), Some(RPC_PORT))?;
    // wait for the provider to start
    let _ticket = match_provide_output(&mut provider, 1)?;

    // test output
    let get_output = cmd(iroh_bin(), ["addresses", "--rpc-port", RPC_PORT])
        // .stderr_file(std::io::stderr().as_raw_fd()) for debug output
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
#[derive(Debug, PartialEq, Clone, Copy)]
enum Input {
    /// Indicates we should pass the content as an argument to the `iroh provide` command
    Path,
    /// Idincates we should pipe the content via `stdin` to the `iroh provide` command
    Stdin,
}

fn iroh_bin() -> &'static str {
    env!("CARGO_BIN_EXE_iroh")
}

/// Makes a provider process with it's home directory in `iroh_data_dir`.
fn make_provider_in(
    iroh_data_dir: &Path,
    path: &Path,
    input: Input,
    addr: Option<&str>,
    rpc_port: Option<&str>,
) -> Result<ReaderHandle> {
    // spawn a provider & optionally provide from stdin
    let res = cmd(
        iroh_bin(),
        [
            "provide",
            path.to_str().unwrap(),
            "--addr",
            addr.unwrap_or(ADDR),
            "--rpc-port",
            rpc_port.unwrap_or("disabled"),
        ],
    )
    .stderr_null()
    // .stderr_file(std::io::stderr().as_raw_fd()) for debug output
    .env("RUST_LOG", "debug")
    .env("IROH_DATA_DIR", &iroh_data_dir);

    let provider = match input {
        Input::Stdin => res.stdin_path(path),
        Input::Path => res.stdin_null(),
    }
    .reader()?;

    // wrap in `ProvideProcess` to ensure the spawned process is killed on drop
    Ok(provider)
}

/// Makes a provider process with it's home directory in `testdir!()`.
fn spawn_provider(
    path: &Path,
    input: Input,
    addr: Option<&str>,
    rpc_port: Option<&str>,
) -> Result<ReaderHandle> {
    let home = testdir!();
    let iroh_data_dir = home.join("iroh_data_dir");
    make_provider_in(&iroh_data_dir, path, input, addr, rpc_port)
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
fn make_get_cmd(ticket: &str, out: Option<PathBuf>) -> duct::Expression {
    // create a `get-ticket` cmd & optionally provide out path
    if let Some(ref out) = out {
        cmd(
            iroh_bin(),
            ["get", "--ticket", ticket, "--out", out.to_str().unwrap()],
        )
    } else {
        cmd(iroh_bin(), ["get", "--ticket", ticket])
    }
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
fn test_provide_get_loop(path: &Path, input: Input, output: Output) -> Result<()> {
    let num_blobs = count_input_files(path);
    let mut provider = spawn_provider(path, input, None, None)?;

    // test provide output & scrape the ticket from stderr
    let ticket = match_provide_output(&mut provider, num_blobs)?;
    let out_dir = to_out_dir(output);
    let get_cmd = make_get_cmd(&ticket, out_dir.clone());

    // test get stderr output
    let get_output = get_cmd.unchecked().run()?;
    drop(provider);

    // checking the output first, so you can still view any logging
    match_get_stderr(get_output.stderr)?;
    assert!(get_output.status.success());

    // test output
    match out_dir {
        None => {
            assert!(!get_output.stdout.is_empty());
            let expect_content = std::fs::read(path)?;
            assert_eq!(expect_content, get_output.stdout);
        }
        Some(out) => compare_files(path, out)?,
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
fn test_provide_get_loop_single(
    path: &Path,
    input: Input,
    output: Output,
    hash: Hash,
) -> Result<()> {
    let out = match output {
        Output::Stdout => None,
        Output::Path => {
            let dir = testdir!();
            Some(dir.join("out"))
        }
        Output::Custom(out) => Some(out),
    };

    let num_blobs = if path.is_dir() {
        WalkDir::new(path)
            .into_iter()
            .filter_map(|x| x.ok().filter(|x| x.file_type().is_file()))
            .count()
    } else {
        1
    };

    let mut provider = spawn_provider(path, input, None, None)?;
    // test provide output & get all in one ticket from stderr
    let ticket = match_provide_output(&mut provider, num_blobs)?;
    let ticket = Ticket::from_str(&ticket).unwrap();
    let addrs = ticket
        .addrs()
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>();
    let peer = ticket.peer().to_string();

    // create a `get-ticket` cmd & optionally provide out path
    let mut args = vec!["get", "--peer", &peer];
    for addr in &addrs {
        args.push("--addrs");
        args.push(addr);
    }
    if let Some(ref out) = out {
        args.push("--out");
        args.push(out.to_str().unwrap());
    }
    args.push("--single");
    let hash_str = hash.to_string();
    args.push(&hash_str);
    let cmd = cmd(iroh_bin(), args)
        .stdout_capture()
        .stderr_capture()
        .unchecked();

    // test get stderr output
    let get_output = cmd.run()?;
    // println!("{}", std::str::from_utf8(&get_output.stdout).unwrap());
    // println!("{}", std::str::from_utf8(&get_output.stderr).unwrap());
    provider.kill().expect("failed to kill provider");
    assert!(get_output.status.success());

    // test output
    let expect_content = std::fs::read(path)?;
    match out {
        None => {
            assert!(!get_output.stdout.is_empty());
            assert_eq!(expect_content, get_output.stdout);
        }
        Some(out) => {
            let content = std::fs::read(out)?;
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
/// Errors on the first regex mis-match or if the stderr output has fewer lines than expected
fn match_get_stderr(stderr: Vec<u8>) -> Result<Vec<(usize, Vec<String>)>> {
    let captures = assert_matches_line(
        std::io::Cursor::new(stderr),
        [
            (r"Fetching: [\da-z]{59}", 1),
            (r"\[1/3\] Connecting ...", 1),
            (r"\[2/3\] Requesting ...", 1),
            (r"\[3/3\] Downloading ...", 1),
            (
                r"\d* file\(s\) with total transfer size [\d.]* ?(?:B|KiB|MiB|GiB|TiB)",
                1,
            ),
            (
                r"Transferred (\d*.?\d*? ?[BKMGT]i?B?) in \d* seconds?, \d*.?\d* ?(?:B|KiB|MiB|GiB|TiB)/s",
                1,
            ),
        ],
    );
    Ok(captures)
}

/// Asserts provider output, returning the all-in-one ticket.
///
/// The provider output is asserted to check if it matches expected output.  The all-in-one
/// ticket is parsed out and returned as a string.
///
/// Returns an error on the first regex mismatch or if the stderr output has fewer lines
/// than expected.
fn match_provide_output<T: Read>(reader: T, num_blobs: usize) -> Result<String> {
    let reader = BufReader::new(reader);

    let mut caps = assert_matches_line(
        reader,
        [
            (r"Listening addresses:", 1),
            (r"^  \S+", -1),
            (r"DERP Region:", 1),
            (r"PeerID: [_\w\d-]*", 1),
            (r"", 1),
            (r"Adding .*", 1),
            (r"- \S*: \d*.?\d*? ?[BKMGT]i?B?", num_blobs as i64),
            (r"Total: [_\w\d-]*", 1),
            (r"", 1),
            (r"Collection: [\da-z]{59}", 1),
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
