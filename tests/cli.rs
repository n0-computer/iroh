#![cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result};
use rand::{RngCore, SeedableRng};
use testdir::testdir;

const ADDR: &str = "127.0.0.1:0";

fn make_rand_file(size: usize, path: &Path) -> Result<()> {
    let mut content = vec![0u8; size];
    rand::rngs::StdRng::seed_from_u64(1).fill_bytes(&mut content);
    std::fs::write(path, content)?;
    Ok(())
}

#[test]
fn cli_provide_one_file() -> Result<()> {
    let dir = testdir!();
    let path = dir.join("foo");
    make_rand_file(1000, &path)?;
    // provide a path to a file, do not pipe from stdin, do not pipe to stdout
    test_provide_get_loop(&path, Input::Path, Output::Path)
}

#[test]
fn cli_provide_folder() -> Result<()> {
    let dir = testdir!();
    let foo_path = dir.join("foo");
    let bar_path = dir.join("bar");
    make_rand_file(1000, &foo_path)?;
    make_rand_file(10000, &bar_path)?;
    // provide a path to a folder, do not pipe from stdin, do not pipe to stdout
    test_provide_get_loop(&dir, Input::Path, Output::Path)
}

#[test]
fn cli_provide_from_stdin_to_stdout() -> Result<()> {
    let dir = testdir!();
    let path = dir.join("foo");
    make_rand_file(1000, &path)?;
    // provide a file, pipe content to the provider's stdin, pipe content to the getter's stdout
    test_provide_get_loop(&path, Input::Stdin, Output::Stdout)
}

#[cfg(unix)]
#[tokio::test]
async fn cli_provide_persistence() -> anyhow::Result<()> {
    use iroh::provider::Database;
    use nix::{
        sys::signal::{self, Signal},
        unistd::Pid,
    };

    let dir = testdir!();
    let iroh_data_dir = dir.join("iroh_data_dir");

    let foo_path = dir.join("foo");
    std::fs::write(&foo_path, b"foo")?;
    let bar_path = dir.join("bar");
    std::fs::write(&bar_path, b"bar")?;
    // spawn iroh in provide mode
    let iroh_provide = |path| {
        Command::new(iroh_bin())
            .env("IROH_DATA_DIR", &iroh_data_dir)
            // comment out to get debug output from the child process
            // .env("RUST_LOG", "debug")
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .arg("provide")
            .arg("--addr")
            .arg(ADDR)
            .arg("--persistent=true")
            .arg("--rpc-port")
            .arg("disabled")
            .arg(path)
            .spawn()
    };
    // provide for 1 sec, then stop with control-c
    let provide_1sec = |path| {
        let mut child = iroh_provide(path)?;
        // wait for the provider to start
        std::thread::sleep(std::time::Duration::from_secs(1));
        // kill the provider via Control-C
        signal::kill(Pid::from_raw(child.id() as i32), Signal::SIGINT).unwrap();
        // wait for the provider to exit and make sure that it exited successfully
        let status = child.wait()?;
        // comment out to get debug output from the child process
        // std::io::copy(&mut child.stderr.unwrap(), &mut std::io::stdout())?;
        assert!(status.success());
        anyhow::Ok(())
    };
    provide_1sec(&foo_path)?;
    // should have some data now
    let db = Database::load(&iroh_data_dir).await?;
    let blobs = db.blobs().map(|x| x.1).collect::<Vec<_>>();
    assert_eq!(blobs, vec![foo_path.clone()]);

    provide_1sec(&bar_path)?;
    // should have more data now
    let db = Database::load(&iroh_data_dir).await?;
    let mut blobs = db.blobs().map(|x| x.1).collect::<Vec<_>>();
    blobs.sort();
    assert_eq!(blobs, vec![bar_path.clone(), foo_path.clone()]);

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
}

/// Parameter for `test_provide_get_loop`, that determines how we send the data to the `provide`
/// command.
#[derive(Debug, PartialEq)]
enum Input {
    /// Indicates we should pass the content as an argument to the `iroh provide` command
    Path,
    /// Idincates we should pipe the content via `stdin` to the `iroh provide` command
    Stdin,
}

fn iroh_bin() -> &'static str {
    env!("CARGO_BIN_EXE_iroh")
}

fn make_provider(path: &Path, input: &Input) -> Result<ProvideProcess> {
    // spawn a provider & optionally provide from stdin
    let mut command = Command::new(iroh_bin());
    let res = command
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .arg("provide")
        .arg(path)
        .arg("--addr")
        .arg(ADDR)
        .arg("--rpc-port")
        .arg("disabled")
        .arg("--persistent=false");

    let provider = match input {
        Input::Stdin => {
            let f = File::open(path)?;
            let stdin = Stdio::from(f);
            res.stdin(stdin).spawn()?
        }
        Input::Path => res.stdin(Stdio::null()).spawn()?,
    };

    // wrap in `ProvideProcess` to ensure the spawned process is killed on drop
    Ok(ProvideProcess { child: provider })
}

/// Test the provide and get loop for success, stderr output, and file contents.
///
/// Can optionally pipe the given `path` content to the provider from stdin & can optionally save the output to an `out` path.
///
/// Runs the provider as a child process that stays alive until the getter has completed. Then
/// checks the output of the "provide" and "get" processes against expected regex output. Finally,
/// test the content fetched from the "get" process is the same as the "provided" content.
fn test_provide_get_loop(path: &Path, input: Input, output: Output) -> Result<()> {
    let out = if output == Output::Stdout {
        None
    } else {
        let dir = testdir!();
        Some(dir.join("out"))
    };

    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");

    let path = src.join(path);
    let num_blobs = if path.is_dir() {
        let entries = std::fs::read_dir(&path)?;
        entries.count()
    } else {
        1
    };

    let mut provider = make_provider(&path, &input)?;
    let stdout = provider.child.stdout.take().unwrap();
    let stdout = BufReader::new(stdout);

    // test provide output & get all in one ticket from stderr
    let all_in_one = match_provide_output(stdout, num_blobs, input)?;

    // create a `get-ticket` cmd & optionally provide out path
    let mut cmd = Command::new(iroh_bin());
    cmd.arg("get-ticket").arg(all_in_one);
    let cmd = if let Some(ref out) = out {
        cmd.arg("--out").arg(out)
    } else {
        &mut cmd
    };

    // test get stderr output
    let get_output = cmd.output()?;
    assert!(get_output.status.success());

    // test output
    match out {
        None => {
            assert!(!get_output.stdout.is_empty());
            let expect_content = std::fs::read(path)?;
            assert_eq!(expect_content, get_output.stdout);
        }
        Some(out) => compare_files(path, out)?,
    };

    assert!(!get_output.stderr.is_empty());
    match_get_stderr(get_output.stderr)
}
/// Wrapping the [`Child`] process here allows us to impl the `Drop` trait ensuring the provide
/// process is killed when it goes out of scope.
struct ProvideProcess {
    child: Child,
}

impl Drop for ProvideProcess {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.try_wait().ok();
    }
}

fn compare_files(expect_path: impl AsRef<Path>, got_dir_path: impl AsRef<Path>) -> Result<()> {
    let expect_path = expect_path.as_ref();
    let got_dir_path = got_dir_path.as_ref();
    if expect_path.is_dir() {
        let paths = std::fs::read_dir(expect_path)?;
        for entry in paths {
            let entry = entry?;
            compare_files(entry.path(), got_dir_path)?;
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
fn match_get_stderr(stderr: Vec<u8>) -> Result<()> {
    println!("{}", String::from_utf8_lossy(&stderr[..]));
    let stderr = std::io::BufReader::new(&stderr[..]);
    assert_matches_line![
        stderr,
        r"Fetching: [\da-z]{59}"; 1,
        r"\[1/3\] Connecting ..."; 1,
        r"\[2/3\] Requesting ..."; 1,
        r"\[3/3\] Downloading collection..."; 1,
        r"\d* file\(s\) with total transfer size [\d.]* ?[BKMGT]?i?B"; 1,
        r"Transferred \d*.?\d*? ?[BKMGT]i?B? in \d* seconds?, \d*.?\d*? [BKMGT]iB/s"; 1
    ];
    Ok(())
}

/// Looks for regex matches on each line of output for the provider, returning the "all in one ticket"
/// that can be used to 'get' from another process.
///
/// Errors on the first regex mismatch or if the stderr output has fewer lines than expected
fn match_provide_output<T: Read>(
    reader: BufReader<T>,
    num_blobs: usize,
    input: Input,
) -> Result<String> {
    // if we are using `stdin` we don't "read" any files, so the provider does not output any lines
    // about "Reading"
    let _reading_line_num = match input {
        Input::Stdin => 0,
        Input::Path => 1,
    };

    let mut caps = assert_matches_line![
        reader,
        r"Listening address: [\d.:]*"; 1,
        r"PeerID: [_\w\d-]*"; 1,
        r"Auth token: [\w\d]*"; 1,
        r""; 1,
        r"Adding .*"; 1,
        r"- \S*: \d*.?\d*? ?[BKMGT]i?B?"; num_blobs,
        r"Total: [_\w\d-]*"; 1,
        r""; 1,
        r"Collection: [\da-z]{59}"; 1,
        r"All-in-one ticket: ([_a-zA-Z\d-]*)"; 1
    ];

    // return the capture of the all in one ticket, should be the last capture
    caps.pop().context("Expected at least one capture.")
}

#[macro_export]
/// Ensures each line of the first expression matches the regex of each following expression. Each
/// regex expression is followed by the number of consecutive lines it should match.
///
/// Returns a vec of `String`s of any captures made against the regex on each line.
///
/// # Examples
/// ```
/// let expr = b"hello world!\nNice to meet you!\n02/23/2023\n02/23/2023\n02/23/2023";
/// let buf_reader = std::io::BufReader::new(&expr[..]);
/// assert_matches_line![
///     buf_reader,
///     r"hello world!"; 1,
///     r"\S*$"; 1,
///     r"\d{2}/\d{2}/\d{4}"; 3
/// ];
/// ```
macro_rules! assert_matches_line {
     ( $x:expr, $( $z:expr;$a:expr ),* ) => {
         {
            let mut lines = $x.lines();
            let mut caps = Vec::new();
            $(
            let rx = regex::Regex::new($z)?;
            for _ in 0..$a {
                let line = lines.next().context("Unexpected end of stderr reader")??;
                if let Some(cap) = rx.captures(line.trim()) {
                    for i in 0..cap.len() {
                        if let Some(capture_group) = cap.get(i) {
                            caps.push(capture_group.as_str().to_string());
                        }
                    }
                } else {
                    anyhow::bail!(format!("no match found\nexpected match for '{}'\ngot '{line}'", $z));
                };
            }
            )*
            caps
         }
    };
}
