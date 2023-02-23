#![cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};

use anyhow::{Context, Result};
use rand::RngCore;
use tempfile::tempdir;

const ADDR: &str = "127.0.0.1:0";

fn make_rand_file(size: usize, path: &Path) -> Result<()> {
    let mut content = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut content);
    std::fs::write(path, content)?;
    Ok(())
}

#[test]
fn cli_provide_one_file() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("foo");
    make_rand_file(1000, &path)?;
    // provide a path to a file, do not pipe from stdin, do not pipe to stdout
    test_provide_get_loop(&path, Input::Path, Output::Path)
}

#[test]
fn cli_provide_folder() -> Result<()> {
    let dir = tempdir()?;
    let foo_path = dir.path().join("foo");
    let bar_path = dir.path().join("bar");
    make_rand_file(1000, &foo_path)?;
    make_rand_file(10000, &bar_path)?;
    // provide a path to a folder, do not pipe from stdin, do not pipe to stdout
    test_provide_get_loop(dir.path(), Input::Path, Output::Path)
}

#[test]
fn cli_provide_from_stdin_to_stdout() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("foo");
    make_rand_file(1000, &path)?;
    // provide a file, pipe content to the provider's stdin, pipe content to the getter's stdout
    test_provide_get_loop(&path, Input::Stdin, Output::Stdout)
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
        let dir = tempdir()?;
        Some(dir.path().join("out"))
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

    let iroh = env!("CARGO_BIN_EXE_iroh");

    // spawn a provider & optionally provide from stdin
    let provider = if input == Input::Stdin {
        let f = File::open(&path)?;
        let stdin = Stdio::from(f);
        Command::new(iroh)
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .stdin(stdin)
            .arg("provide")
            .arg("--addr")
            .arg(ADDR)
            .spawn()?
    } else {
        Command::new(iroh)
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .arg("provide")
            .arg(&path)
            .arg("--addr")
            .arg(ADDR)
            .spawn()?
    };

    // wrap in `ProvideProcess` to ensure the spawned process is killed on drop
    let mut provider = ProvideProcess { child: provider };
    let stderr = provider.child.stderr.take().unwrap();
    let stderr = BufReader::new(stderr);

    // test provide output & get all in one ticket from stderr
    let all_in_one = match_provide_stderr(stderr, num_blobs, input)?;

    // create a `get-ticket` cmd & optionally provide out path
    let mut cmd = Command::new(iroh);
    cmd.arg("get-ticket").arg(all_in_one);
    let cmd = if let Some(ref out) = out {
        cmd.arg("--out").arg(out)
    } else {
        &mut cmd
    };

    // test get stderr output
    let get_output = cmd.output()?;
    assert!(get_output.status.success());
    match_get_stderr(get_output.stderr)?;

    // test output
    match out {
        None => {
            let expect_content = std::fs::read(path)?;
            assert_eq!(expect_content, get_output.stdout);
            Ok(())
        }
        Some(out) => compare_files(path, out),
    }
}

// Wrapping the [`Child`] process here allows us to impl the `Drop` trait ensuring the provide
// process is killed when it goes out of scope.
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
    let stderr = std::io::BufReader::new(&stderr[..]);
    assert_matches_line![
        stderr,
        r"Fetching: [\da-z]{59}"; 1,
        r"\[1/3\] Connecting ..."; 1,
        r"\[2/3\] Requesting ..."; 1,
        r"\[3/3\] Downloading collection..."; 1,
        r"\d* file\(s\) with total transfer size [\d.]* ?[KMGT]?i?B"; 1,
        r"Done in \d* seconds?"; 1
    ];
    Ok(())
}

/// Looks for regex matches on stderr output for the provider, returning the "all in one ticket"
/// that can be used to 'get' from another process.
///
/// Errors on the first regex mismatch or if the stderr output has fewer lines than expected
fn match_provide_stderr(
    stderr: BufReader<ChildStderr>,
    num_blobs: usize,
    input: Input,
) -> Result<String> {
    // if we are using `stdin` we don't "read" any files, so the provider does not output any lines
    // about "Reading"
    let reading_line_num = if input == Input::Stdin { 0 } else { 1 };

    let mut remaining_lines = assert_matches_line![
        stderr,
        r"Reading \S*"; reading_line_num,
        r"Collection: [\da-z]{59}"; 1,
        r""; 1,
        r"- \S*: \d* bytes"; num_blobs,
        r""; 1,
        r"PeerID: [_\w\d-]*"; 1,
        r"Auth token: [\w\d]*"; 1
    ];

    let re = r"All-in-one ticket: ([_a-zA-Z\d-]*)";
    let rx = regex::Regex::new(re)?;
    let line = next_line(&mut remaining_lines)?;
    if !rx.is_match(&line) {
        anyhow::bail!(match_err_msg(&line, re))
    }
    let caps = rx
        .captures(&line)
        .context("expected match on 'All-in-one' ticket")?;
    Ok(caps
        .get(1)
        .context("expected 2 matches on 'All-in-one' ticket")?
        .as_str()
        .to_string())
}

fn matches(line: &str, re: &str) -> Result<()> {
    let rx = regex::Regex::new(re)?;
    if rx.is_match(line) {
        Ok(())
    } else {
        anyhow::bail!(match_err_msg(line, re))
    }
}

fn next_line<T: std::io::Read>(l: &mut std::io::Lines<BufReader<T>>) -> Result<String> {
    Ok(l.next().context("Unexpected end of stderr reader")??)
}

fn match_err_msg(line: &str, re: &str) -> String {
    format!("no match found\nexpected match for '{re}'\ngot '{line}'")
}

#[macro_export]
/// Ensures each line of the first expression matches the regex of each following expression. Each
/// regex expression is followed by the number of consecutive lines it should match.
///
/// Returns any left over [`Lines`] that haven't been examined.
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
            $(
            for _ in 0..$a {
                matches(
                    next_line(&mut lines)?.trim(),
                    $z,
                )?;
            }
            )*
            lines
         }
    };
}
