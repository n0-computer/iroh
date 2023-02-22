#![cfg(any(target_os = "windows", target_os = "macos"))]
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};

use anyhow::{Context, Result};
use tempfile::tempdir;

#[test]
fn cli_provide_one_file() -> Result<()> {
    let dir = tempdir()?;
    let out = dir.path().join("out");

    test_provide_get_loop(
        &PathBuf::from("transfer").join("foo.bin"),
        Some(&out),
        false,
    )
}

#[test]
fn cli_provide_folder() -> Result<()> {
    let dir = tempdir()?;
    let out = dir.path().join("out");

    test_provide_get_loop(&PathBuf::from("transfer"), Some(&out), false)
}

#[test]
fn cli_provide_from_stdin_to_stdout() -> Result<()> {
    test_provide_get_loop(&PathBuf::from("transfer").join("foo.bin"), None, true)
}

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

// Test the provide and get loop for success, stderr output, and file contents.
//
// Can optionally save the output to the `out` path parameter.
//
// Can optionally pipe content to stdin.
//
// Runs the provider as a child process that stays alive until the getter has completed.
fn test_provide_get_loop(path: &Path, out: Option<&Path>, use_stdin: bool) -> Result<()> {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");

    let path = src.join(path);

    let iroh = env!("CARGO_BIN_EXE_iroh");

    // spawn a provider & optionally provide from stdin
    let provider = if use_stdin {
        let f = File::open(&path)?;
        let stdin = Stdio::from(f);
        Command::new(iroh)
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .stdin(stdin)
            .arg("provide")
            .arg("--addr")
            .arg("127.0.0.1:0")
            .spawn()?
    } else {
        Command::new(iroh)
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .arg("provide")
            .arg(&path)
            .arg("--addr")
            .arg("127.0.0.1:0")
            .spawn()?
    };

    // wrap in `ProvideProcess` to ensure the spawned process is killed on drop
    let mut provider = ProvideProcess { child: provider };
    let stderr = provider.child.stderr.take().unwrap();
    let stderr = BufReader::new(stderr);

    // test provide output & get all in one ticket from stderr
    let all_in_one = match_provide_stderr(stderr, use_stdin)?;

    // create a `get-ticket` cmd & optionally provide out path
    let mut cmd = Command::new(iroh);
    cmd.arg("get-ticket").arg(all_in_one);
    let cmd = if let Some(out) = out {
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

// looks for regex matches on stderr output for the getter.
//
// errors on the first regex mis-match or if the stderr output has fewer lines than expected
fn match_get_stderr(stderr: Vec<u8>) -> Result<()> {
    let stderr = std::str::from_utf8(&stderr[..])?;
    let mut lines = stderr.lines();
    let res = vec![
        r"Fetching: [\da-z]{59}",
        r"\[1/3\] Connecting ...",
        r"\[2/3\] Requesting ...",
        r"\[3/3\] Downloading collection...",
        r"\d* file\(s\) with total transfer size [\d.]* ?[KMGT]?i?B",
        r"Done in \d* seconds?",
    ];

    for re in res {
        matches(
            lines
                .next()
                .context("Unexpected end of 'get' output")?
                .trim(),
            re,
        )?;
    }
    Ok(())
}

/// looks for regex matches on stderr output for the provider.
///
/// returns the "all in one ticket" that can be used to 'get' from another process.
///
/// errors on the first regex mismatch or if the stderr output has fewer lines than expected
fn match_provide_stderr(stderr: BufReader<ChildStderr>, use_stdin: bool) -> Result<String> {
    let mut lines = stderr.lines();

    let mut res = vec![
        r"Reading \S*",
        r"Collection: [\da-z]{59}",
        r"",
        r"PeerID: [_\w\d-]*",
        r"Auth token: [\w\d]*",
    ];

    // when piping from stdin, we don't open and read any files
    if use_stdin {
        res = res[1..].to_vec();
    }

    for re in res {
        matches(next_line(&mut lines)?.trim(), re)?;
    }

    // get all-in-one ticket
    let re = r"All-in-one ticket: ([_a-zA-Z\d-]*)";
    let rx = regex::Regex::new(re)?;
    let line = next_line(&mut lines)?;
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

fn matches(line: &str, re: &str) -> Result<bool> {
    let rx = regex::Regex::new(re)?;
    if rx.is_match(line) {
        Ok(true)
    } else {
        anyhow::bail!(match_err_msg(line, re))
    }
}

fn next_line(l: &mut std::io::Lines<BufReader<ChildStderr>>) -> Result<String> {
    let line = l.next().context("Unexpected end of stderr reader")??;
    Ok(line)
}

fn match_err_msg(line: &str, re: &str) -> String {
    format!("no match found\nexpected match for '{re}'\ngot '{line}'")
}
