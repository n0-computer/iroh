#![cfg(any(target_os = "windows", target_os = "macos"))]
use std::env;
// use std::fs::File;
// use std::io::Read;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result};
use tempfile::tempdir;

#[test]
fn cli_transfer_one_file() -> Result<()> {
    let dir = tempdir()?;
    let out = dir.path().join("out");

    let res = CliTestRunner::new()
        .path(PathBuf::from("transfer").join("foo.bin"))
        .out(&out)
        .run()?;

    // run test w/ `UPDATE_EXPECT=1` to update snapshot files
    // let expect = expect_test::expect_file!("./snapshots/cli__transfer_one_file__provide.snap");
    // expect.assert_eq(&res.provider_stderr);

    let expect = expect_test::expect_file!("./snapshots/cli__transfer_one_file__get.snap");
    expect.assert_eq(&res.getter_stderr);
    compare_files(res.input_path.unwrap(), out)?;
    Ok(())
}

#[test]
fn cli_transfer_folder() -> Result<()> {
    let dir = tempdir()?;
    let out = dir.path().join("out");

    let res = CliTestRunner::new()
        .path(PathBuf::from("transfer"))
        .out(&out)
        .run()?;

    // run test w/ `UPDATE_EXPECT=1` to update snapshot files
    let expect = expect_test::expect_file!("./snapshots/cli__transfer_folder__provide.snap");
    expect.assert_eq(&res.provider_stderr);

    let expect = expect_test::expect_file!("./snapshots/cli__transfer_folder__get.snap");
    expect.assert_eq(&res.getter_stderr);
    compare_files(res.input_path.unwrap(), out)
}

#[test]
#[ignore]
fn cli_transfer_from_stdin() -> Result<()> {
    // let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    //     .join("tests")
    //     .join("fixtures");
    // let path = src.join("transfer").join("foo.bin");
    // let f = File::open(path)?;
    // let stdin = Stdio::from(f);

    // let iroh = env!("CARGO_BIN_EXE_iroh");
    // let provide = Command::new(iroh);
    //     .stderr(Stdio::piped())
    //     .stdout(Stdio::piped())
    //     .stdin(stdin)
    //     .arg("provide");

    // // Because of the way we handle providing data from stdin, the hash of the file will change every time.
    // // Since there is no way to neatly extract the collection hash and then pass it to the getter
    // // process, let's just test the provider side in this case

    // let mut stderr = {
    //     let mut provide_process = ProvideProcess {
    //         child: cmd.spawn()?,
    //     };

    //     std::thread::sleep(std::time::Duration::from_secs(1));

    //     provide_process.child.stderr.take().unwrap()
    // };

    // let mut got = String::new();
    // stderr.read_to_string(&mut got)?;

    // // Redact the collection & ticket hashes, since they change on each run.
    // let got = redact_collection_and_ticket(&mut got)?;

    // // run test w/ `UPDATE_EXPECT=1` to update snapshot files
    // let expect = expect_test::expect_file!("./snapshots/cli__transfer_from_stdin__provide.snap");
    // expect.assert_eq(&got);
    Ok(())
}

#[test]
fn cli_transfer_to_stdout() -> Result<()> {
    let res = CliTestRunner::new()
        .path(PathBuf::from("transfer").join("foo.bin"))
        .run()?;

    // run test w/ `UPDATE_EXPECT=1` to update snapshot files
    let expect = expect_test::expect_file!("./snapshots/cli__transfer_to_stdout__provide.snap");
    expect.assert_eq(&res.provider_stderr);

    let expect = expect_test::expect_file!("./snapshots/cli__transfer_to_stdout__get.snap");
    expect.assert_eq(&res.getter_stderr);

    let expect_content = std::fs::read(res.input_path.unwrap())?;
    assert_eq!(expect_content, res.getter_stdout);
    Ok(())
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

fn redact_provide_path(path: &Path, s: String) -> String {
    let path = path.to_string_lossy();
    s.replace(&*path, "[PATH]")
}

fn redact_get_time(s: &mut str) -> Result<String> {
    let re = regex::Regex::new(r"Done in \d\s\w*")?;
    let s = re.replace(s, "Done in [TIME]");
    Ok(s.to_string())
}

// fn redact_collection_and_ticket(s: &mut str) -> Result<String> {
//     let re = regex::Regex::new(r"Collection: \S*")?;
//     let s = re.replace(s, "Collection: [HASH]").to_string();
//     let re = regex::Regex::new(r"All-in-one ticket: \S*")?;
//     Ok(re.replace(&s, "All-in-one ticket: [TICKET]").to_string())
// }

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

struct CliTestRunner {
    path: PathBuf,
    out: Option<PathBuf>,
}

#[derive(Debug)]
struct CliTestResults {
    // expected terminal output from the provider
    provider_stderr: String,
    // expected terminal output from the getter
    getter_stderr: String,
    // only used when we don't specify an `--out` folder, the content of the transfered file gets
    // pushed to the getter's stdout
    getter_stdout: Vec<u8>,
    // the content path given to the provider
    input_path: Option<PathBuf>,
}

impl CliTestResults {
    fn empty() -> Self {
        Self {
            provider_stderr: "".to_string(),
            getter_stdout: vec![],
            getter_stderr: "".to_string(),
            input_path: None,
        }
    }
}

impl CliTestRunner {
    fn new() -> Self {
        Self {
            path: "transfer".parse().unwrap(),
            out: None,
        }
    }

    fn path(mut self, path: impl AsRef<Path>) -> Self {
        self.path = path.as_ref().to_path_buf();
        self
    }

    fn out(mut self, out: impl AsRef<Path>) -> Self {
        self.out = Some(out.as_ref().to_path_buf());
        self
    }

    fn run(self) -> Result<CliTestResults> {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures");

        let path = src.join(&self.path);

        let iroh = env!("CARGO_BIN_EXE_iroh");
        let provider = Command::new(iroh)
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .arg("provide")
            .arg(&path)
            .spawn()?;

        let mut provider = ProvideProcess { child: provider };

        let stderr = provider.child.stderr.take().unwrap();
        let stderr = BufReader::new(stderr);

        let mut res = CliTestResults::empty();

        let mut all_in_one = String::new();
        let all_in_one_re = regex::Regex::new(r"All-in-one ticket: ([_a-zA-Z\d-]*)")?;

        for line in stderr.lines() {
            let line = line.unwrap();
            res.provider_stderr.push_str(&line);
            if all_in_one_re.is_match(&line) {
                let caps = all_in_one_re
                    .captures(&line)
                    .context("expected match on 'All-in-one' ticket")?;
                all_in_one = caps
                    .get(1)
                    .context("expected 2 matches on 'All-in-one' ticket")?
                    .as_str()
                    .to_string();
                break;
            }
        }

        let mut cmd = Command::new(iroh);
        cmd.arg("get-ticket").arg(all_in_one);
        let cmd = if let Some(out) = self.out {
            cmd.arg("--out").arg(out)
        } else {
            &mut cmd
        };

        let get_output = cmd.output()?;

        res.getter_stderr = String::from_utf8_lossy(&get_output.stderr).to_string();
        res.getter_stdout = get_output.stdout;

        // redactions
        res.provider_stderr = redact_provide_path(&path, res.provider_stderr);
        res.getter_stderr = redact_get_time(&mut res.getter_stderr)?;

        res.input_path = Some(path);
        println!("{res:#?}");
        Ok(res)
    }
}
