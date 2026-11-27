//! Regression test for <https://github.com/n0-computer/iroh/issues/4636>.
//!
//! When the relay runs out of file descriptors, `accept()` fails with `EMFILE`. The accept
//! loops used to log the error and retry immediately, spinning the CPU and flooding the log.
//!
//! The open-file limit is per process, so this runs the real `iroh-relay` binary with a low
//! limit instead of lowering the limit of the test process.

#![cfg(all(feature = "server", unix))]

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
    thread::{self, sleep},
    time::Duration,
};

struct Relay(Child);

impl Drop for Relay {
    fn drop(&mut self) {
        self.0.kill().ok();
    }
}

/// Whether the relay answers `/healthz`.
fn healthy(addr: SocketAddr) -> bool {
    let timeout = Duration::from_secs(1);
    let mut response = String::new();
    let _ = TcpStream::connect_timeout(&addr, timeout).and_then(|mut stream| {
        stream.set_read_timeout(Some(timeout))?;
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
        stream.read_to_string(&mut response)
    });
    response.starts_with("HTTP/1.1 200")
}

#[test]
fn accept_errors_back_off() {
    // Port 0 lets the OS pick a free port, which the relay logs.
    let config = concat!(env!("CARGO_TARGET_TMPDIR"), "/accept-emfile.toml");
    std::fs::write(
        config,
        "enable_metrics = false\nhttp_bind_addr = \"127.0.0.1:0\"\n",
    )
    .unwrap();

    // `ulimit` lowers the limit for the relay only, which `exec` then replaces the shell with.
    let mut relay = Relay(
        Command::new("sh")
            .args(["-c", "ulimit -n 64 && exec \"$0\" \"$@\""])
            .arg(env!("CARGO_BIN_EXE_iroh-relay"))
            .args(["--dev", "--config-path", config])
            .env("RUST_LOG", "iroh_relay::server::http_server=info")
            .env("NO_COLOR", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );

    let stderr = relay.0.stderr.take().unwrap();
    let mut lines = BufReader::new(stderr).lines().map_while(Result::ok);
    let addr = lines
        .find_map(|line| {
            line.split_once("serving on ")?
                .1
                .trim()
                .parse::<SocketAddr>()
                .ok()
        })
        .expect("relay did not report its address");
    let errors = Arc::new(AtomicUsize::new(0));
    thread::spawn({
        let errors = errors.clone();
        move || {
            for line in lines {
                if line.contains("failed to accept connection") {
                    errors.fetch_add(1, SeqCst);
                }
            }
        }
    });

    // More silent connections than the relay has file descriptors for.
    let held: Vec<_> = (0..150)
        .map(|_| TcpStream::connect(addr).unwrap())
        .collect();

    // Give the relay up to 5s to run out of file descriptors.
    for _ in 0..250 {
        if errors.load(SeqCst) > 0 {
            break;
        }
        sleep(Duration::from_millis(20));
    }

    // A one second backoff gives one or two errors in this time. Without a backoff there are
    // hundreds of thousands.
    sleep(Duration::from_secs(1));
    let count = errors.load(SeqCst);
    assert!(
        (1..10).contains(&count),
        "expected a few accept errors from backing off, got {count} in 1s"
    );

    // Closing the connections frees file descriptors, so the relay must accept again.
    drop(held);
    for _ in 0..50 {
        if healthy(addr) {
            return;
        }
        sleep(Duration::from_millis(100));
    }
    panic!("relay did not recover");
}
