//! Smoke test for [`iroh_dns::dns::DnsResolver`].
//!
//! Builds the default resolver and looks up `dns.iroh.link`. Exits 0
//! on success, 1 on failure with diagnostic output. Intended as a
//! cross-platform sanity check that runs on Android emulators in CI
//! to catch regressions like the hickory-0.26 panic on uninitialized
//! `ndk_context`.
//!
//! Run locally:
//!
//! ```ignore
//! cargo run --example resolve_smoke --features tls-ring
//! ```
//!
//! On an Android device or emulator (no JNI context required):
//!
//! ```ignore
//! ANDROID_NDK_HOME=$ANDROID_NDK cargo ndk --target x86_64-linux-android \
//!     build --example resolve_smoke --release --features tls-ring
//! adb push target/x86_64-linux-android/release/examples/resolve_smoke \
//!     /data/local/tmp/iroh-dns-smoke
//! adb shell /data/local/tmp/iroh-dns-smoke
//! ```

use std::time::Duration;

use iroh_dns::dns::DnsResolver;

const TIMEOUT: Duration = Duration::from_secs(8);
const HOST: &str = "dns.iroh.link";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let _ = tracing_subscriber::fmt::try_init();

    println!("== building DnsResolver");
    let resolver = match std::panic::catch_unwind(DnsResolver::new) {
        Ok(r) => {
            println!("OK: built without panic");
            r
        }
        Err(payload) => {
            let msg = panic_message(&payload);
            eprintln!("FAIL: DnsResolver::new panicked: {msg}");
            std::process::exit(1);
        }
    };

    println!("== resolving {HOST}");
    let mut any_success = false;
    match resolver.lookup_ipv4(HOST, TIMEOUT).await {
        Ok(addrs) => {
            let v: Vec<_> = addrs.collect();
            if v.is_empty() {
                eprintln!("FAIL: IPv4 lookup returned no addresses");
            } else {
                println!("OK: IPv4 = {v:?}");
                any_success = true;
            }
        }
        Err(err) => eprintln!("WARN: IPv4 lookup failed: {err:#}"),
    }
    match resolver.lookup_ipv6(HOST, TIMEOUT).await {
        Ok(addrs) => {
            let v: Vec<_> = addrs.collect();
            if v.is_empty() {
                eprintln!("WARN: IPv6 lookup returned no addresses");
            } else {
                println!("OK: IPv6 = {v:?}");
                any_success = true;
            }
        }
        Err(err) => eprintln!("WARN: IPv6 lookup failed: {err:#}"),
    }

    if any_success {
        println!("== smoke test passed");
    } else {
        eprintln!("FAIL: no successful lookups");
        std::process::exit(1);
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&'static str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| String::from("<non-string panic payload>"))
}
