//! APK smoke test for iroh-dns's Android JNI path.
//!
//! `android-activity` populates `ndk_context` before `android_main`, so
//! iroh-dns's system DNS reader runs through real JNI against
//! `ConnectivityService`.

use std::time::Duration;

use android_activity::AndroidApp;
use iroh_dns::dns::DnsResolver;
use n0_tracing_test::internal::{
    INITIALIZED, MockWriter, get_subscriber, global_buf, logs_assert,
};
use tracing::{dispatcher::set_global_default, info, info_span};

const HOST: &str = "dns.iroh.link";
const TIMEOUT: Duration = Duration::from_secs(8);
const SCOPE: &str = "android_apk_smoke";

#[unsafe(no_mangle)]
fn android_main(_app: AndroidApp) {
    init_tracing();
    let span = info_span!(SCOPE);
    let _enter = span.enter();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(run());

    println!("RESULT=ok");
    eprintln!("RESULT=ok");
    std::process::exit(0);
}

fn init_tracing() {
    INITIALIZED.call_once(|| {
        let writer = MockWriter::new(global_buf());
        let subscriber = get_subscriber(writer, "info,iroh_dns=debug");
        set_global_default(subscriber).expect("set tracing default subscriber");
    });
}

async fn run() {
    let resolver = DnsResolver::new();

    logs_assert(SCOPE, |lines| {
        if lines
            .iter()
            .any(|l| l.contains("read system DNS via Android JNI"))
        {
            Ok(())
        } else {
            Err(format!(
                "missing JNI debug line in {} captured log lines",
                lines.len()
            ))
        }
    })
    .expect("JNI proof failed");

    let addrs: Vec<_> = resolver
        .lookup_ipv4(HOST, TIMEOUT)
        .await
        .expect("lookup failed")
        .collect();
    assert!(!addrs.is_empty(), "no IPs returned for {HOST}");
    info!(count = addrs.len(), "resolved {HOST} via system DNS");
}
