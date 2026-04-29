//! APK smoke test for iroh-dns's Android JNI path.
//!
//! `android-activity` populates `ndk_context` before `android_main`, so
//! iroh-dns's system DNS reader runs through real JNI against
//! `ConnectivityService`.

use std::{
    ffi::CString,
    os::raw::{c_char, c_int},
    time::Duration,
};

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
    log_to_logcat("MARK: android_main start");
    install_panic_hook();
    init_tracing();
    log_to_logcat("MARK: tracing init done");
    let span = info_span!(SCOPE);
    let _enter = span.enter();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    log_to_logcat("MARK: tokio runtime built, entering block_on");
    rt.block_on(run());
    log_to_logcat("MARK: block_on returned");

    // NativeActivity processes' stdout/stderr are not captured by logcat,
    // so write the marker through the Android log API directly.
    log_to_logcat("RESULT=ok");
    std::process::exit(0);
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        log_to_logcat(&format!("PANIC: {info}"));
    }));
}

fn log_to_logcat(msg: &str) {
    let msg = CString::new(msg).unwrap();
    let tag = c"iroh_dns_smoke";
    // ANDROID_LOG_INFO == 4
    unsafe {
        __android_log_write(4, tag.as_ptr(), msg.as_ptr());
    }
}

#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
}

fn init_tracing() {
    INITIALIZED.call_once(|| {
        let writer = MockWriter::new(global_buf());
        let subscriber = get_subscriber(writer, "info,iroh_dns=debug");
        set_global_default(subscriber).expect("set tracing default subscriber");
    });
}

async fn run() {
    log_to_logcat("MARK: run() start");
    let resolver = DnsResolver::new();
    log_to_logcat("MARK: DnsResolver::new returned");

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
    log_to_logcat("MARK: JNI proof asserted");

    let addrs: Vec<_> = resolver
        .lookup_ipv4(HOST, TIMEOUT)
        .await
        .expect("lookup failed")
        .collect();
    log_to_logcat(&format!("MARK: lookup_ipv4 returned {} addrs", addrs.len()));
    assert!(!addrs.is_empty(), "no IPs returned for {HOST}");
    info!(count = addrs.len(), "resolved {HOST} via system DNS");
}
