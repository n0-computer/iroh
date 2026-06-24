//! APK smoke test for iroh-dns's Android JNI path.
//!
//! `android-activity` populates `ndk_context` before `android_main`, so
//! iroh-dns's system DNS reader runs through real JNI against
//! `ConnectivityService`.

use std::time::Duration;

use android_activity::AndroidApp;
use iroh_dns::dns::DnsResolver;
use n0_tracing_test::internal::{INITIALIZED, MockWriter, global_buf, logs_assert};
use tracing::{error, info, info_span};
use tracing_subscriber::{EnvFilter, Layer, Registry, layer::SubscriberExt};

const HOST: &str = "dns.iroh.link";
const TIMEOUT: Duration = Duration::from_secs(8);
const SCOPE: &str = "android_apk_smoke";

#[unsafe(no_mangle)]
fn android_main(app: AndroidApp) {
    init_tracing();
    install_panic_hook();
    info!("android_main started");

    // The test runs on a worker thread so the main thread can keep
    // pumping Android lifecycle events. Without that, the Android
    // cached-app freezer eventually freezes the process before the
    // test completes.
    let test_app = app.clone();
    std::thread::spawn(move || run_test(test_app));

    loop {
        app.poll_events(Some(Duration::from_millis(100)), |_event| {});
    }
}

fn run_test(_app: AndroidApp) {
    let span = info_span!(SCOPE);
    let _enter = span.enter();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(run());

    info!("RESULT=ok");
    std::process::exit(0);
}

fn init_tracing() {
    INITIALIZED.call_once(|| {
        let buf_layer = tracing_subscriber::fmt::layer()
            .with_writer(MockWriter::new(global_buf()))
            .with_level(true)
            .with_ansi(false)
            .with_filter(EnvFilter::new("info,iroh_dns=debug"));
        let android_layer =
            tracing_android::layer("iroh_dns_smoke").expect("tracing-android layer");
        let subscriber = Registry::default().with(buf_layer).with(android_layer);
        tracing::subscriber::set_global_default(subscriber)
            .expect("set tracing default subscriber");
    });
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        error!("PANIC: {info}");
    }));
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
