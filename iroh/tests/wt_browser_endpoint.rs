//! Browser WebTransport iroh `Endpoint` test.
//!
//! Runs in a headless browser via `wasm-bindgen-test`. A browser iroh
//! [`Endpoint`] connects to a native echo peer *through a local relay over
//! WebTransport* and verifies an echo round-trip. The native relay and peer run
//! out of band (they cannot run inside the wasm test); see
//! `bench/wasm/run_iroh.sh`, which spawns the `wt_browser_peer` example and
//! passes its relay URL, certificate hash, and peer id to this test via the
//! `RELAY_URL`, `RELAY_CERT_SHA256`, and `PROVIDER_ID` environment variables,
//! baked in at compile time.
#![cfg(all(
    target_family = "wasm",
    target_os = "unknown",
    feature = "h3-transport"
))]

use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayMap, RelayMode, RelayUrl,
    endpoint::presets,
};
use n0_future::time::{Duration, timeout};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

const ECHO_ALPN: &[u8] = b"echo";

fn env(name: &str, value: Option<&'static str>) -> &'static str {
    value.unwrap_or_else(|| {
        panic!("{name} must be set at build time (run via bench/wasm/run_iroh.sh)")
    })
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn setup() {
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));
    let mut config = wasm_tracing::WasmLayerConfig::new();
    config.set_max_level(tracing::Level::DEBUG);
    let _ = wasm_tracing::set_as_global_default_with_config(config);
}

#[wasm_bindgen_test]
async fn browser_endpoint_echo_through_relay() {
    setup();

    let relay_url: RelayUrl = env("RELAY_URL", option_env!("RELAY_URL"))
        .parse()
        .expect("valid relay URL");
    let cert_hash = hex_decode(env("RELAY_CERT_SHA256", option_env!("RELAY_CERT_SHA256")));
    let provider_id: EndpointId = env("PROVIDER_ID", option_env!("PROVIDER_ID"))
        .parse()
        .expect("valid endpoint id");

    // Point the browser endpoint at the local relay over WebTransport, trusting
    // its self-signed certificate by hash.
    let mut h3 = iroh::H3Opts::default();
    h3.server_cert_hashes = Some(vec![cert_hash]);
    let relay_config = RelayConfig::new(relay_url.clone(), None).with_h3(h3);
    tracing::info!(
        h3 = relay_config.h3.is_some(),
        %relay_url,
        "browser relay config"
    );
    let relay_map: RelayMap = relay_config.into();

    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay_map))
        .bind()
        .await
        .expect("bind browser endpoint");
    tracing::info!(id = %endpoint.id().fmt_short(), "browser endpoint bound, going online");

    // Wait until connected to the relay (over WebTransport).
    timeout(Duration::from_secs(20), endpoint.online())
        .await
        .expect("browser endpoint failed to come online via the relay");

    let addr = EndpointAddr::new(provider_id).with_relay_url(relay_url);
    tracing::info!(peer = %provider_id.fmt_short(), "connecting through relay");

    let conn = timeout(Duration::from_secs(20), endpoint.connect(addr, ECHO_ALPN))
        .await
        .expect("connect timed out")
        .expect("connect to peer through relay");

    let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
    let payload = b"Hello over browser WebTransport!";
    send.write_all(payload).await.expect("write");
    send.finish().expect("finish");

    let response = recv.read_to_end(10_000).await.expect("read echo");
    assert_eq!(&response, payload, "echoed bytes must match");

    conn.close(0u32.into(), b"done");
    endpoint.close().await;
}
