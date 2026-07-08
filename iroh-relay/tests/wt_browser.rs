//! Browser WebTransport relay client test.
//!
//! Runs in a headless browser via `wasm-bindgen-test` and connects two relay
//! clients to a native relay over the browser's WebTransport, then relays a
//! message from one to the other. The native relay is started out of band (it
//! cannot run inside the wasm test); see `bench/wasm/run.sh`, which spawns the
//! `wasm_relay` example and passes its URL and certificate hash to this test
//! via the `RELAY_URL` and `RELAY_CERT_SHA256` environment variables, baked in
//! at compile time.
#![cfg(all(
    target_family = "wasm",
    target_os = "unknown",
    feature = "h3-transport"
))]

use iroh_base::{EndpointId, RelayUrl, SecretKey};
use iroh_relay::{
    client::{Client, ClientBuilder, Transport},
    protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
};
use n0_future::{SinkExt, StreamExt, time::Duration};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

/// The relay URL, baked in at compile time by the orchestration script.
fn relay_url() -> RelayUrl {
    option_env!("RELAY_URL")
        .expect("RELAY_URL must be set at build time (run via bench/wasm/run.sh)")
        .parse()
        .expect("valid relay URL")
}

/// The SHA-256 hash of the relay's certificate, baked in at compile time.
fn cert_hashes() -> Vec<Vec<u8>> {
    let hex = option_env!("RELAY_CERT_SHA256")
        .expect("RELAY_CERT_SHA256 must be set at build time (run via bench/wasm/run.sh)");
    let bytes = data_encoding::HEXLOWER
        .decode(hex.as_bytes())
        .expect("valid lowercase hex certificate hash");
    vec![bytes]
}

fn setup() {
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));
    let mut config = wasm_tracing::WasmLayerConfig::new();
    config.set_max_level(tracing::Level::DEBUG);
    let _ = wasm_tracing::set_as_global_default_with_config(config);
}

async fn connect(secret_key: SecretKey) -> Client {
    ClientBuilder::new(relay_url(), secret_key)
        .enable_h3(true)
        .server_cert_hashes(cert_hashes())
        .connect()
        .await
        .expect("connect over browser WebTransport")
}

/// Send from `client_a` to `client_b` until a message arrives, retrying because
/// the relay drops messages addressed to a peer it has not registered yet.
async fn try_send_recv(
    client_a: &mut Client,
    client_b: &mut Client,
    b_key: EndpointId,
    msg: Datagrams,
) -> RelayToClientMsg {
    for _ in 0..10 {
        client_a
            .send(ClientToRelayMsg::Datagrams {
                dst_endpoint_id: b_key,
                datagrams: msg.clone(),
            })
            .await
            .expect("send");
        match n0_future::time::timeout(Duration::from_millis(500), client_b.next()).await {
            Ok(Some(res)) => return res.expect("stream item"),
            Ok(None) => panic!("relay stream ended"),
            Err(_) => continue,
        }
    }
    panic!("failed to send and receive message over browser WebTransport");
}

#[wasm_bindgen_test]
async fn browser_wt_relay_roundtrip() {
    setup();

    let a_secret_key = SecretKey::from_bytes(&[1u8; 32]);
    let a_key = a_secret_key.public();
    let mut client_a = connect(a_secret_key).await;
    assert_eq!(
        client_a.transport(),
        Transport::H3,
        "client A must use the WebTransport (H3) transport"
    );

    let b_secret_key = SecretKey::from_bytes(&[2u8; 32]);
    let b_key = b_secret_key.public();
    let mut client_b = connect(b_secret_key).await;
    assert_eq!(
        client_b.transport(),
        Transport::H3,
        "client B must use the WebTransport (H3) transport"
    );

    // A -> B
    let msg = Datagrams::from("hello over browser webtransport, b!");
    let res = try_send_recv(&mut client_a, &mut client_b, b_key, msg.clone()).await;
    let RelayToClientMsg::Datagrams {
        remote_endpoint_id,
        datagrams,
    } = res
    else {
        panic!("unexpected message {res:?}");
    };
    assert_eq!(a_key, remote_endpoint_id);
    assert_eq!(msg, datagrams);

    // B -> A
    let msg = Datagrams::from("howdy over browser webtransport, a!");
    let res = try_send_recv(&mut client_b, &mut client_a, a_key, msg.clone()).await;
    let RelayToClientMsg::Datagrams {
        remote_endpoint_id,
        datagrams,
    } = res
    else {
        panic!("unexpected message {res:?}");
    };
    assert_eq!(b_key, remote_endpoint_id);
    assert_eq!(msg, datagrams);
}
