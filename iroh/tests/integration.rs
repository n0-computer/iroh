//! Basic integration tests for iroh that can be run both in browsers & natively.
//!
//! At the moment, these tests unfortunately interact with deployed services, specifically
//! the "real" DNS server infrastructure and "real" relays.
//!
//! The main reason is that running rust code natively and simultaneously in node.js via
//! wasm-bindgen-test is not trivial. We want to avoid a situation where you need to
//! remember to run *another* binary simultaneously to running `cargo test --test integration`.
//!
//! In the past we've hit relay rate-limits from all the tests in our CI, but I expect
//! we won't hit these with only this integration test.
use iroh::{
    discovery::{pkarr::PkarrResolver, Discovery},
    Endpoint,
};
use n0_future::{
    task,
    time::{self, Duration},
    StreamExt,
};
use testresult::TestResult;
#[cfg(not(wasm_browser))]
use tokio::test;
use tracing::{info_span, Instrument};
#[cfg(wasm_browser)]
use wasm_bindgen_test::wasm_bindgen_test as test;

// Enable this if you want to run these tests in the browser.
// Unfortunately it's either-or: Enable this and you can run in the browser, disable to run in nodejs.
// #[cfg(wasm_browser)]
// wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const ECHO_ALPN: &[u8] = b"echo";

#[test]
async fn simple_node_id_based_connection_transfer() -> TestResult {
    setup_logging();

    let relay_map = iroh::defaults::prod::default_relay_map();

    let client = Endpoint::builder()
        .relay_mode(iroh::RelayMode::Custom(relay_map.clone()))
        .discovery_n0()
        .bind()
        .await?;
    let server = Endpoint::builder()
        .relay_mode(iroh::RelayMode::Custom(relay_map))
        .discovery_n0()
        .alpns(vec![ECHO_ALPN.to_vec()])
        .bind()
        .await?;

    // Make the server respond to requests with an echo
    task::spawn({
        let server = server.clone();
        async move {
            while let Some(incoming) = server.accept().await {
                let conn = incoming.await?;
                let node_id = conn.remote_node_id()?;
                tracing::info!(node_id = %node_id.fmt_short(), "Accepted connection");

                let (mut send, mut recv) = conn.accept_bi().await?;
                let mut bytes_sent = 0;
                while let Some(chunk) = recv.read_chunk(10_000, true).await? {
                    bytes_sent += chunk.bytes.len();
                    send.write_chunk(chunk.bytes).await?;
                }
                send.finish()?;
                tracing::info!("Copied over {bytes_sent} byte(s)");

                let code = conn.closed().await;
                tracing::info!("Closed with code: {code:?}");
            }

            TestResult::Ok(())
        }
        .instrument(info_span!("server"))
    });

    // Wait for pkarr records to be published
    time::timeout(Duration::from_secs(10), {
        let client = client.clone();
        let node_id = server.node_id();
        async move {
            let resolver = PkarrResolver::n0_dns();
            loop {
                // Very rudimentary non-backoff algorithm
                time::sleep(Duration::from_secs(1)).await;

                let Some(mut stream) = resolver.resolve(client.clone(), node_id) else {
                    continue;
                };
                let Ok(Some(item)) = stream.try_next().await else {
                    continue;
                };
                if item.relay_url().is_some() {
                    break;
                }
            }
        }
    })
    .await?;

    tracing::info!(to = %server.node_id().fmt_short(), "Opening a connection");
    let conn = client.connect(server.node_id(), ECHO_ALPN).await?;
    tracing::info!("Connection opened");

    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"Hello, World!").await?;
    send.finish()?;
    tracing::info!("Sent request");

    let response = recv.read_to_end(10_000).await?;
    tracing::info!(len = response.len(), "Received response");
    assert_eq!(&response, b"Hello, World!");

    tracing::info!("Closing connection");
    conn.close(1u32.into(), b"thank you, bye");

    client.close().await;
    server.close().await;

    Ok(())
}

#[cfg(wasm_browser)]
fn setup_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::level_filters::LevelFilter::DEBUG)
        .with_writer(
            // To avoide trace events in the browser from showing their JS backtrace
            tracing_subscriber_wasm::MakeConsoleWriter::default()
                .map_trace_level_to(tracing::Level::DEBUG),
        )
        // If we don't do this in the browser, we get a runtime error.
        .without_time()
        .with_ansi(false)
        .init();
}

#[cfg(not(wasm_browser))]
fn setup_logging() {
    tracing_subscriber::fmt().init();
}
