//! Very basic example to show how to get the first net-report from the `iroh` endpoint, as well as how to get a stream of subsequent reports.
//!
//! ## Usage
//!
//!     cargo run --example report --features=examples

use anyhow::Result;
use iroh::Endpoint;
use n0_future::StreamExt;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Creating endpoint");
    let endpoint = Endpoint::builder().bind().await?;

    println!("Waiting for first net-report to run...");
    // Wait until the first report is run and set.
    let first_report = endpoint.net_report().initialized().await;

    println!("{:#?}", first_report);

    // The `Watcher` `stream_update_only` method will return any subsequent net-reports (if there have been any changes).
    // Using the more basic `stream` method will first return the *current* report and any subsequent net-reports (if there have been any changes).
    let mut report_stream = endpoint.net_report().stream_updates_only();

    println!("Waiting for any reported network changes...");
    while let Some(report) = report_stream.next().await {
        println!("new report:\n{:#?}", report);
    }
    Ok(())
}
