//! Classify the NAT in front of this host.
//!
//! Binds an iroh endpoint, waits for net-report to probe the configured
//! relays via QAD, and prints the classified [`NatPattern`] for IPv4 and
//! IPv6 along with the candidate set iroh would advertise to peers.
//!
//! Run with:
//!
//! ```text
//! cargo run --example nat_classify
//! ```

use std::time::Duration;

use iroh::{
    Endpoint, Watcher,
    endpoint::presets,
    nat_pattern::{NatPattern, NatPatternConfig},
};
use n0_error::Result;
use n0_future::time::timeout;

const CLASSIFY_TIMEOUT: Duration = Duration::from_secs(20);

#[tokio::main]
async fn main() -> Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "iroh=warn".into()),
        )
        .init();

    let config = NatPatternConfig::default();
    println!("Binding endpoint...");
    let ep = Endpoint::builder(presets::N0)
        .nat_pattern(config.clone())
        .bind()
        .await?;
    println!("  endpoint id     : {}", ep.id().fmt_short());
    println!("  bound sockets   : {:?}", ep.bound_sockets());
    println!();

    println!(
        "Waiting for QAD classification (up to {}s)...",
        CLASSIFY_TIMEOUT.as_secs()
    );
    let (pattern_v4, pattern_v6) = tokio::join!(
        wait_classified(ep.nat_pattern_v4()),
        wait_classified(ep.nat_pattern_v6()),
    );

    print_family("IPv4", pattern_v4.as_ref(), &config);
    print_family("IPv6", pattern_v6.as_ref(), &config);

    ep.close().await;
    Ok(())
}

async fn wait_classified(
    mut watcher: impl Watcher<Value = Option<NatPattern>>,
) -> Option<NatPattern> {
    if let Some(p) = watcher.get()
        && !matches!(p, NatPattern::Unknown)
    {
        return Some(p);
    }
    timeout(CLASSIFY_TIMEOUT, async {
        loop {
            match watcher.updated().await {
                Ok(Some(p)) if !matches!(p, NatPattern::Unknown) => return Some(p),
                Ok(_) => continue,
                Err(_disconnected) => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

fn print_family(name: &str, pattern: Option<&NatPattern>, config: &NatPatternConfig) {
    println!("── {name} ──");
    let Some(pattern) = pattern else {
        println!("  classification  : unavailable (no QAD response)");
        println!();
        return;
    };
    println!("  classification  : {pattern}");
    print_details(pattern);
    print_interpretation(pattern);

    let candidates = pattern.expand_candidates(config);
    if !candidates.is_empty() {
        println!(
            "  expanded ports  : {} of {} cap",
            candidates.len(),
            config.pba_candidate_cap
        );
        let sample: Vec<String> = candidates.iter().take(8).map(|p| p.to_string()).collect();
        let tail = if candidates.len() > 8 {
            format!(", ... ({} more)", candidates.len() - 8)
        } else {
            String::new()
        };
        println!("                    [{}{}]", sample.join(", "), tail);
    }
    println!();
}

fn print_details(pattern: &NatPattern) {
    match pattern {
        NatPattern::Preservation {
            bound_port,
            external_port,
        } => {
            println!("  bound port      : {bound_port}");
            println!("  external port   : {external_port}");
        }
        NatPattern::Incremental {
            last_port,
            delta,
            parity_preserving,
        } => {
            println!("  last seen port  : {last_port}");
            println!("  observed delta  : {delta}");
            println!("  parity preserved: {parity_preserving}");
        }
        NatPattern::PortBlock {
            block_base,
            block_size,
            first_observed,
        } => {
            println!("  block base      : {block_base}");
            println!("  block size      : {block_size}");
            println!("  first observed  : {first_observed}");
        }
        NatPattern::Random | NatPattern::Unknown => {}
    }
}

fn print_interpretation(pattern: &NatPattern) {
    let text = match pattern {
        NatPattern::Preservation {
            bound_port,
            external_port,
        } if bound_port == external_port => {
            "Port-preserving NAT or no NAT. Hole punching works well: peers \
             target the bound port directly."
        }
        NatPattern::Preservation { .. } => {
            "Endpoint-independent mapping that shifts the port. Still a \
             single stable external port — hole punching works like the \
             preserving case."
        }
        NatPattern::Incremental { .. } => {
            "Incremental symmetric NAT. The peer can predict the next \
             allocation; candidate window is advertised for NAT traversal."
        }
        NatPattern::PortBlock { .. } => {
            "Port-block allocation (CGN vendor pattern). Subscriber has a \
             fixed port block within which allocations are random. Peers \
             probe the block to find a working port."
        }
        NatPattern::Random => {
            "Fully random symmetric NAT. No prediction possible — hole \
             punching will fall back to the relay."
        }
        NatPattern::Unknown => "Not enough observations to classify.",
    };
    println!("  note            : {text}");
}
