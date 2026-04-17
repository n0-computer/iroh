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

use std::{net::SocketAddr, time::Duration};

use iroh::{
    Endpoint, RelayUrl, Watcher,
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
    let report = ep.net_report().get();
    let observed_v4: Vec<(RelayUrl, SocketAddr)> = report
        .as_ref()
        .map(|r| {
            r.qad_v4_observations
                .iter()
                .map(|o| (o.relay.clone(), o.observed))
                .collect()
        })
        .unwrap_or_default();
    let observed_v6: Vec<(RelayUrl, SocketAddr)> = report
        .as_ref()
        .map(|r| {
            r.qad_v6_observations
                .iter()
                .map(|o| (o.relay.clone(), o.observed))
                .collect()
        })
        .unwrap_or_default();

    print_family("IPv4", pattern_v4.as_ref(), &observed_v4, &config);
    print_family("IPv6", pattern_v6.as_ref(), &observed_v6, &config);

    ep.close().await;
    Ok(())
}

async fn wait_classified(
    mut watcher: impl Watcher<Value = Option<NatPattern>>,
) -> Option<NatPattern> {
    if let Some(p) = watcher.get() {
        return Some(p);
    }
    timeout(CLASSIFY_TIMEOUT, async {
        loop {
            match watcher.updated().await {
                Ok(Some(p)) => return Some(p),
                Ok(None) => continue,
                Err(_disconnected) => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

fn print_family(
    name: &str,
    pattern: Option<&NatPattern>,
    observed: &[(RelayUrl, SocketAddr)],
    config: &NatPatternConfig,
) {
    println!("── {name} ──");
    println!("  QAD probes      : {} responded", observed.len());
    for (relay, addr) in observed {
        let host = relay.host_str().unwrap_or("<relay>");
        println!("    via {host:<40} → {addr}");
    }
    let distinct_ips: std::collections::BTreeSet<_> =
        observed.iter().map(|(_, a)| a.ip()).collect();
    if distinct_ips.len() > 1 {
        println!(
            "  distinct IPs    : {} — external IP varies across QAD probes",
            distinct_ips.len()
        );
    }
    let Some(pattern) = pattern else {
        let reason = if observed.is_empty() {
            "no QAD responses — address family unreachable on this network"
        } else {
            "net-report did not complete in time"
        };
        println!("  classification  : unavailable ({reason})");
        println!();
        return;
    };
    println!("  classification  : {pattern}");
    print_details(pattern);
    print_interpretation(pattern, observed.len());

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

fn print_interpretation(pattern: &NatPattern, observation_count: usize) {
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
        NatPattern::Unknown if observation_count < 2 => {
            "Fewer than 2 QAD probes responded — can't classify. Typical \
             on flaky or cellular networks when some relays are \
             unreachable; retry, or try a different network."
        }
        NatPattern::Unknown => {
            "Observations disagreed but fewer than 3 responded, so the \
             varying pattern (incremental, port-block, random) can't be \
             distinguished. Retry to gather more samples."
        }
    };
    println!("  note            : {text}");
}
