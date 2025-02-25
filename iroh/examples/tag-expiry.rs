use std::{net::SocketAddr, time::SystemTime};

use chrono::Utc;
use clap::Parser;
use futures_lite::StreamExt;
use iroh::{
    base::hash::Hash,
    blobs::{hashseq::HashSeq, BlobFormat},
    client::Iroh,
};
use iroh_blobs::HashAndFormat;
use tracing_subscriber::{prelude::*, EnvFilter};

// set the RUST_LOG env var to one of {debug,info,warn} to see logging info
pub fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

#[derive(Parser, Debug)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser, Debug)]
enum Command {
    CreateExpiringTag {
        #[clap(long)]
        addr: Option<SocketAddr>,
        #[clap(long)]
        prefix: Option<String>,
        #[clap(long)]
        expiry: String,
        hashes: Vec<Hash>,
    },
    ScanExpiringTags {
        #[clap(long)]
        addr: Option<SocketAddr>,
        #[clap(long)]
        prefix: Option<String>,
        #[clap(long)]
        interval: Option<String>,
    },
}

/// Using an iroh rpc client, create a tag that is marked to expire at `expiry` for all the given hashes.
///
/// The tag name will be `prefix`- followed by the expiry date in iso8601 format (e.g. `expiry-2025-01-01T12:00:00Z`).
///
async fn create_expiring_tag(
    iroh: &Iroh,
    hashes: Vec<Hash>,
    prefix: String,
    expiry: SystemTime,
) -> anyhow::Result<()> {
    let expiry = chrono::DateTime::<chrono::Utc>::from(expiry);
    let expiry = expiry.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let tagname = format!("{}-{}", prefix, expiry);
    let batch = iroh.blobs().batch().await?;
    let tt = if hashes.is_empty() {
        return Ok(());
    } else if hashes.len() == 1 {
        let hash = hashes[0];
        batch.temp_tag(HashAndFormat::raw(hash)).await?
    } else {
        let hs = hashes.into_iter().collect::<HashSeq>();
        batch
            .add_bytes_with_opts(hs.into_inner(), BlobFormat::HashSeq)
            .await?
    };
    batch.persist_to(tt, tagname.as_str().into()).await?;
    println!("Created tag {}", tagname);
    Ok(())
}

async fn delete_expired_tags(iroh: &Iroh, prefix: String) -> anyhow::Result<()> {
    // todo: use prefix filter once the tags api becomes more rich.
    // Scan from `prefix-` to `prefix-<now>` and delete all tags that have expired.
    let mut tags = iroh.tags().list().await?;
    let prefix = format!("{}-", prefix);
    let now = chrono::Utc::now();
    let mut to_delete = Vec::new();
    while let Some(tag) = tags.next().await {
        let tag = tag?.name;
        if let Some(rest) = tag.0.strip_prefix(prefix.as_bytes()) {
            let Ok(expiry) = std::str::from_utf8(rest) else {
                tracing::warn!("Tag {} does have non utf8 expiry", tag);
                continue;
            };
            let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(expiry) else {
                tracing::warn!("Tag {} does have invalid expiry date", tag);
                continue;
            };
            let expiry = expiry.with_timezone(&Utc);
            if expiry < now {
                to_delete.push(tag);
            }
        }
    }
    // todo: use bulk delete once the tags api becomes more rich.
    for tag in to_delete {
        println!("Deleting expired tag {}", tag);
        iroh.tags().delete(tag).await?;
    }
    Ok(())
}

fn parse_duration(input: &str) -> Option<chrono::Duration> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }

    let (num, unit) = input.split_at(input.find(|c: char| !c.is_digit(10)).unwrap_or(input.len()));
    let num: i64 = num.parse().ok()?;
    match unit {
        "s" => Some(chrono::Duration::seconds(num)),
        "m" => Some(chrono::Duration::minutes(num)),
        "h" => Some(chrono::Duration::hours(num)),
        "d" => Some(chrono::Duration::days(num)),
        "" => Some(chrono::Duration::seconds(num)), // Assume seconds if no unit
        _ => None,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logging();
    let args = Args::parse();
    let default_addr = "127.0.0.1:4919".parse().unwrap();
    match args.command {
        Command::CreateExpiringTag {
            addr,
            hashes,
            prefix,
            expiry,
        } => {
            let addr = addr.unwrap_or(default_addr);
            let prefix = prefix.unwrap_or_else(|| "expiring-tag".into());
            let Some(expiry) = parse_duration(&expiry) else {
                anyhow::bail!("Invalid expiry duration");
            };
            let Some(expiry) = SystemTime::now().checked_add(expiry.to_std()?) else {
                anyhow::bail!("Invalid expiry duration");
            };
            let iroh = Iroh::connect_addr(addr).await?;
            create_expiring_tag(&iroh, hashes, prefix, expiry).await?;
        }
        Command::ScanExpiringTags {
            addr,
            prefix,
            interval,
        } => {
            let addr = addr.unwrap_or(default_addr);
            let iroh = Iroh::connect_addr(addr).await?;
            let prefix = prefix.unwrap_or_else(|| "expiring-tag".into());
            if let Some(interval) = interval {
                let Some(interval) = parse_duration(&interval) else {
                    anyhow::bail!("Invalid interval duration");
                };
                let interval = interval.to_std()?;
                loop {
                    println!("Scanning for expired tags");
                    delete_expired_tags(&iroh, prefix.clone()).await?;
                    println!("Waiting {}s for next scan", interval.as_secs());
                    tokio::time::sleep(interval).await;
                }
            } else {
                // just once
                delete_expired_tags(&iroh, prefix).await?;
            }
        }
    }
    Ok(())
}
