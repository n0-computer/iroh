use std::{net::SocketAddr, str::FromStr};

use clap::{Parser, ValueEnum};
use iroh::{
    discovery::{
        dns::{N0_DNS_NODE_ORIGIN_PROD, N0_DNS_NODE_ORIGIN_STAGING},
        pkarr::{PkarrRelayClient, N0_DNS_PKARR_RELAY_PROD, N0_DNS_PKARR_RELAY_STAGING},
        UserData,
    },
    node_info::{NodeIdExt, NodeInfo, IROH_TXT_NAME},
    NodeId, SecretKey,
};
use n0_snafu::{Result, ResultExt};
use url::Url;

const DEV_PKARR_RELAY_URL: &str = "http://localhost:8080/pkarr";
const DEV_DNS_ORIGIN_DOMAIN: &str = "irohdns.example";
const EXAMPLE_RELAY_URL: &str = "https://relay.iroh.example";

#[derive(ValueEnum, Clone, Debug, Default, Copy, strum::Display)]
#[strum(serialize_all = "kebab-case")]
pub enum Env {
    /// Use the staging pkarr relay run by number0.
    #[default]
    Staging,
    /// Use the production pkarr relay run by number0.
    Prod,
    /// Use a relay listening at http://localhost:8080
    Dev,
}

/// Publish a record to an irohdns server.
///
/// You have to set the IROH_SECRET environment variable to the node secret for which to publish.
#[derive(Parser, Debug)]
struct Cli {
    /// Environment to publish to.
    #[clap(value_enum, short, long, default_value_t = Env::Staging)]
    env: Env,
    /// Pkarr Relay URL. If set, the --env option will be ignored.
    #[clap(long, conflicts_with = "env")]
    pkarr_relay_url: Option<Url>,
    /// Home relay server URL to publish.
    #[clap(short, long, conflicts_with = "no_relay_url")]
    relay_url: Option<Url>,
    /// Do not publish a home relay server URL.
    #[clap(long)]
    no_relay_url: bool,
    /// Direct addresses to publish.
    #[clap(short, long)]
    addr: Vec<SocketAddr>,
    /// User data to publish for this node
    #[clap(short, long)]
    user_data: Option<UserData>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Cli::parse();

    let secret_key = match std::env::var("IROH_SECRET") {
        Ok(s) => SecretKey::from_str(&s)
            .context("failed to parse IROH_SECRET environment variable as iroh secret key")?,
        Err(_) => {
            let s = SecretKey::generate(rand::rngs::OsRng);
            println!("Generated a new node secret. To reuse, set");
            println!(
                "\tIROH_SECRET={}",
                data_encoding::HEXLOWER.encode(&s.to_bytes())
            );
            s
        }
    };

    let node_id = secret_key.public();
    let pkarr_relay_url = match (args.pkarr_relay_url, args.env) {
        (Some(url), _) => url,
        (None, Env::Staging) => N0_DNS_PKARR_RELAY_STAGING.parse().expect("valid url"),
        (None, Env::Prod) => N0_DNS_PKARR_RELAY_PROD.parse().expect("valid url"),
        (None, Env::Dev) => DEV_PKARR_RELAY_URL.parse().expect("valid url"),
    };

    let relay_url = if let Some(relay_url) = args.relay_url {
        Some(relay_url)
    } else if !args.no_relay_url {
        Some(EXAMPLE_RELAY_URL.parse().expect("valid url"))
    } else {
        None
    };

    println!("announce node {node_id}:");
    if let Some(relay_url) = &relay_url {
        println!("    relay={relay_url}");
    }
    for addr in &args.addr {
        println!("    addr={addr}");
    }
    if let Some(user_data) = &args.user_data {
        println!("    user-data={user_data}");
    }
    println!();
    println!("publish to {pkarr_relay_url} ...");

    let pkarr = PkarrRelayClient::new(pkarr_relay_url);
    let node_info = NodeInfo::new(node_id)
        .with_relay_url(relay_url.map(Into::into))
        .with_direct_addresses(args.addr.into_iter().collect())
        .with_user_data(args.user_data);
    let signed_packet = node_info.to_pkarr_signed_packet(&secret_key, 30)?;
    tracing::debug!("signed packet: {signed_packet:?}");
    pkarr.publish(&signed_packet).await?;

    println!("signed packet published.");
    println!("resolve with:");

    match args.env {
        Env::Staging => {
            println!(
                "   cargo run --example resolve -- --env staging node {}",
                node_id
            );
            println!(
                "   dig {} TXT",
                fmt_domain(&node_id, N0_DNS_NODE_ORIGIN_STAGING)
            )
        }
        Env::Prod => {
            println!(
                "   cargo run --example resolve -- --env prod node {}",
                node_id
            );
            println!(
                "   dig {} TXT",
                fmt_domain(&node_id, N0_DNS_NODE_ORIGIN_PROD)
            )
        }
        Env::Dev => {
            println!(
                "    cargo run --example resolve -- --env dev node {}",
                node_id
            );
            println!(
                "    dig @localhost -p 5300 {} TXT",
                fmt_domain(&node_id, DEV_DNS_ORIGIN_DOMAIN)
            )
        }
    }
    Ok(())
}

fn fmt_domain(node_id: &NodeId, origin: &str) -> String {
    format!("{}.{}.{}", IROH_TXT_NAME, node_id.to_z32(), origin)
}
