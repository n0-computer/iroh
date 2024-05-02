use std::str::FromStr;

use anyhow::{bail, Result};
use clap::{Parser, ValueEnum};
use iroh_net::{
    discovery::{
        dns::N0_DNS_NODE_ORIGIN,
        pkarr_publish::{PkarrRelayClient, N0_DNS_PKARR_RELAY},
    },
    dns::node_info::{to_z32, NodeInfo, IROH_TXT_NAME},
    key::SecretKey,
    NodeId,
};
use url::Url;

const LOCALHOST_PKARR: &str = "http://localhost:8080/pkarr";
const EXAMPLE_ORIGIN: &str = "irohdns.example";

#[derive(ValueEnum, Clone, Debug, Default, Copy, strum::Display)]
#[strum(serialize_all = "kebab-case")]
pub enum Env {
    /// Use the pkarr relay run by number0.
    #[default]
    Default,
    /// Use a relay listening at http://localhost:8080
    Dev,
}

/// Publish a record to an irohdns server.
///
/// You have to set the IROH_SECRET environment variable to the node secret for which to publish.
#[derive(Parser, Debug)]
struct Cli {
    /// Environment to publish to.
    #[clap(value_enum, short, long, default_value_t = Env::Default)]
    env: Env,
    /// Pkarr Relay URL. If set, the --env option will be ignored.
    #[clap(long, conflicts_with = "env")]
    pkarr_relay: Option<Url>,
    /// Home relay server to publish for this node
    relay_url: Url,
    /// Create a new node secret if IROH_SECRET is unset. Only for development / debugging.
    #[clap(short, long)]
    create: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Cli::parse();

    let secret_key = match std::env::var("IROH_SECRET") {
        Ok(s) => SecretKey::from_str(&s)?,
        Err(_) if args.create => {
            let s = SecretKey::generate();
            println!("Generated a new node secret. To reuse, set");
            println!("IROH_SECRET={s}");
            s
        }
        Err(_) => {
            bail!("Environtment variable IROH_SECRET is not set. To create a new secret, use the --create option.")
        }
    };

    let node_id = secret_key.public();
    let pkarr_relay = match (args.pkarr_relay, args.env) {
        (Some(pkarr_relay), _) => pkarr_relay,
        (None, Env::Default) => N0_DNS_PKARR_RELAY.parse().expect("valid url"),
        (None, Env::Dev) => LOCALHOST_PKARR.parse().expect("valid url"),
    };

    println!("announce {node_id}:");
    println!("    relay={}", args.relay_url);
    println!();
    println!("publish to {pkarr_relay} ...");

    let pkarr = PkarrRelayClient::new(pkarr_relay);
    let node_info = NodeInfo::new(node_id, Some(args.relay_url), Default::default());
    let signed_packet = node_info.to_pkarr_signed_packet(&secret_key, 30)?;
    pkarr.publish(&signed_packet).await?;

    println!("signed packet published.");
    println!("resolve with:");

    match args.env {
        Env::Default => {
            println!("   cargo run --example resolve -- node {}", node_id);
            println!("   dig {} TXT", fmt_domain(&node_id, N0_DNS_NODE_ORIGIN))
        }
        Env::Dev => {
            println!(
                "    cargo run --example resolve -- --env dev node {}",
                node_id
            );
            println!(
                "    dig @localhost -p 5300 {} TXT",
                fmt_domain(&node_id, EXAMPLE_ORIGIN)
            )
        }
    }
    Ok(())
}

fn fmt_domain(node_id: &NodeId, origin: &str) -> String {
    format!("{}.{}.{}", IROH_TXT_NAME, to_z32(node_id), origin)
}
