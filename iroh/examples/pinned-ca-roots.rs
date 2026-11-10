//! Restricts the CA roots an endpoint trusts for relays, probes and address lookup.
//!
//! By default iroh trusts the full Mozilla root store for its HTTPS and TLS connections
//! to iroh infrastructure. Connections between endpoints don't depend on CAs at all, but
//! a compromised CA lets an on-path attacker intercept e.g. the relay connection.
//!
//! All n0 infrastructure uses Let's Encrypt, so an endpoint using [`presets::N0`] can trust
//! just the Let's Encrypt roots. The downside is that you can't talk to relays or address
//! lookup services that use a different CA.
//!
//! Pass one or more relay URLs to try relays other than the n0 defaults. A relay whose
//! certificate doesn't chain up to a Let's Encrypt root fails with `UnknownIssuer` in the log.

use std::time::Duration;

use clap::Parser;
use iroh::{Endpoint, RelayMap, RelayMode, RelayUrl, endpoint::presets, tls::CaTlsConfig};
use n0_error::{Result, StdResultExt};
use rustls::pki_types::{CertificateDer, pem::PemObject};

/// The current and next generation Let's Encrypt roots, from <https://letsencrypt.org/certificates/>.
const LETS_ENCRYPT_ROOTS: &[u8] = include_bytes!("lets-encrypt-roots.pem");

#[derive(clap::Parser, Debug)]
struct Args {
    /// Pass one or more relay URLs.
    ///
    /// If unset will use the public default relays.
    relays: Vec<RelayUrl>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let roots = CertificateDer::pem_slice_iter(LETS_ENCRYPT_ROOTS)
        .collect::<Result<Vec<_>, _>>()
        .anyerr()?;

    let mut builder =
        Endpoint::builder(presets::N0).ca_tls_config(CaTlsConfig::custom_roots(roots));
    if !args.relays.is_empty() {
        builder = builder.relay_mode(RelayMode::Custom(RelayMap::from_iter(args.relays)));
    }
    let endpoint = builder.bind().await?;

    // Connecting to the home relay only works if its certificate chains up to one of our roots.
    // If it doesn't, `online` never resolves. See the `home-relay-status` example for details.
    match tokio::time::timeout(Duration::from_secs(10), endpoint.online()).await {
        Ok(()) => println!(
            "Endpoint is online. Home relay: {}",
            endpoint.addr().relay_urls().next().expect("has relay")
        ),
        Err(_) => println!("Not online after 10s, run with RUST_LOG=debug to see why"),
    }

    endpoint.close().await;
    Ok(())
}
