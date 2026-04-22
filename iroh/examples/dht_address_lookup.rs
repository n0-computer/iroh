//! An example chat application using the iroh endpoint and
//! pkarr address lookup.
//!
//! Starting the example without args creates a server that publishes its
//! address to the DHT. Starting the example with an endpoint id as argument
//! looks up the address of the endpoint id in the DHT and connects to it.
//!
//! You can look at the published pkarr DNS record using <https://app.pkarr.org/>.
//!
//! To see what is going on, run with `RUST_LOG=iroh_pkarr_address_lookup=debug`.
//!
//! Note that while the DhtAddressLookup by default publishes only the home
//! relay of the endpoint, this example explicitly removes the filter to publish
//! all addresses.
use clap::Parser;
use iroh::{
    Endpoint, EndpointId,
    address_lookup::{AddrFilter, DhtAddressLookup},
    endpoint::presets,
};
use n0_error::{Result, StdResultExt};
use tracing::warn;

const CHAT_ALPN: &[u8] = b"pkarr-address-lookup-demo-chat";

#[derive(Parser)]
struct Args {
    /// The endpoint id to connect to. If not set, the program will start a server.
    endpoint_id: Option<EndpointId>,
}

async fn chat_server() -> Result<()> {
    let secret_key = iroh::SecretKey::generate();
    let endpoint_id = secret_key.public();
    let address_lookup = DhtAddressLookup::builder().addr_filter(AddrFilter::unfiltered());
    let endpoint = Endpoint::builder(presets::N0)
        .alpns(vec![CHAT_ALPN.to_vec()])
        .secret_key(secret_key)
        .address_lookup(address_lookup)
        .bind()
        .await?;
    let zid = endpoint_id.to_z32();
    println!("Listening on {endpoint_id}");
    println!("pkarr z32: {zid}");
    println!("see https://app.pkarr.org/?pk={zid}");
    while let Some(incoming) = endpoint.accept().await {
        let accepting = match incoming.accept() {
            Ok(accepting) => accepting,
            Err(err) => {
                warn!("incoming connection failed: {err:#}");
                // we can carry on in these cases:
                // this can be caused by retransmitted datagrams
                continue;
            }
        };
        tokio::spawn(async move {
            let connection = accepting.await?;
            let remote_endpoint_id = connection.remote_id();
            println!("got connection from {remote_endpoint_id}");
            // just leave the tasks hanging. this is just an example.
            let (mut writer, mut reader) = connection.accept_bi().await.anyerr()?;
            let _copy_to_stdout = tokio::spawn(async move {
                tokio::io::copy(&mut reader, &mut tokio::io::stdout()).await
            });
            let _copy_from_stdin =
                tokio::spawn(
                    async move { tokio::io::copy(&mut tokio::io::stdin(), &mut writer).await },
                );
            n0_error::Ok(())
        });
    }
    Ok(())
}

async fn chat_client(args: Args) -> Result<()> {
    let remote_endpoint_id = args.endpoint_id.unwrap();
    let secret_key = iroh::SecretKey::generate();
    let endpoint_id = secret_key.public();
    // note: we don't pass a secret key here, because we don't need to publish our address, don't spam the DHT
    let address_lookup = DhtAddressLookup::builder().no_publish();
    // we do not need to specify the alpn here, because we are not going to accept connections
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .address_lookup(address_lookup)
        .bind()
        .await?;
    println!("We are {endpoint_id} and connecting to {remote_endpoint_id}");
    let connection = endpoint.connect(remote_endpoint_id, CHAT_ALPN).await?;
    println!("connected to {remote_endpoint_id}");
    let (mut writer, mut reader) = connection.open_bi().await.anyerr()?;
    let _copy_to_stdout =
        tokio::spawn(async move { tokio::io::copy(&mut reader, &mut tokio::io::stdout()).await });
    let _copy_from_stdin =
        tokio::spawn(async move { tokio::io::copy(&mut tokio::io::stdin(), &mut writer).await });
    _copy_to_stdout.await.anyerr()?.anyerr()?;
    _copy_from_stdin.await.anyerr()?.anyerr()?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    if args.endpoint_id.is_some() {
        chat_client(args).await?;
    } else {
        chat_server().await?;
    }
    Ok(())
}
