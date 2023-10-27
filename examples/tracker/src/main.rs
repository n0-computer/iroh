pub mod args;
pub mod discovery;
pub mod io;
pub mod iroh_bytes_util;
pub mod options;
pub mod protocol;
pub mod tracker;

use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use clap::Parser;
use io::CONFIG_DEFAULTS_FILE;
use iroh::util::fs::load_secret_key;
use iroh_net::{
    magic_endpoint::{get_alpn, get_peer_id},
    AddrInfo, MagicEndpoint, PeerAddr,
};
use tokio_util::task::LocalPoolHandle;

use crate::{
    args::{AnnounceArgs, Args, Commands, QueryArgs, ServerArgs},
    io::{load_from_file, setup_logging, tracker_home, tracker_path, CONFIG_FILE, SERVER_KEY_FILE},
    options::Options,
    protocol::{
        Announce, AnnounceKind, Query, QueryFlags, Request, Response, REQUEST_SIZE_LIMIT,
        TRACKER_ALPN,
    },
    tracker::Tracker,
};

pub type NodeId = iroh_net::key::PublicKey;

static VERBOSE: AtomicBool = AtomicBool::new(false);

fn set_verbose(verbose: bool) {
    VERBOSE.store(verbose, Ordering::Relaxed);
}

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        if $crate::verbose() {
            println!($($arg)*);
        }
    };
}

/// Wait until the endpoint has figured out it's own DERP region.
async fn await_derp_region(endpoint: &MagicEndpoint) -> anyhow::Result<()> {
    let t0 = Instant::now();
    loop {
        let addr = endpoint.my_addr().await?;
        if addr.derp_region().is_some() {
            break;
        }
        if t0.elapsed() > Duration::from_secs(10) {
            anyhow::bail!("timeout waiting for DERP region");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

async fn create_endpoint(
    key: iroh_net::key::SecretKey,
    port: u16,
) -> anyhow::Result<MagicEndpoint> {
    // let pkarr_relay_discovery = discovery::PkarrRelayDiscovery::new(key.clone(), PKARR_RELAY_URL.parse().unwrap());
    let region_discover = discovery::HardcodedRegionDiscovery::new(2);
    iroh_net::MagicEndpoint::builder()
        .secret_key(key)
        .discovery(Box::new(region_discover))
        .alpns(vec![TRACKER_ALPN.to_vec()])
        .bind(port)
        .await
}

/// Accept an incoming connection and extract the client-provided [`NodeId`] and ALPN protocol.
pub async fn accept_conn(
    mut conn: quinn::Connecting,
) -> anyhow::Result<(NodeId, String, quinn::Connection)> {
    let alpn = get_alpn(&mut conn).await?;
    tracing::info!("awaiting conn");
    let conn = conn.await?;
    tracing::info!("got conn");
    let peer_id = get_peer_id(&conn).await?;
    Ok((peer_id, alpn, conn))
}

/// Write default options to a sample config file.
fn write_defaults() -> anyhow::Result<()> {
    let default_path = tracker_path(CONFIG_DEFAULTS_FILE)?;
    crate::io::save_to_file(Options::default(), &default_path)?;
    Ok(())
}

async fn server(args: ServerArgs) -> anyhow::Result<()> {
    set_verbose(!args.quiet);
    let rt = tokio::runtime::Handle::current();
    let tpc = LocalPoolHandle::new(2);
    let rt = iroh_bytes::util::runtime::Handle::new(rt, tpc);
    let home = tracker_home()?;
    log!("tracker starting using {}", home.display());
    let key_path = tracker_path(SERVER_KEY_FILE)?;
    let key = load_secret_key(key_path).await?;
    let endpoint = create_endpoint(key, args.port).await?;
    let config_path = tracker_path(CONFIG_FILE)?;
    write_defaults()?;
    let mut options = load_from_file::<Options>(&config_path)?;
    options.make_paths_relative(&home);
    let db = Tracker::new(options)?;
    await_derp_region(&endpoint).await?;
    let addr = endpoint.my_addr().await?;
    log!("listening on {:?}", addr);
    log!("tracker addr: {}\n", addr.peer_id);
    log!("usage:");
    log!("tracker announce --tracker {} <tickets>", addr.peer_id);
    log!(
        "tracker query --tracker {} <hash> or <ticket>",
        addr.peer_id
    );
    log!();
    let db2 = db.clone();
    let endpoint2 = endpoint.clone();
    let _task = rt
        .local_pool()
        .spawn_pinned(move || db2.probe_loop(endpoint2));
    while let Some(connecting) = endpoint.accept().await {
        tracing::info!("got connecting");
        let db = db.clone();
        tokio::spawn(async move {
            let Ok((pk, h, conn)) = accept_conn(connecting).await else {
                tracing::error!("error accepting connection");
                return;
            };
            tracing::info!("got connection from {} {}", pk, h);
            if let Err(cause) = db.handle_connection(conn).await {
                tracing::error!("error handling connection: {}", cause);
            }
        });
    }
    Ok(())
}

async fn announce(args: AnnounceArgs) -> anyhow::Result<()> {
    set_verbose(true);
    // todo: uncomment once the connection problems are fixed
    // for now, a random node id is more reliable.
    // let key = load_secret_key(tracker_path(CLIENT_KEY)?).await?;
    let key = iroh_net::key::SecretKey::generate();
    let endpoint = create_endpoint(key, 11112).await?;
    log!("announce {:?}", args);
    log!("trying to connect to {:?}", args.tracker);
    let info = PeerAddr {
        peer_id: args.tracker,
        info: AddrInfo {
            derp_region: Some(2),
            direct_addresses: Default::default(),
        },
    };
    let connection = endpoint.connect(info, TRACKER_ALPN).await?;
    log!("connected to {:?}", connection.remote_address());
    let (mut send, mut recv) = connection.open_bi().await?;
    log!("opened bi stream");
    let kind = if args.partial {
        AnnounceKind::Partial
    } else {
        AnnounceKind::Complete
    };
    let host = if let Some(host) = args.host {
        host
    } else {
        let hosts = args
            .content
            .iter()
            .filter_map(|x| x.host())
            .collect::<BTreeSet<_>>();
        if hosts.len() != 1 {
            anyhow::bail!(
                "content for all tickets must be from the same host, unless a host is specified"
            );
        }
        *hosts.iter().next().unwrap()
    };
    let content = args.content.iter().map(|x| x.hash_and_format()).collect();
    let announce = Announce {
        host,
        kind,
        content,
    };
    let request = Request::Announce(announce);
    let request = postcard::to_stdvec(&request)?;
    log!("sending announce");
    send.write_all(&request).await?;
    send.finish().await?;
    let _response = recv.read_to_end(REQUEST_SIZE_LIMIT).await?;
    Ok(())
}

async fn query(args: QueryArgs) -> anyhow::Result<()> {
    set_verbose(true);
    // todo: uncomment once the connection problems are fixed
    // for now, a random node id is more reliable.
    // let key = load_secret_key(tracker_path(CLIENT_KEY)?).await?;
    let key = iroh_net::key::SecretKey::generate();
    let endpoint = create_endpoint(key, args.port.unwrap_or_default()).await?;
    let query = Query {
        content: args.content.hash_and_format(),
        flags: QueryFlags {
            complete: !args.partial,
            verified: args.verified,
        },
    };
    let info = PeerAddr {
        peer_id: args.tracker,
        info: AddrInfo {
            derp_region: Some(2),
            direct_addresses: Default::default(),
        },
    };
    log!("trying to connect to tracker at {:?}", args.tracker);
    let connection = endpoint.connect(info, TRACKER_ALPN).await?;
    log!("connected to {:?}", connection.remote_address());
    let (mut send, mut recv) = connection.open_bi().await?;
    log!("opened bi stream");
    let request = Request::Query(query);
    let request = postcard::to_stdvec(&request)?;
    log!("sending query");
    send.write_all(&request).await?;
    send.finish().await?;
    let response = recv.read_to_end(REQUEST_SIZE_LIMIT).await?;
    let response = postcard::from_bytes::<Response>(&response)?;
    match response {
        Response::QueryResponse(response) => {
            log!("content {}", response.content);
            for peer in response.hosts {
                log!("- peer {}", peer);
            }
        }
    }
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    setup_logging();
    let args = Args::parse();
    match args.command {
        Commands::Server(args) => server(args).await,
        Commands::Announce(args) => announce(args).await,
        Commands::Query(args) => query(args).await,
    }
}
