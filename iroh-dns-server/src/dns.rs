//! Implementation of a DNS name server for iroh node announces

use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use hickory_server::{
    authority::{Catalog, MessageResponse, ZoneType},
    proto::{
        self,
        op::ResponseCode,
        rr::{
            LowerName, Name, RData, Record, RecordSet, RecordType, RrKey,
            rdata::{self},
        },
        serialize::{binary::BinEncoder, txt::RDataParser},
        xfer::Protocol,
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    store::in_memory::InMemoryAuthority,
};
use n0_snafu::{Result, ResultExt, format_err};
use serde::{Deserialize, Serialize};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::broadcast,
};
use tracing::{debug, info};

use self::node_authority::NodeAuthority;
use crate::{metrics::Metrics, store::ZoneStore};

mod node_authority;

const DEFAULT_NS_TTL: u32 = 60 * 60 * 12; // 12h
const DEFAULT_SOA_TTL: u32 = 60 * 60 * 24 * 14; // 14d
const DEFAULT_A_TTL: u32 = 60 * 60; // 1h

/// DNS server settings
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsConfig {
    /// The port to serve a local UDP DNS server at
    pub port: u16,
    /// The IPv4 or IPv6 address to bind the UDP DNS server.
    /// Uses `0.0.0.0` if unspecified.
    pub bind_addr: Option<IpAddr>,
    /// SOA record data for any authoritative DNS records
    pub default_soa: String,
    /// Default time to live for returned DNS records (TXT & SOA)
    pub default_ttl: u32,
    /// Domain used for serving the `_iroh_node.<nodeid>.<origin>` DNS TXT entry
    pub origins: Vec<String>,

    /// `A` record to set for all origins
    pub rr_a: Option<Ipv4Addr>,
    /// `AAAA` record to set for all origins
    pub rr_aaaa: Option<Ipv6Addr>,
    /// `NS` record to set for all origins
    pub rr_ns: Option<String>,
}

/// A DNS server that serves pkarr signed packets.
pub struct DnsServer {
    local_addr: SocketAddr,
    server: hickory_server::ServerFuture<DnsHandler>,
}

impl DnsServer {
    /// Spawn the server.
    pub async fn spawn(config: DnsConfig, dns_handler: DnsHandler) -> Result<Self> {
        const TCP_TIMEOUT: Duration = Duration::from_millis(1000);
        let mut server = hickory_server::ServerFuture::new(dns_handler);

        let bind_addr = SocketAddr::new(
            config.bind_addr.unwrap_or(Ipv4Addr::UNSPECIFIED.into()),
            config.port,
        );

        let socket = UdpSocket::bind(bind_addr).await.e()?;

        let socket_addr = socket.local_addr().e()?;

        server.register_socket(socket);
        server.register_listener(TcpListener::bind(bind_addr).await.e()?, TCP_TIMEOUT);
        info!("DNS server listening on {}", bind_addr);

        Ok(Self {
            server,
            local_addr: socket_addr,
        })
    }

    /// Get the local address of the UDP/TCP socket.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Shutdown the server an wait for all tasks to complete.
    pub async fn shutdown(mut self) -> Result<()> {
        self.server.shutdown_gracefully().await.e()?;
        Ok(())
    }

    /// Wait for all tasks to complete.
    ///
    /// Runs forever unless tasks fail.
    pub async fn run_until_done(mut self) -> Result<()> {
        self.server.block_until_done().await.e()?;
        Ok(())
    }
}

/// State for serving DNS
#[derive(Clone, derive_more::Debug)]
pub struct DnsHandler {
    #[debug("Catalog")]
    catalog: Arc<Catalog>,
    metrics: Arc<Metrics>,
}

impl DnsHandler {
    /// Create a DNS server given some settings, a connection to the DB for DID-by-username lookups
    /// and the server DID to serve under `_did.<origin>`.
    pub fn new(zone_store: ZoneStore, config: &DnsConfig, metrics: Arc<Metrics>) -> Result<Self> {
        let origins = config
            .origins
            .iter()
            .map(Name::from_utf8)
            .collect::<Result<Vec<_>, _>>()
            .e()?;

        let (static_authority, serial) = create_static_authority(&origins, config)?;
        let authority = Arc::new(NodeAuthority::new(
            zone_store,
            static_authority,
            origins,
            serial,
        )?);

        let mut catalog = Catalog::new();
        for origin in authority.origins() {
            catalog.upsert(LowerName::from(origin), vec![authority.clone()]);
        }

        Ok(Self {
            catalog: Arc::new(catalog),
            metrics,
        })
    }

    /// Handle a DNS request
    pub async fn answer_request(&self, request: Request) -> Result<Bytes> {
        let (tx, mut rx) = broadcast::channel(1);
        let response_handle = Handle(tx);
        self.handle_request(&request, response_handle).await;
        rx.recv().await.e()
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        self.metrics.dns_requests.inc();
        match request.protocol() {
            Protocol::Udp => {
                self.metrics.dns_requests_udp.inc();
            }
            Protocol::Https => {
                self.metrics.dns_requests_https.inc();
            }
            _ => {}
        }
        debug!(protocol=%request.protocol(), queries=?request.queries(), "incoming DNS request");

        let res = self.catalog.handle_request(request, response_handle).await;
        match &res.response_code() {
            ResponseCode::NoError => match res.answer_count() {
                0 => self.metrics.dns_lookup_notfound.inc(),
                _ => self.metrics.dns_lookup_success.inc(),
            },
            ResponseCode::NXDomain => self.metrics.dns_lookup_notfound.inc(),
            _ => self.metrics.dns_lookup_error.inc(),
        };
        res
    }
}

/// A handle to the channel over which the response to a DNS request will be sent
#[derive(Debug, Clone)]
pub struct Handle(pub broadcast::Sender<Bytes>);

#[async_trait]
impl ResponseHandler for Handle {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
            impl Iterator<Item = &'a proto::rr::Record> + Send + 'a,
        >,
    ) -> io::Result<ResponseInfo> {
        let mut bytes = Vec::with_capacity(512);
        let info = {
            let mut encoder = BinEncoder::new(&mut bytes);
            response.destructive_emit(&mut encoder)?
        };

        let bytes = Bytes::from(bytes);
        self.0.send(bytes).unwrap();

        Ok(info)
    }
}

fn create_static_authority(
    origins: &[Name],
    config: &DnsConfig,
) -> Result<(InMemoryAuthority, u32)> {
    let soa = RData::parse(
        RecordType::SOA,
        config.default_soa.split_ascii_whitespace(),
        None,
    )
    .e()?
    .into_soa()
    .map_err(|_| format_err!("Couldn't parse SOA: {}", config.default_soa))?;
    let serial = soa.serial();
    let mut records = BTreeMap::new();
    for name in origins {
        push_record(
            &mut records,
            serial,
            Record::from_rdata(name.clone(), DEFAULT_SOA_TTL, RData::SOA(soa.clone())),
        );
        if let Some(addr) = config.rr_a {
            push_record(
                &mut records,
                serial,
                Record::from_rdata(name.clone(), DEFAULT_A_TTL, RData::A(addr.into())),
            );
        }
        if let Some(addr) = config.rr_aaaa {
            push_record(
                &mut records,
                serial,
                Record::from_rdata(name.clone(), DEFAULT_A_TTL, RData::AAAA(addr.into())),
            );
        }
        if let Some(ns) = &config.rr_ns {
            let ns = Name::parse(ns, Some(&Name::root())).e()?;
            push_record(
                &mut records,
                serial,
                Record::from_rdata(name.clone(), DEFAULT_NS_TTL, RData::NS(rdata::NS(ns))),
            );
        }
    }

    let static_authority = InMemoryAuthority::new(Name::root(), records, ZoneType::Primary, false)
        .map_err(|e| format_err!("new authority: {e}"))?;

    Ok((static_authority, serial))
}

fn push_record(records: &mut BTreeMap<RrKey, RecordSet>, serial: u32, record: Record) {
    let key = RrKey::new(record.name().clone().into(), record.record_type());
    let mut record_set = RecordSet::new(record.name().clone(), record.record_type(), serial);
    record_set.insert(record, serial);
    records.insert(key, record_set);
}
