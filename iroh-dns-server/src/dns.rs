//! Implementation of a DNS name server for iroh endpoint announces

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use bytes::Bytes;
use domain::{
    base::{
        Message, MessageBuilder, Name, Record, Ttl,
        iana::{Class, Opcode, Rcode, Rtype},
    },
    rdata::{A, Aaaa, Ns, Soa, Txt},
};
use n0_error::{Result, StdResultExt, anyerr};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, info, trace, warn};

use crate::{metrics::Metrics, store::ZoneStore, util::PublicKeyBytes};

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
    /// Domain used for serving the `_iroh.<endpointid>.<origin>` DNS TXT entry
    pub origins: Vec<String>,

    /// `A` record to set for all origins
    pub rr_a: Option<Ipv4Addr>,
    /// `AAAA` record to set for all origins
    pub rr_aaaa: Option<Ipv6Addr>,
    /// `NS` record to set for all origins
    pub rr_ns: Option<String>,
}

/// Protocol used for DNS queries (for metrics).
#[derive(Debug, Clone, Copy)]
pub enum DnsProtocol {
    /// DNS over UDP
    Udp,
    /// DNS over HTTPS
    Https,
}

/// A DNS server that serves pkarr signed packets.
pub struct DnsServer {
    local_addr: SocketAddr,
    cancel: tokio::sync::watch::Sender<bool>,
    udp_task: tokio::task::JoinHandle<()>,
    tcp_task: tokio::task::JoinHandle<()>,
}

impl DnsServer {
    /// Spawn the server.
    pub async fn spawn(config: DnsConfig, dns_handler: DnsHandler) -> Result<Self> {
        let bind_addr = SocketAddr::new(
            config.bind_addr.unwrap_or(Ipv4Addr::UNSPECIFIED.into()),
            config.port,
        );

        let udp_socket = Arc::new(UdpSocket::bind(bind_addr).await.anyerr()?);
        let local_addr = udp_socket.local_addr().anyerr()?;
        let tcp_bind_addr = SocketAddr::new(local_addr.ip(), local_addr.port());
        let tcp_listener = TcpListener::bind(tcp_bind_addr).await.anyerr()?;

        info!("DNS server listening on {}", local_addr);

        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let handler = Arc::new(dns_handler);

        let udp_handler = handler.clone();
        let mut udp_cancel = cancel_rx.clone();
        let udp_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    result = udp_socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, src)) => {
                                let query_bytes = buf[..len].to_vec();
                                let handler = udp_handler.clone();
                                let socket = udp_socket.clone();
                                tokio::spawn(async move {
                                    match handler.answer(&query_bytes, DnsProtocol::Udp).await {
                                        Ok(response) => {
                                            if let Err(e) = socket.send_to(&response, src).await {
                                                warn!("failed to send UDP response: {e}");
                                            }
                                        }
                                        Err(e) => {
                                            debug!("failed to handle DNS query: {e}");
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("UDP recv error: {e}");
                            }
                        }
                    }
                    _ = udp_cancel.changed() => {
                        break;
                    }
                }
            }
        });

        let tcp_handler = handler.clone();
        let mut tcp_cancel = cancel_rx.clone();
        let tcp_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = tcp_listener.accept() => {
                        match result {
                            Ok((stream, _src)) => {
                                let handler = tcp_handler.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = handle_tcp_connection(stream, &handler).await {
                                        debug!("TCP DNS connection error: {e}");
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("TCP accept error: {e}");
                            }
                        }
                    }
                    _ = tcp_cancel.changed() => {
                        break;
                    }
                }
            }
        });

        Ok(Self {
            local_addr,
            cancel: cancel_tx,
            udp_task,
            tcp_task,
        })
    }

    /// Get the local address of the UDP/TCP socket.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Shutdown the server and wait for all tasks to complete.
    pub async fn shutdown(self) -> Result<()> {
        let _ = self.cancel.send(true);
        self.udp_task.abort();
        self.tcp_task.abort();
        let _ = self.udp_task.await;
        let _ = self.tcp_task.await;
        Ok(())
    }

    /// Wait for all tasks to complete.
    ///
    /// Runs forever unless tasks fail.
    pub async fn run_until_done(self) -> Result<()> {
        tokio::select! {
            res = self.udp_task => { res.anyerr()?; }
            res = self.tcp_task => { res.anyerr()?; }
        }
        Ok(())
    }
}

/// Handle a single TCP DNS connection (length-prefixed messages).
async fn handle_tcp_connection(
    stream: tokio::net::TcpStream,
    handler: &DnsHandler,
) -> io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut reader, mut writer) = stream.into_split();
    loop {
        // Read 2-byte length prefix
        let len = match reader.read_u16().await {
            Ok(len) => len as usize,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        if len == 0 {
            continue;
        }
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await?;

        match handler.answer(&buf, DnsProtocol::Udp).await {
            Ok(response) => {
                let response_len = response.len() as u16;
                writer.write_u16(response_len).await?;
                writer.write_all(&response).await?;
            }
            Err(e) => {
                debug!("failed to handle TCP DNS query: {e}");
                return Ok(());
            }
        }
    }
}

/// Parsed static records for an origin zone.
struct StaticRecords {
    /// SOA record fields
    soa_mname: Name<Vec<u8>>,
    soa_rname: Name<Vec<u8>>,
    soa_serial: u32,
    soa_refresh: u32,
    soa_retry: u32,
    soa_expire: u32,
    soa_minimum: u32,
    /// Optional A record
    rr_a: Option<Ipv4Addr>,
    /// Optional AAAA record
    rr_aaaa: Option<Ipv6Addr>,
    /// Optional NS record
    rr_ns: Option<Name<Vec<u8>>>,
}

/// State for serving DNS
#[derive(Clone, derive_more::Debug)]
pub struct DnsHandler {
    #[debug("ZoneStore")]
    zone_store: ZoneStore,
    #[debug("StaticRecords")]
    static_records: Arc<StaticRecords>,
    origins: Vec<String>,
    metrics: Arc<Metrics>,
}

impl DnsHandler {
    /// Create a DNS handler.
    pub fn new(zone_store: ZoneStore, config: &DnsConfig, metrics: Arc<Metrics>) -> Result<Self> {
        let static_records = parse_static_records(config)?;
        let origins: Vec<String> = config
            .origins
            .iter()
            .map(|o| {
                // Normalize: strip trailing dot for consistent matching
                o.trim_end_matches('.').to_string()
            })
            .collect();

        Ok(Self {
            zone_store,
            static_records: Arc::new(static_records),
            origins,
            metrics,
        })
    }

    /// Handle a DNS query from raw bytes, return response bytes.
    pub async fn answer(&self, query_bytes: &[u8], protocol: DnsProtocol) -> Result<Bytes> {
        self.metrics.dns_requests.inc();
        match protocol {
            DnsProtocol::Udp => {
                self.metrics.dns_requests_udp.inc();
            }
            DnsProtocol::Https => {
                self.metrics.dns_requests_https.inc();
            }
        }

        let query = Message::from_octets(query_bytes.to_vec())
            .map_err(|_| anyerr!("invalid DNS message"))?;

        debug!("incoming DNS request");

        let response_bytes = self.resolve_query(&query).await?;

        // Count answers for metrics
        if let Ok(response) = Message::from_octets(response_bytes.clone()) {
            let rcode = response.header().rcode();
            if rcode == Rcode::NOERROR {
                if let Ok(answer) = response.answer() {
                    let count = answer.count();
                    if count == 0 {
                        self.metrics.dns_lookup_notfound.inc();
                    } else {
                        self.metrics.dns_lookup_success.inc();
                    }
                }
            } else if rcode == Rcode::NXDOMAIN {
                self.metrics.dns_lookup_notfound.inc();
            } else {
                self.metrics.dns_lookup_error.inc();
            }
        }

        Ok(Bytes::from(response_bytes))
    }

    /// Resolve a DNS query message and return the response as wire-format bytes.
    async fn resolve_query(&self, query: &Message<Vec<u8>>) -> Result<Vec<u8>> {
        let header = query.header();

        // Only handle queries
        if header.opcode() != Opcode::QUERY {
            return self.build_error_response(query, Rcode::REFUSED);
        }

        // Collect questions
        let questions: Vec<_> = query.question().filter_map(|q| q.ok()).collect();

        if questions.is_empty() {
            return self.build_error_response(query, Rcode::FORMERR);
        }

        // Build response
        let builder = MessageBuilder::new_vec();
        let mut answer_builder = builder
            .start_answer(query, Rcode::NOERROR)
            .map_err(|e| anyerr!("failed to start answer: {e}"))?;
        answer_builder.header_mut().set_aa(true);
        answer_builder.header_mut().set_ra(false);

        let mut found_any = false;
        let mut nx_domain = false;

        for q in &questions {
            let qname = q.qname().to_string();
            let qtype = q.qtype();

            trace!(name=%qname, typ=?qtype, "resolving question");

            match self.resolve_name(&qname, qtype).await {
                ResolveResult::Answers(records) => {
                    found_any = true;
                    for record in records {
                        record
                            .push_to(&mut answer_builder)
                            .map_err(|e| anyerr!("failed to push record: {e}"))?;
                    }
                }
                ResolveResult::NxDomain => {
                    nx_domain = true;
                }
                ResolveResult::NoData => {
                    // No records of this type, but the name exists
                }
            }
        }

        if !found_any && nx_domain {
            answer_builder.header_mut().set_rcode(Rcode::NXDOMAIN);
        }

        let response = answer_builder.into_message();
        Ok(response.into_octets())
    }

    /// Resolve a single DNS name and type.
    async fn resolve_name(&self, qname: &str, qtype: Rtype) -> ResolveResult {
        let qname_normalized = qname.trim_end_matches('.');

        // Check if this is a query for an origin itself (static records)
        for origin in &self.origins {
            if qname_normalized.eq_ignore_ascii_case(origin)
                || (origin.is_empty() && (qname == "." || qname.is_empty()))
            {
                return self.resolve_static(qname, qtype);
            }
        }

        // Try to parse as a pkarr name within one of the origins
        for origin in &self.origins {
            if let Some(result) = self.try_resolve_pkarr(qname, qtype, origin).await {
                return result;
            }
        }

        // Not a known name
        ResolveResult::NxDomain
    }

    /// Resolve static records (SOA, NS, A, AAAA) for an origin.
    fn resolve_static(&self, qname: &str, qtype: Rtype) -> ResolveResult {
        let sr = &self.static_records;
        let mut records: Vec<DnsRecord> = Vec::new();

        let name: Name<Vec<u8>> = match qname.parse() {
            Ok(n) => n,
            Err(_) => return ResolveResult::NxDomain,
        };

        match qtype {
            Rtype::SOA => {
                let soa = Soa::new(
                    sr.soa_mname.clone(),
                    sr.soa_rname.clone(),
                    domain::base::Serial::from(sr.soa_serial),
                    Ttl::from_secs(sr.soa_refresh),
                    Ttl::from_secs(sr.soa_retry),
                    Ttl::from_secs(sr.soa_expire),
                    Ttl::from_secs(sr.soa_minimum),
                );
                records.push(DnsRecord::Soa(Record::new(
                    name,
                    Class::IN,
                    Ttl::from_secs(DEFAULT_SOA_TTL),
                    soa,
                )));
            }
            Rtype::NS => {
                if let Some(ns_name) = &sr.rr_ns {
                    records.push(DnsRecord::Ns(Record::new(
                        name,
                        Class::IN,
                        Ttl::from_secs(DEFAULT_NS_TTL),
                        Ns::new(ns_name.clone()),
                    )));
                }
            }
            Rtype::A => {
                if let Some(addr) = sr.rr_a {
                    records.push(DnsRecord::A(Record::new(
                        name,
                        Class::IN,
                        Ttl::from_secs(DEFAULT_A_TTL),
                        A::new(addr),
                    )));
                }
            }
            Rtype::AAAA => {
                if let Some(addr) = sr.rr_aaaa {
                    records.push(DnsRecord::Aaaa(Record::new(
                        name,
                        Class::IN,
                        Ttl::from_secs(DEFAULT_A_TTL),
                        Aaaa::new(addr),
                    )));
                }
            }
            _ => {}
        }

        if records.is_empty() {
            ResolveResult::NoData
        } else {
            ResolveResult::Answers(records)
        }
    }

    /// Try to resolve a name as a pkarr name under the given origin.
    async fn try_resolve_pkarr(
        &self,
        qname: &str,
        qtype: Rtype,
        origin: &str,
    ) -> Option<ResolveResult> {
        let qname_normalized = qname.trim_end_matches('.');

        // Check if qname ends with the origin
        let labels_before_origin = if origin.is_empty() {
            // Root origin: all labels are before the origin
            qname_normalized
        } else if qname_normalized.eq_ignore_ascii_case(origin) {
            // The qname IS the origin, not a pkarr name
            return None;
        } else {
            let suffix = format!(".{origin}");
            strip_suffix_ignore_case(qname_normalized, &suffix)?
        };

        // Parse the z32 pubkey label (last label before origin)
        let (remaining_name, pubkey_label) = match labels_before_origin.rsplit_once('.') {
            Some((prefix, pubkey)) => (prefix.to_string(), pubkey),
            None => (String::new(), labels_before_origin),
        };

        let pubkey = match PublicKeyBytes::from_z32(pubkey_label) {
            Ok(pk) => pk,
            Err(_) => return None, // Not a valid z32 pubkey, not a pkarr name
        };

        debug!(%origin, %pubkey, name=%remaining_name, "resolve in pkarr zones");

        match self
            .zone_store
            .resolve(&pubkey, &remaining_name, qtype)
            .await
        {
            Ok(Some(zone_records)) => {
                debug!(
                    %origin,
                    %pubkey,
                    name=%remaining_name,
                    "found {} records in pkarr zone",
                    zone_records.len()
                );
                let mut records = Vec::new();
                let full_name: Name<Vec<u8>> = match qname.parse() {
                    Ok(n) => n,
                    Err(_) => return Some(ResolveResult::NxDomain),
                };
                for zr in &zone_records {
                    if let Some(record) = zone_record_to_dns(&full_name, qtype, zr) {
                        records.push(record);
                    }
                }
                if records.is_empty() {
                    Some(ResolveResult::NoData)
                } else {
                    Some(ResolveResult::Answers(records))
                }
            }
            Ok(None) => Some(ResolveResult::NxDomain),
            Err(e) => {
                warn!("zone store resolve error: {e}");
                Some(ResolveResult::NxDomain)
            }
        }
    }

    fn build_error_response(&self, query: &Message<Vec<u8>>, rcode: Rcode) -> Result<Vec<u8>> {
        let builder = MessageBuilder::new_vec();
        let answer = builder
            .start_answer(query, rcode)
            .map_err(|e| anyerr!("failed to build error response: {e}"))?;
        Ok(answer.into_message().into_octets())
    }
}

/// Result of resolving a DNS name.
enum ResolveResult {
    /// Found answer records.
    Answers(Vec<DnsRecord>),
    /// The name does not exist.
    NxDomain,
    /// The name exists but has no records of the requested type.
    NoData,
}

/// A DNS record that can be pushed to a MessageBuilder answer section.
///
/// We need this enum because domain's `push()` requires concrete types.
enum DnsRecord {
    A(Record<Name<Vec<u8>>, A>),
    Aaaa(Record<Name<Vec<u8>>, Aaaa>),
    Txt(Record<Name<Vec<u8>>, Txt<Vec<u8>>>),
    Soa(Record<Name<Vec<u8>>, Soa<Name<Vec<u8>>>>),
    Ns(Record<Name<Vec<u8>>, Ns<Name<Vec<u8>>>>),
}

impl DnsRecord {
    fn push_to(
        self,
        answer: &mut domain::base::message_builder::AnswerBuilder<Vec<u8>>,
    ) -> std::result::Result<(), domain::base::message_builder::PushError> {
        match self {
            DnsRecord::A(r) => answer.push(r),
            DnsRecord::Aaaa(r) => answer.push(r),
            DnsRecord::Txt(r) => answer.push(r),
            DnsRecord::Soa(r) => answer.push(r),
            DnsRecord::Ns(r) => answer.push(r),
        }
    }
}

/// Convert a ZoneRecord to a DNS record for the wire format.
fn zone_record_to_dns(
    name: &Name<Vec<u8>>,
    rtype: Rtype,
    zr: &crate::util::ZoneRecord,
) -> Option<DnsRecord> {
    let ttl = Ttl::from_secs(zr.ttl);
    match rtype {
        Rtype::TXT => {
            let txt: Txt<Vec<u8>> = Txt::build_from_slice(zr.data.as_bytes()).ok()?;
            Some(DnsRecord::Txt(Record::new(
                name.clone(),
                Class::IN,
                ttl,
                txt,
            )))
        }
        Rtype::A => {
            let addr: Ipv4Addr = zr.data.parse().ok()?;
            Some(DnsRecord::A(Record::new(
                name.clone(),
                Class::IN,
                ttl,
                A::new(addr),
            )))
        }
        Rtype::AAAA => {
            let addr: Ipv6Addr = zr.data.parse().ok()?;
            Some(DnsRecord::Aaaa(Record::new(
                name.clone(),
                Class::IN,
                ttl,
                Aaaa::new(addr),
            )))
        }
        _ => {
            // Unsupported record type
            None
        }
    }
}

/// Parse the static records from the config.
fn parse_static_records(config: &DnsConfig) -> Result<StaticRecords> {
    let parts: Vec<&str> = config.default_soa.split_ascii_whitespace().collect();
    if parts.len() < 7 {
        return Err(anyerr!(
            "SOA record must have 7 fields: mname rname serial refresh retry expire minimum, got: {}",
            config.default_soa
        ));
    }

    let soa_mname: Name<Vec<u8>> = parts[0]
        .parse()
        .map_err(|e| anyerr!("invalid SOA mname: {e}"))?;
    let soa_rname: Name<Vec<u8>> = parts[1]
        .parse()
        .map_err(|e| anyerr!("invalid SOA rname: {e}"))?;
    let soa_serial: u32 = parts[2]
        .parse()
        .map_err(|e| anyerr!("invalid SOA serial: {e}"))?;
    let soa_refresh: u32 = parts[3]
        .parse()
        .map_err(|e| anyerr!("invalid SOA refresh: {e}"))?;
    let soa_retry: u32 = parts[4]
        .parse()
        .map_err(|e| anyerr!("invalid SOA retry: {e}"))?;
    let soa_expire: u32 = parts[5]
        .parse()
        .map_err(|e| anyerr!("invalid SOA expire: {e}"))?;
    let soa_minimum: u32 = parts[6]
        .parse()
        .map_err(|e| anyerr!("invalid SOA minimum: {e}"))?;

    let rr_ns = if let Some(ns) = &config.rr_ns {
        Some(ns.parse().map_err(|e| anyerr!("invalid NS name: {e}"))?)
    } else {
        None
    };

    Ok(StaticRecords {
        soa_mname,
        soa_rname,
        soa_serial,
        soa_refresh,
        soa_retry,
        soa_expire,
        soa_minimum,
        rr_a: config.rr_a,
        rr_aaaa: config.rr_aaaa,
        rr_ns,
    })
}

/// Case-insensitive suffix stripping.
fn strip_suffix_ignore_case<'a>(s: &'a str, suffix: &str) -> Option<&'a str> {
    if s.len() >= suffix.len() && s[s.len() - suffix.len()..].eq_ignore_ascii_case(suffix) {
        Some(&s[..s.len() - suffix.len()])
    } else {
        None
    }
}
