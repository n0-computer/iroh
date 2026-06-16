//! DNS transport implementations: UDP, TCP, TLS, and HTTPS.

use std::net::SocketAddr;
#[cfg(with_crypto_provider)]
use std::sync::Arc;

#[cfg(with_crypto_provider)]
use n0_error::{AnyError, StdResultExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(with_crypto_provider)]
use crate::dns::DnsError;

// Known limitation: TCP and TLS connections are not reused across queries.
// Each query opens a fresh connection, which means a full TLS handshake per
// DNS-over-TLS query. This adds significant latency for DoT/DoH workloads.
// The default UDP-only configuration is not affected.
//
// A future improvement could maintain a per-nameserver connection pool for
// TCP/TLS, similar to how hickory-resolver multiplexes queries over
// persistent connections.
//
// UDP sockets are intentionally not reused (new random source port per query
// prevents cache poisoning).

/// Send a DNS query over UDP and receive the response.
///
/// Each query uses a fresh socket with a random ephemeral source port to
/// prevent cache poisoning. The response source address is validated against
/// the target nameserver.
pub(super) async fn udp_query(addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let unspecified: std::net::IpAddr = if addr.is_ipv6() {
        std::net::Ipv6Addr::UNSPECIFIED.into()
    } else {
        std::net::Ipv4Addr::UNSPECIFIED.into()
    };
    let bind_addr = SocketAddr::new(unspecified, 0);
    let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
    socket.send_to(query, addr).await?;

    let mut buf = vec![0u8; 4096];
    let (len, src) = socket.recv_from(&mut buf).await?;
    if src != addr {
        return Err(std::io::Error::other(format!(
            "DNS response from unexpected source {src}, expected {addr}"
        )))?;
    }
    buf.truncate(len);
    Ok(buf)
}

/// Send a DNS query over TCP (RFC 1035 Section 4.2.2: 2-byte length prefix).
pub(super) async fn tcp_query(addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut stream = tokio::net::TcpStream::connect(addr).await?;

    // Write length-prefixed query
    let len = u16::try_from(query.len())
        .map_err(|_| std::io::Error::other("DNS query too large for TCP framing"))?
        .to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(query).await?;
    stream.flush().await?;

    // Read length-prefixed response
    let resp_len = stream.read_u16().await? as usize;
    let mut buf = vec![0u8; resp_len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Send a DNS query over TLS (DNS-over-TLS, RFC 7858).
///
/// With `server_name`, that name is used for SNI and certificate validation;
/// without it the certificate is validated against the IP address, which works
/// for providers that include IP SANs (e.g. Google `8.8.8.8`, Cloudflare
/// `1.1.1.1`) but not for those whose certificates only cover a hostname.
#[cfg(with_crypto_provider)]
pub(super) async fn tls_query(
    addr: SocketAddr,
    query: &[u8],
    tls_config: &Arc<rustls::ClientConfig>,
    server_name: Option<&str>,
) -> Result<Vec<u8>, std::io::Error> {
    let connector = tokio_rustls::TlsConnector::from(tls_config.clone());
    let tcp_stream = tokio::net::TcpStream::connect(addr).await?;

    // Use the explicit server name for SNI and validation if given, otherwise
    // validate against the IP the connection was made to.
    let server_name = match server_name {
        Some(name) => rustls::pki_types::ServerName::try_from(name.to_string())
            .map_err(std::io::Error::other)?,
        None => rustls::pki_types::ServerName::IpAddress(addr.ip().into()),
    };
    let mut stream = connector.connect(server_name, tcp_stream).await?;

    // Write length-prefixed query (same framing as TCP)
    let len = u16::try_from(query.len())
        .map_err(|_| std::io::Error::other("DNS query too large for TCP framing"))?
        .to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(query).await?;
    stream.flush().await?;

    // Read length-prefixed response
    let resp_len = stream.read_u16().await? as usize;
    let mut buf = vec![0u8; resp_len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Build a [`reqwest::Client`] for DNS-over-HTTPS queries.
///
/// `resolves` pins each named DoH host to a fixed address, so a hostname-based
/// DoH URL connects to that IP instead of being resolved recursively.
#[cfg(with_crypto_provider)]
pub(super) fn build_https_client(
    tls_config: Option<&Arc<rustls::ClientConfig>>,
    resolves: &[(String, SocketAddr)],
) -> Result<reqwest::Client, DnsError> {
    let mut builder = reqwest::Client::builder();
    if let Some(config) = tls_config {
        builder = builder.use_preconfigured_tls(config.clone());
    }
    for (host, addr) in resolves {
        builder = builder.resolve(host, *addr);
    }
    Ok(builder.build().anyerr()?)
}

/// Send a DNS query over HTTPS (DNS-over-HTTPS, RFC 8484).
///
/// With `server_name`, the URL is addressed by hostname (the client pins it to
/// `addr`); without it the URL is addressed by IP (e.g.
/// `https://1.1.1.1/dns-query`), which works only for providers whose
/// certificates include the IP as a SAN.
#[cfg(with_crypto_provider)]
pub(super) async fn https_query(
    addr: SocketAddr,
    server_name: Option<&str>,
    query: &[u8],
    client: &reqwest::Client,
) -> Result<Vec<u8>, AnyError> {
    // With a server name, address the URL by hostname (the client pins it to
    // `addr`); otherwise address it by IP.
    let url = match server_name {
        Some(name) => format!("https://{name}:{}/dns-query", addr.port()),
        None => format!("https://{addr}/dns-query"),
    };
    let response = client
        .post(&url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(query.to_vec())
        .send()
        .await
        .anyerr()?;

    let bytes = response
        .error_for_status()
        .anyerr()?
        .bytes()
        .await
        .anyerr()?;
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use simple_dns::{
        CLASS, Name, Packet, PacketFlag, ResourceRecord, TYPE,
        rdata::{A, RData},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn build_a_response(id: u16, addrs: &[Ipv4Addr]) -> Vec<u8> {
        let mut packet = Packet::new_reply(id);
        packet.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
        for addr in addrs {
            let rdata = RData::A(A {
                address: u32::from(*addr),
            });
            packet.answers.push(ResourceRecord::new(
                Name::new_unchecked("example.com"),
                CLASS::IN,
                300,
                rdata,
            ));
        }
        packet.build_bytes_vec().unwrap()
    }

    /// Spawn a mock UDP server that echoes back an A response for any query.
    async fn mock_udp_server(addrs: &[Ipv4Addr]) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let addrs = addrs.to_vec();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (len, client_addr) = server.recv_from(&mut buf).await.unwrap();
            let id = Packet::parse(&buf[..len]).unwrap().id();
            server
                .send_to(&build_a_response(id, &addrs), client_addr)
                .await
                .unwrap();
        });
        (server_addr, handle)
    }

    /// Spawn a mock TCP server that echoes back an A response for any query.
    async fn mock_tcp_server(addrs: &[Ipv4Addr]) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let addrs = addrs.to_vec();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let query_len = stream.read_u16().await.unwrap() as usize;
            let mut query_buf = vec![0u8; query_len];
            stream.read_exact(&mut query_buf).await.unwrap();
            let id = Packet::parse(&query_buf).unwrap().id();
            let resp = build_a_response(id, &addrs);
            stream
                .write_all(&(resp.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&resp).await.unwrap();
            stream.flush().await.unwrap();
        });
        (server_addr, handle)
    }

    fn build_query() -> (u16, Vec<u8>) {
        super::super::query::build_query("example.com", TYPE::A).unwrap()
    }

    #[tokio::test]
    async fn test_udp_query() {
        let (addr, handle) = mock_udp_server(&[Ipv4Addr::new(93, 184, 216, 34)]).await;
        let (id, query) = build_query();
        let (addrs, _) =
            super::super::query::parse_a_response(&udp_query(addr, &query).await.unwrap(), id)
                .unwrap();
        assert_eq!(addrs, [Ipv4Addr::new(93, 184, 216, 34)]);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_query() {
        let (addr, handle) = mock_tcp_server(&[Ipv4Addr::new(93, 184, 216, 34)]).await;
        let (id, query) = build_query();
        let (addrs, _) =
            super::super::query::parse_a_response(&tcp_query(addr, &query).await.unwrap(), id)
                .unwrap();
        assert_eq!(addrs, [Ipv4Addr::new(93, 184, 216, 34)]);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_udp_multiple_records() {
        let expected = [
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            Ipv4Addr::new(9, 10, 11, 12),
        ];
        let (addr, handle) = mock_udp_server(&expected).await;
        let (id, query) = build_query();
        let (addrs, ttl) =
            super::super::query::parse_a_response(&udp_query(addr, &query).await.unwrap(), id)
                .unwrap();
        assert_eq!(addrs, expected);
        assert_eq!(ttl, 300);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_large_response() {
        let expected: Vec<Ipv4Addr> = (0..50).map(|i| Ipv4Addr::new(10, 0, 0, i)).collect();
        let (addr, handle) = mock_tcp_server(&expected).await;
        let (id, query) = build_query();
        let (addrs, _) =
            super::super::query::parse_a_response(&tcp_query(addr, &query).await.unwrap(), id)
                .unwrap();
        assert_eq!(addrs, expected);
        handle.await.unwrap();
    }
}
