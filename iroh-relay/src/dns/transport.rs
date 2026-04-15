//! DNS transport implementations: UDP, TCP, TLS, and HTTPS.

use std::net::SocketAddr;
#[cfg(with_crypto_provider)]
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::DnsError;

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
pub(super) async fn udp_query(addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>, DnsError> {
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
pub(super) async fn tcp_query(addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>, DnsError> {
    let mut stream = tokio::net::TcpStream::connect(addr).await?;

    // Write length-prefixed query
    let len = (query.len() as u16).to_be_bytes();
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
/// **Limitation:** The server name for TLS SNI is derived from the IP address.
/// This works for public DNS providers that include IP SANs in their certificates
/// (e.g. Google 8.8.8.8, Cloudflare 1.1.1.1), but will fail TLS validation for
/// servers whose certificates only cover hostnames. A future improvement could
/// accept an optional hostname for SNI.
#[cfg(with_crypto_provider)]
pub(super) async fn tls_query(
    addr: SocketAddr,
    query: &[u8],
    tls_config: &Arc<rustls::ClientConfig>,
) -> Result<Vec<u8>, DnsError> {
    let connector = tokio_rustls::TlsConnector::from(tls_config.clone());
    let tcp_stream = tokio::net::TcpStream::connect(addr).await?;

    // Use the IP address as the server name for SNI.
    let server_name = rustls::pki_types::ServerName::IpAddress(addr.ip().into());
    let mut stream = connector.connect(server_name, tcp_stream).await?;

    // Write length-prefixed query (same framing as TCP)
    let len = (query.len() as u16).to_be_bytes();
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
#[cfg(with_crypto_provider)]
pub(super) fn build_https_client(
    tls_config: Option<&Arc<rustls::ClientConfig>>,
) -> Result<reqwest::Client, DnsError> {
    let mut builder = reqwest::Client::builder();
    if let Some(config) = tls_config {
        builder = builder.use_preconfigured_tls(config.clone());
    }
    Ok(builder.build()?)
}

/// Send a DNS query over HTTPS (DNS-over-HTTPS, RFC 8484).
///
/// **Limitation:** The URL is constructed from the IP address (e.g.
/// `https://1.1.1.1/dns-query`). This works for providers whose TLS
/// certificates include the IP address as a SAN, but will fail for servers
/// that only have hostname-based certificates. A future improvement could
/// accept an optional hostname for URL construction and TLS SNI.
#[cfg(with_crypto_provider)]
pub(super) async fn https_query(
    addr: SocketAddr,
    query: &[u8],
    client: &reqwest::Client,
) -> Result<Vec<u8>, DnsError> {
    let url = format!("https://{}/dns-query", addr);
    let response = client
        .post(&url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(query.to_vec())
        .send()
        .await?;

    let bytes = response.bytes().await?;
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
