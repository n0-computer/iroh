//! based on tailscale/derp/derp_server.go

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot::Receiver;

use crate::hp::key::node::{PublicKey, SecretKey};

use super::client::ClientInfo;
use super::conn::Conn;

// TODO: skiping `verboseDropKeys` for now

/// The number of packets buffered for sending
const PER_CLIENT_SEND_QUEUE_DEPTH: usize = 32;

pub(crate) const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// A temporary (2021-08-30) mechanism to change the policy
/// of how duplicate connections for the same key are handled.
#[derive(Debug)]
enum DupPolicy {
    /// A DupPolicy where the last connection to send traffic for a peer
    /// if the active one.
    LastWriterIsActive,
    /// A DupPolicy that detects if peers are trying to send traffic interleaved
    /// with each other and then disables all of them
    DisabledFighters,
}

#[derive(Debug)]
/// A DERP server.
pub struct Server<'a, C: Conn> {
    /// Optionally specifies how long to wait before failing when writing
    /// to a cliet
    write_timeout: Option<Duration>,
    secret_key: SecretKey,
    // TODO: what is this?
    /// "runtime.MemStats.Sys at start (or early-ish)
    mem_sys_0: u64,
    // TODO: this is a string in the go impl, I made it a standard length array
    // of bytes in this impl for ease of serializing. (Postcard cannot estimate
    // the size of the serialized struct if this field is a `String`). This should
    // be discussed and worked out.
    mesh_key: [u8; 32],
    /// the encoded x509 cert to send after `LetsEncrypt` cert+intermediate
    meta_cert: &'a [u8],
    dup_policy: DupPolicy,
    debug: bool,

    /// Counters:
    // TODO: this is the go impl, need to add this in
    // 	packetsSent, bytesSent       expvar.Int
    // packetsRecv, bytesRecv       expvar.Int
    // packetsRecvByKind            metrics.LabelMap
    // packetsRecvDisco             *expvar.Int
    // packetsRecvOther             *expvar.Int
    // _                            align64
    // packetsDropped               expvar.Int
    // packetsDroppedReason         metrics.LabelMap
    // packetsDroppedReasonCounters []*expvar.Int // indexed by dropReason
    // packetsDroppedType           metrics.LabelMap
    // packetsDroppedTypeDisco      *expvar.Int
    // packetsDroppedTypeOther      *expvar.Int
    // _                            align64
    // packetsForwardedOut          expvar.Int
    // packetsForwardedIn           expvar.Int
    // peerGoneFrames               expvar.Int // number of peer gone frames sent
    // gotPing                      expvar.Int // number of ping frames from client
    // sentPong                     expvar.Int // number of pong frames enqueued to client
    // accepts                      expvar.Int
    // curClients                   expvar.Int
    // curHomeClients               expvar.Int // ones with preferred
    // dupClientKeys                expvar.Int // current number of public keys we have 2+ connections for
    // dupClientConns               expvar.Int // current number of connections sharing a public key
    // dupClientConnTotal           expvar.Int // total number of accepted connections when a dup key existed
    // unknownFrames                expvar.Int
    // homeMovesIn                  expvar.Int // established clients announce home server moves in
    // homeMovesOut                 expvar.Int // established clients announce home server moves out
    // multiForwarderCreated        expvar.Int
    // multiForwarderDeleted        expvar.Int
    // removePktForwardOther        expvar.Int
    // avgQueueDuration             *uint64          // In milliseconds; accessed atomically
    // tcpRtt                       metrics.LabelMap // histogram

    /// When true, only accept client connections to the DERP server if the `client_key` is a
    /// known  peer in the network, as specified by a running "tailscaled's client's
    /// LocalAPI"
    verify_clients: bool,

    closed: AtomicBool,
    // TODO: how is this used, should it be a `Sender`?
    net_conns: HashMap<C, Receiver<()>>,
    clients: HashMap<PublicKey, ClientSet>,
    watchers: HashMap<ClientConn, bool>,
    /// Tracks all clients in the cluster, both locally and to mesh peers.
    /// If the value is nil, that means the peer is only local (And thus in
    /// the clients Map, but not remote). If the value is non-nil, it's remote
    /// (+ maybe also local).
    clients_mesh: HashMap<PublicKey, PacketForwarder>,
    /// Tracks which peers have sent to which other peers, and at which
    /// connection number. This isn't on sclient because it includes intra-region
    /// forwarded packets as the src.
    /// src => dst => dst's latest sclient.connNum
    sent_to: HashMap<PublicKey, HashMap<PublicKey, i64>>,

    /// Maps from netip.AddrPort to a client's public key
    key_of_addr: HashMap<SocketAddr, PublicKey>,
}

impl<'a, C> Server<'a, C>
where
    C: Conn,
{
    /// replace with builder
    pub fn new(key: SecretKey) -> Self {
        // TODO:
        todo!();
    }

    /// Reports whether the server is configured with a mesh key.
    pub fn has_mesh_key(&self) -> bool {
        !self.mesh_key.is_empty()
    }

    /// Returns the configured mesh key, may be empty.
    pub fn mesh_key(&self) -> [u8; 32] {
        self.mesh_key
    }

    /// Returns the server's private key.
    pub fn private_key(&self) -> SecretKey {
        self.secret_key.clone()
    }

    /// Returns the server's public key.
    pub fn public_key(&self) -> PublicKey {
        self.secret_key.verifying_key()
    }

    /// Closes the server and waits for the connections to disconnect.
    pub async fn close(self) {
        let closed = self.closed.load(Ordering::Relaxed);
        if closed {
            return;
        }
        self.closed.swap(true, Ordering::Relaxed);
        let mut closed_channels = Vec::new();

        for (net_conn, closed) in self.net_conns.into_iter() {
            match net_conn.close() {
                Ok(_) => closed_channels.push(closed),
                Err(e) => {
                    tracing::warn!("error closing connection {e:#?}")
                }
            }
        }

        for c in closed_channels.into_iter() {
            if let Err(e) = c.await {
                tracing::warn!("error while closing connection {e:#?}");
            }
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Reports whether the client with the specified key is connected.
    /// This is used in tests to verify that nodes are connected
    // TODO: we may not need this
    fn is_client_connected_for_test(&self, key: PublicKey) -> bool {
        todo!();
    }

    /// Adds a new connection to the server and serves it.
    ///
    /// The provided [`AsyncReader`] and [`AsyncWriter`] must be already connected to the [`Conn`].
    /// Accept blocks until the Server is closed or the connection closes on its own.
    ///
    /// Accept closes `conn`.
    pub fn accept<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        conn: C,
        reader: R,
        writer: W,
        remote_addr: String,
    ) -> Result<()> {
        todo!();
    }

    /// Initializes `Server::meta_cert` with a self-signed x509 cert
    /// encoding this server's public key and protocol version. "cmd/derp_server
    /// then sends this after the Let's Encrypt leaf + intermediate certs after
    /// the ServerHello (encrypted in TLS 1.3, not that is matters much).
    ///
    /// Then the client can save a round trime getting that and can start speaking
    /// DERP right away. (we don't use ALPN because that's sent in the clear and
    /// we're being paranoid to not look too weird to any middleboxes, given that
    /// DERP is an ultimate fallback path). But since the post-ServerHello certs
    /// are encrypted we can have the client also use them as a signal to be able
    /// to start speaking DERP right away, starting with its identity proof,
    /// encrypted to the server's public key.
    ///
    /// This RTT optimization fails where there's a corp-mandated TLS proxy with
    /// corp-mandated root certs on employee machines and TLS proxy cleans up
    /// unnecessary certs. In that case we jsut fall back to the extra RTT.
    fn init_meta_cert(&self) {
        todo!();
    }

    // Returns the server metadata cert that can be sent by the TLS server to
    // let the client skip a round trip during start-up.
    pub fn meta_cert(&self) -> &[u8] {
        self.meta_cert.clone()
    }

    /// Notes that client c is no authenticated and ready for packets.
    ///
    /// If `SCLient::key` is connected more than once, the earlier connection(s)
    /// are placed in a non-active state where we read from them (primarily to
    /// observe EOFs/timeouts) but won't send them frames on the assumption
    /// that they're dead.
    fn register_client(&mut self, client: ClientConn) {
        todo!();
    }

    /// Enqueues a message to all watchers (other DERP nodes in the region or
    /// trusted clients) that peer's presence changed.
    fn broadcast_peer_state_change(&mut self, peer: PublicKey, present: bool) {
        todo!();
    }

    /// Removes a client from the server
    fn unregister_client(&mut self, client: ClientConn) {
        todo!();
    }

    /// Sends [`PEER_GONE`] frames to parties that `key` has sent to previously
    /// (whether those sends were from a local client or forward). It must only
    /// be called after the key has been rmoved from `Server::clients_mesh`.
    fn not_peer_gone_from_region(&self, key: PublicKey) {
        todo!();
    }

    fn add_watcher(&self, client: ClientConn) {
        todo!();
    }

    fn accept_0<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &mut self,
        conn: C,
        reader: R,
        writer: W,
        remote_addr: String,
        conn_num: i64,
    ) -> Result<()> {
        todo!();
    }

    fn note_peer_send(&self, key: PublicKey, dst: ClientConn) {
        todo!();
    }

    fn record_drop(
        &self,
        packet_bytes: &[u8],
        srckey: PublicKey,
        dstkey: PublicKey,
        reason: DropReason,
    ) {
        todo!();
    }

    fn verify_client(&self, client_key: PublicKey, info: ClientInfo) -> Result<()> {
        todo!();
    }

    fn send_server_key<W: AsyncWrite + Unpin>(&self, writer: W) -> Result<()> {
        todo!();
    }

    fn note_client_activity(&self, client: ClientConn) {
        todo!();
    }

    fn send_server_info<W: AsyncWrite + Unpin>(
        &self,
        writer: W,
        client_key: PublicKey,
    ) -> Result<()> {
        todo!();
    }

    /// Reads the `FRAME_CLIENT_INFO` frame from the client (its proof of identity)
    /// upon it's initial connection. It should be considered especially untrusted
    /// at this point.
    fn recv_client_key<R: AsyncRead + Unpin>(&self, reader: R) -> Result<(PublicKey, ClientInfo)> {
        todo!();
    }

    fn recv_packet<R: AsyncRead + Unpin>(
        &self,
        reader: R,
        frame_len: usize,
    ) -> Result<(PublicKey, &[u8])> {
        todo!();
    }

    fn recv_forward_packet<R: AsyncRead + Unpin>(
        &self,
        reader: R,
        frame_len: usize,
    ) -> Result<(PublicKey, PublicKey, &[u8])> {
        todo!();
    }

    pub fn add_packet_forwarder(&self, dst: PublicKey, fwd: PacketForwarder) {
        todo!();
    }

    pub fn remove_packet_forwarder(&self, dst: PublicKey, fwd: PacketForwarder) {
        todo!();
    }

    pub fn consistency_check() -> Result<()> {
        todo!();
    }

    // fn serve_debug_traffic() {
    //     todo!();
    // }
}

#[derive(Debug)]
enum DropReason {
    /// Unknown destination PublicKey
    UnknownDest,
    /// Unkonwn destination PublicKey on a derp-forwarded packet
    UnknownDestOnFwd,
    /// Destination disconnected before we could send
    Gone,
    /// Destination queue is full, dropped packet at queue head
    QueueHead,
    /// Destination queue is full, dropped packet at queue tail
    QueueTail,
    /// OS write failed
    WriteError,
    /// The PublicKey is connected 2+ times (active/active, fighting)
    DupClient,
}

#[derive(Debug)]
struct ClientConn {}

#[derive(Debug)]
struct ClientSet {}

#[derive(Debug)]
pub struct PacketForwarder {}

#[derive(Serialize, Deserialize)]
pub(crate) struct ServerInfo {
    pub(crate) version: usize,
    pub(crate) token_bucket_bytes_per_second: usize,
    pub(crate) token_bucket_bytes_burst: usize,
}
