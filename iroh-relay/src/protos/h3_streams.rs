//! WebTransport stream adapter for the relay protocol.
//!
//! [`WtBytesFramed`] carries each relay message in one of three framings,
//! selected at runtime by the [`WtTransferMode`] negotiated in the CONNECT
//! handshake:
//!
//! - [`UniPerPacket`](WtTransferMode::UniPerPacket): a fresh unidirectional
//!   stream per message (the default). Each stream carries the standard
//!   WebTransport uni-stream header `[StreamUni::WEBTRANSPORT][session_id]`
//!   followed by the payload and is finished, so the receiver reads to EOF;
//!   successive send streams get increasing priority so the QUIC scheduler
//!   prefers newer messages over retransmissions of older ones.
//! - [`Datagrams`](WtTransferMode::Datagrams): one QUIC datagram per message.
//!   Datagrams are unreliable and capped at the connection's path MTU, so an
//!   over-large one is dropped (iroh's own QUIC over the relay retransmits it).
//! - [`UniOrdered`](WtTransferMode::UniOrdered): a single long-lived uni stream
//!   per direction (the WT header once, then `[varint length][payload]` frames).
//!   Reliable and globally ordered, TCP-like.
//!
//! [`BytesStreamSink`]: super::streams::BytesStreamSink

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use n0_error::{StdResultExt, anyerr};
use n0_future::{Sink, Stream, ready};
use tokio::{
    io::{AsyncReadExt, BufReader},
    sync::Mutex,
};
use tokio_util::sync::ReusableBoxFuture;
use tracing::trace;
use web_transport_proto as wt;

use super::streams::StreamError;
use crate::{ExportKeyingMaterial, WtTransferMode};

/// The single long-lived send stream for [`WtTransferMode::UniOrdered`], opened
/// lazily on first send. Behind an async mutex so a fresh per-message send future
/// can reach it; sends are serialized by the [`Sink`], so it is never contended.
type OrderedSend = Arc<Mutex<Option<noq::SendStream>>>;

/// The single long-lived receive stream for [`WtTransferMode::UniOrdered`],
/// accepted lazily on first receive (its WebTransport header already consumed).
type OrderedRecv = Arc<Mutex<Option<BufReader<noq::RecvStream>>>>;

/// Maximum bytes to read from a single uni stream before rejecting.
const MAX_UNI_STREAM_SIZE: usize = crate::MAX_PACKET_SIZE + 64;

/// Packet-reordering threshold for the relay's H3/WebTransport QUIC connection.
///
/// QUIC (RFC 9002) declares a packet lost once this many later-numbered packets
/// have been acknowledged before it. The default of 3 is far too aggressive for
/// the reordering last-mile links relays sit behind: a wifi profile with a few
/// ms of jitter reorders many packets at bulk send rates (e.g. ~18 packets per
/// 2 ms at 100 Mbit), so at a threshold of 3 the connection declares a large
/// fraction of in-order packets lost *spuriously* and retransmits them --
/// measured at ~40-47% "loss" on a wifi profile with only 0.1% real loss, which
/// halves goodput and inflates RTT. TCP avoids this by adapting its reordering
/// window; QUIC's threshold is fixed. Raising it makes loss detection
/// effectively time-based (the 9/8-RTT time threshold still catches genuine
/// losses promptly), tolerating reordering the way the link requires.
pub(crate) const WT_REORDER_PACKET_THRESHOLD: u32 = 1000;

/// Time-reordering threshold for the relay's H3/WebTransport QUIC connection, a
/// multiple of the smoothed RTT (the time-domain counterpart of
/// [`WT_REORDER_PACKET_THRESHOLD`]).
///
/// QUIC also declares a packet lost once more than `threshold * RTT` has elapsed
/// since it was sent and a later packet was acknowledged. The default 9/8 is
/// tuned for links whose delay variation is small next to the RTT. On a low-RTT
/// link with a few ms of jitter that breaks: at an ~8ms hop RTT the 9/8
/// threshold is ~9ms, but 2ms of one-way jitter perturbs the RTT by a comparable
/// amount, so a reordered-but-not-lost packet trips the time threshold and is
/// retransmitted spuriously -- raising the packet-count threshold alone does not
/// prevent this. Widening the window to a few RTTs absorbs the jitter; genuinely
/// lost packets are still recovered by the probe timeout. Kept moderate (not
/// huge) so a genuine loss on a high-RTT link is not delayed excessively: at 2x
/// it still clears the wifi profile's jitter (a ~2ms one-way perturbation on an
/// ~8ms RTT) with margin.
pub(crate) const WT_REORDER_TIME_THRESHOLD: f32 = 2.0;

/// Environment variable that, when set, leaves the relay H3 connection's
/// congestion controller and reordering thresholds at the noq defaults instead
/// of applying the tuning in [`configure_relay_h3_transport`]. A benchmarking
/// knob to measure the tuning against a baseline; not for production use.
const DEFAULT_TRANSPORT_ENV: &str = "IROH_RELAY_H3_DEFAULT_TRANSPORT";

/// Configures the QUIC transport parameters for a relay H3/WebTransport
/// connection, shared by both ends of a relay hop -- the client (in
/// [`crate::client`]) and the server (in [`crate::server`]) -- so the two stay
/// in lockstep. The server additionally lowers its bidi-stream limit.
///
/// The uni-stream limit and MTU floor are always applied, as baseline
/// requirements: a high uni-stream limit so per-message uni streams never block
/// on credits, and a 1280-byte MTU floor so the datagram budget stays above
/// iroh's 1200-byte packet floor (before MTU discovery runs and after a
/// black-hole reset). See [`MAX_CONCURRENT_UNI_STREAMS`] and [`H3_MIN_MTU`].
///
/// The reordering thresholds are the loss/jitter tuning for the relay's
/// last-mile link: raised packet- and time-reordering thresholds so a jittery
/// link's reordering is not misread as loss. Without them, QUIC's fixed
/// thresholds declare a large fraction of in-order packets lost spuriously and
/// the reliable relay stream retransmits ~40% of its traffic, collapsing goodput
/// and inflating RTT. With them, the hop reaches WebSocket-level goodput while
/// keeping noq's default (Cubic) congestion controller -- the same loss-based
/// controller ws' TCP hop uses. Setting the [`DEFAULT_TRANSPORT_ENV`]
/// environment variable leaves both thresholds at the noq defaults instead.
pub(crate) fn configure_relay_h3_transport(config: &mut noq_proto::TransportConfig) {
    config.max_concurrent_uni_streams(MAX_CONCURRENT_UNI_STREAMS.into());
    config.min_mtu(H3_MIN_MTU).initial_mtu(H3_MIN_MTU);

    if std::env::var_os(DEFAULT_TRANSPORT_ENV).is_some() {
        return;
    }

    // The tuning is exactly this: raise QUIC's packet- and time-reordering
    // thresholds so a jittery last-mile link's reordering is not misread as loss.
    // Ablation (realistic wifi, wt-singlestream) shows these two together are the
    // whole win -- goodput 41 -> 126 Mbit (WebSocket parity), and neither alone
    // suffices (packet-only 77, time-only 43). Nothing else needs changing: the
    // congestion controller is left at noq's default (Cubic), the same loss-based
    // controller ws' TCP hop uses, which is what fills the link once spurious loss
    // is gone. (BBR3 was tried and collapses its cwnd on the tunnelled hop --
    // app-limited mis-sampling -- throttling goodput to ~half of ws.)
    config.packet_threshold(WT_REORDER_PACKET_THRESHOLD);
    config.time_threshold(WT_REORDER_TIME_THRESHOLD);
}

/// Concurrent unidirectional stream limit for the relay H3/WebTransport
/// connection.
///
/// In the per-message uni-stream mode every relayed message is a fresh uni
/// stream, so the number of streams in flight at once is the bandwidth-delay
/// product divided by the message size. Under high RTT and loss a stream stays
/// open until its FIN is acknowledged, which can take several round trips; at
/// the old 256-stream limit those lingering streams exhausted the credit window
/// and `open_uni` then blocked for *seconds* waiting for the peer to raise
/// MAX_STREAMS, backing up iroh's send path until its connection timed out. This
/// ceiling is set far above any realistic in-flight count so opening a new
/// stream never blocks on credits. The peer only allocates state for streams it
/// actually opens (bounded by the real in-flight count), so a high ceiling costs
/// nothing on a healthy connection.
pub(crate) const MAX_CONCURRENT_UNI_STREAMS: u32 = 100_000;

/// Minimum (and initial) path MTU for the relay's H3/WebTransport QUIC
/// connection.
///
/// In datagram framing each relayed message is a single QUIC DATAGRAM, whose
/// payload is capped at the connection's current path MTU minus QUIC framing
/// overhead (~38 bytes). The messages we carry are whole iroh QUIC packets, and
/// iroh -- like all QUIC -- never sends a packet below the 1200-byte minimum. At
/// QUIC's default MTU of 1200 the datagram budget is only ~1162, *below* that
/// 1200-byte floor, so every full-size iroh packet is dropped and the tunneled
/// connection cannot make progress.
///
/// This value is used as BOTH the initial MTU and the minimum MTU. The minimum
/// matters as much as the initial: QUIC's MTU black-hole detector resets the
/// path MTU down to `min_mtu` when it suspects the path shrank, and under a
/// datagram flood with a little loss that reset fires spuriously. If `min_mtu`
/// were left at the 1200 default, that reset would drop the datagram budget back
/// to ~1162 mid-transfer and re-break the tunnel. MTU discovery still probes
/// upward from here on capable paths.
///
/// Minimum value required, worst case:
///
/// ```text
///   datagram we send = prefix + iroh_packet   must fit   current_mtu - overhead
///     iroh_packet <= 1200   (iroh never sends below QUIC's minimum MTU)
///     prefix      <= 8       (Quarter-Stream-ID varint, 1..=8 bytes)
///     overhead     = 38      (QUIC DATAGRAM framing: measured, MTU 1200 -> budget 1162)
///   => current_mtu >= 1200 + 8 + 38 = 1246
/// ```
///
/// 1280 (the IPv6 minimum link MTU, RFC 8200) is the smallest standard value
/// clearing 1246: its datagram budget is 1280 - 38 = 1242, which carries iroh's
/// 1200-byte floor plus any prefix with room to spare. It is also guaranteed
/// deliverable on every IPv6 path, so pinning the floor there never breaks a
/// real relay connection. A path below 1280 cannot carry a minimum-size iroh
/// packet as a datagram at all; there the WebTransport connection is expected to
/// fail and the client falls back to WebSocket.
pub(crate) const H3_MIN_MTU: u16 = 1280;

/// Relay transport using one unidirectional QUIC stream per message.
///
/// Each message is sent on a fresh uni stream with a WT session header and
/// the raw payload. The receiver accepts uni streams and reads each to EOF.
/// This eliminates head-of-line blocking: retransmission on one stream does
/// not delay delivery of later messages on other streams.
pub struct WtBytesFramed {
    conn: noq::Connection,
    /// Precomputed WebTransport uni-stream header for this session, cloned per
    /// send. Unused in datagram mode.
    header: Bytes,
    /// Precomputed WebTransport datagram prefix (the CONNECT stream's Quarter
    /// Stream ID) for this session, cloned per send. Unused in uni-stream modes.
    dgram_prefix: Bytes,
    /// How relay messages are framed. Both ends agree on this via the CONNECT
    /// handshake, so the receiver reads the same framing the sender writes.
    mode: WtTransferMode,
    /// The single persistent send stream for [`WtTransferMode::UniOrdered`].
    ordered_send: OrderedSend,
    /// The single persistent receive stream for [`WtTransferMode::UniOrdered`].
    ordered_recv: OrderedRecv,
    pending_send: Option<Bytes>,
    send_fut: ReusableBoxFuture<'static, Result<(), StreamError>>,
    recv_fut: ReusableBoxFuture<'static, Result<Bytes, StreamError>>,
    recv_terminated: bool,
    send_busy: bool,
    send_priority: i32,
}

impl std::fmt::Debug for WtBytesFramed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WtBytesFramed").finish()
    }
}

impl WtBytesFramed {
    /// Create from a QUIC connection, the WebTransport session ID, and the
    /// negotiated framing (`mode`).
    pub fn new(conn: noq::Connection, session_id: u64, mode: WtTransferMode) -> Self {
        let recv_conn = conn.clone();
        let ordered_recv: OrderedRecv = Arc::new(Mutex::new(None));
        Self {
            conn,
            header: encode_wt_header(session_id).freeze(),
            dgram_prefix: encode_wt_datagram_prefix(session_id),
            mode,
            ordered_send: Arc::new(Mutex::new(None)),
            recv_fut: ReusableBoxFuture::new(recv_one_message(
                recv_conn,
                mode,
                ordered_recv.clone(),
            )),
            ordered_recv,
            pending_send: None,
            send_fut: ReusableBoxFuture::new(std::future::pending()),
            recv_terminated: false,
            send_busy: false,
            send_priority: 0,
        }
    }

    /// Whether this transport carries relay messages as QUIC datagrams (rather
    /// than unidirectional streams). The relay actor uses this to decide whether
    /// to split GSO batches into one datagram per packet; only datagram framing
    /// needs it, since the stream framings carry an arbitrarily large batch whole.
    pub fn uses_datagrams(&self) -> bool {
        self.mode == WtTransferMode::Datagrams
    }

    /// Switch to the negotiated framing before the data phase.
    ///
    /// The handshake always runs over per-message uni streams
    /// ([`WtTransferMode::UniPerPacket`]; a peer may drop datagrams sent before
    /// the WebTransport session is fully established), so both ends construct the
    /// transport in that mode and call this to switch. Re-arms the pending receive
    /// with the new framing so the next message is read the same way it is sent.
    pub fn set_transfer_mode(&mut self, mode: WtTransferMode) {
        self.mode = mode;
        let recv_conn = self.conn.clone();
        self.recv_fut
            .set(recv_one_message(recv_conn, mode, self.ordered_recv.clone()));
    }
}

/// Encode the WebTransport unidirectional stream header for the given session ID.
///
/// This is the standard WebTransport uni-stream framing: the
/// [`StreamUni::WEBTRANSPORT`](wt::StreamUni::WEBTRANSPORT) stream type followed
/// by the session ID. A real browser writes exactly this header in front of
/// every uni stream it opens, and only recognises incoming uni streams that
/// carry it, so the server must use it too for browser interop.
fn encode_wt_header(session_id: u64) -> BytesMut {
    let mut hdr = BytesMut::with_capacity(16);
    wt::StreamUni::WEBTRANSPORT.encode(&mut hdr);
    wt::VarInt::from_u64(session_id)
        .expect("session ID fits in varint")
        .encode(&mut hdr);
    hdr
}

/// Encode the WebTransport datagram prefix for the given session ID.
///
/// A WebTransport datagram is framed on the wire as `[Quarter-Stream-ID
/// varint][payload]`, where the Quarter Stream ID is the session's CONNECT
/// stream ID divided by four. A browser's QUIC stack adds and strips this prefix
/// transparently, so raw noq datagrams (which carry no prefix) must add it
/// explicitly to interoperate with a browser peer and to stay symmetric with
/// another native peer that does the same.
fn encode_wt_datagram_prefix(session_id: u64) -> Bytes {
    let mut buf = BytesMut::with_capacity(8);
    wt::VarInt::from_u64(session_id / 4)
        .expect("quarter stream ID fits in varint")
        .encode(&mut buf);
    buf.freeze()
}

/// Strip the WebTransport datagram prefix (see [`encode_wt_datagram_prefix`]),
/// returning the payload.
fn decode_wt_datagram_prefix(mut dgram: Bytes) -> Result<Bytes, StreamError> {
    // `Bytes` implements `Buf`, so decoding advances past the varint prefix and
    // leaves `dgram` holding the payload.
    wt::VarInt::decode(&mut dgram).anyerr()?;
    Ok(dgram)
}

impl ExportKeyingMaterial for WtBytesFramed {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        mut output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Option<T> {
        self.conn
            .export_keying_material(output.as_mut(), label, context.unwrap_or(&[]))
            .ok()?;
        Some(output)
    }
}

impl ExportKeyingMaterial for noq::Connection {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        mut output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Option<T> {
        noq::Connection::export_keying_material(
            self,
            output.as_mut(),
            label,
            context.unwrap_or(&[]),
        )
        .ok()?;
        Some(output)
    }
}

/// Accept a WebTransport uni stream, skip its header, and read the payload.
///
/// Each relay message arrives on its own uni stream prefixed with the
/// [`StreamUni::WEBTRANSPORT`](wt::StreamUni::WEBTRANSPORT) type and the session
/// ID (see [`encode_wt_header`]). A real browser also opens HTTP/3 control and
/// QPACK unidirectional streams on the same connection; those are drained and
/// kept alive in the background so their (critical) streams are not reset, and
/// we keep accepting until an actual WebTransport stream arrives.
async fn recv_one_message(
    conn: noq::Connection,
    mode: WtTransferMode,
    ordered_recv: OrderedRecv,
) -> Result<Bytes, StreamError> {
    match mode {
        WtTransferMode::Datagrams => {
            let dgram = conn.read_datagram().await.anyerr()?;
            decode_wt_datagram_prefix(dgram)
        }
        WtTransferMode::UniPerPacket => {
            let recv = accept_wt_uni(&conn).await?;
            let mut payload = Vec::new();
            recv.take(MAX_UNI_STREAM_SIZE as u64 + 1)
                .read_to_end(&mut payload)
                .await
                .anyerr()?;
            if payload.len() > MAX_UNI_STREAM_SIZE {
                return Err(anyerr!("uni stream exceeds max size"));
            }
            Ok(Bytes::from(payload))
        }
        WtTransferMode::UniOrdered => recv_uni_ordered(&conn, &ordered_recv).await,
    }
}

/// Accept the next WebTransport unidirectional stream on `conn`, consuming its
/// header (`[StreamUni::WEBTRANSPORT][session_id]`) and returning the stream
/// positioned at the payload.
///
/// A real browser also opens HTTP/3 control and QPACK unidirectional streams on
/// the same connection; those are drained and kept alive in the background so
/// their (critical) streams are not reset, and we keep accepting until an actual
/// WebTransport stream arrives.
async fn accept_wt_uni(conn: &noq::Connection) -> Result<BufReader<noq::RecvStream>, StreamError> {
    loop {
        let recv = conn.accept_uni().await.anyerr()?;
        let mut recv = BufReader::new(recv);
        let stream_type = wt::VarInt::read(&mut recv).await.anyerr()?;
        if stream_type != wt::StreamUni::WEBTRANSPORT.0 {
            trace!(stream_type = %stream_type, "ignoring non-WebTransport uni stream");
            drain_in_background(recv);
            continue;
        }
        // Skip the session ID; we serve a single WebTransport session per
        // connection, so there is nothing to demultiplex.
        let _session_id = wt::VarInt::read(&mut recv).await.anyerr()?;
        return Ok(recv);
    }
}

/// Receive one message from the single persistent [`WtTransferMode::UniOrdered`]
/// stream: accept it (once) and then read successive `[varint length][payload]`
/// frames from it.
async fn recv_uni_ordered(
    conn: &noq::Connection,
    ordered_recv: &OrderedRecv,
) -> Result<Bytes, StreamError> {
    let mut guard = ordered_recv.lock().await;
    if guard.is_none() {
        *guard = Some(accept_wt_uni(conn).await?);
    }
    let recv = guard.as_mut().expect("stream just set");
    let len = wt::VarInt::read(recv).await.anyerr()?.into_inner();
    if len > MAX_UNI_STREAM_SIZE as u64 {
        return Err(anyerr!("ordered stream message exceeds max size"));
    }
    let mut payload = vec![0u8; len as usize];
    recv.read_exact(&mut payload).await.anyerr()?;
    Ok(Bytes::from(payload))
}

/// Read and discard the rest of a receive stream in a detached task, holding it
/// open until it finishes or the connection closes.
///
/// Shared with the H3 server, which drains the browser's HTTP/3 control and
/// QPACK uni streams the same way.
pub(crate) fn drain_in_background<R>(mut reader: R)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::task::spawn(async move {
        let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
    });
}

/// Send one relay message in the negotiated framing.
///
/// `header` is the per-connection WebTransport uni-stream header and
/// `dgram_prefix` the per-connection datagram Quarter-Stream-ID prefix, both
/// precomputed once (see [`WtBytesFramed::new`]) and cheaply cloned per message;
/// each is unused in the framings that do not need it.
#[allow(clippy::too_many_arguments)]
async fn send_one_message(
    conn: noq::Connection,
    header: Bytes,
    dgram_prefix: Bytes,
    mode: WtTransferMode,
    ordered_send: OrderedSend,
    priority: i32,
    payload: Bytes,
) -> Result<(), StreamError> {
    match mode {
        WtTransferMode::Datagrams => send_datagram(&conn, &dgram_prefix, payload),
        WtTransferMode::UniPerPacket => {
            let mut stream = conn.open_uni().await.anyerr()?;
            let _ = stream.set_priority(priority);
            // Write the WT header and payload in one batched, zero-copy call.
            let mut chunks = [header, payload];
            stream.write_all_chunks(&mut chunks).await.anyerr()?;
            stream.finish().anyerr()?;
            Ok(())
        }
        WtTransferMode::UniOrdered => send_uni_ordered(&conn, &header, &ordered_send, payload).await,
    }
}

/// Send one relay message as a single QUIC datagram.
///
/// Datagrams are unreliable by design, and a relayed iroh packet plus framing can
/// exceed the WebTransport connection's max datagram size on a small-MTU path. A
/// `TooLarge` datagram is dropped -- iroh's own QUIC connection running over the
/// relay retransmits it and its PLPMTUD backs off -- rather than surfaced as a
/// fatal error that would tear the relay connection down and reconnect.
fn send_datagram(
    conn: &noq::Connection,
    dgram_prefix: &Bytes,
    payload: Bytes,
) -> Result<(), StreamError> {
    // Prepend the Quarter-Stream-ID prefix so the datagram matches the
    // WebTransport wire framing a browser peer produces and expects.
    let mut datagram = BytesMut::with_capacity(dgram_prefix.len() + payload.len());
    datagram.extend_from_slice(dgram_prefix);
    datagram.extend_from_slice(&payload);
    let dgram_len = datagram.len();
    match conn.send_datagram(datagram.freeze()) {
        Ok(()) => Ok(()),
        Err(noq::SendDatagramError::TooLarge) => {
            trace!(
                dgram_len,
                max = ?conn.max_datagram_size(),
                "dropping too-large relay datagram; iroh QUIC will retransmit"
            );
            Ok(())
        }
        Err(err) => Err(anyerr!(err)),
    }
}

/// Send one relay message on the single persistent [`WtTransferMode::UniOrdered`]
/// stream: open it (once, writing the WebTransport header) and then write
/// successive `[varint length][payload]` frames on it. The stream is never
/// finished, so all messages stay ordered and reliable on one QUIC stream.
async fn send_uni_ordered(
    conn: &noq::Connection,
    header: &Bytes,
    ordered_send: &OrderedSend,
    payload: Bytes,
) -> Result<(), StreamError> {
    let mut guard = ordered_send.lock().await;
    if guard.is_none() {
        let mut stream = conn.open_uni().await.anyerr()?;
        // Higher priority than per-message streams' default so the ordered data
        // stream is scheduled ahead of any stray control streams.
        let _ = stream.set_priority(1);
        stream.write_all_chunks(&mut [header.clone()]).await.anyerr()?;
        *guard = Some(stream);
    }
    let stream = guard.as_mut().expect("stream just set");
    let mut len_prefix = BytesMut::with_capacity(8);
    wt::VarInt::from_u64(payload.len() as u64)
        .expect("relay message length fits in varint")
        .encode(&mut len_prefix);
    let mut chunks = [len_prefix.freeze(), payload];
    stream.write_all_chunks(&mut chunks).await.anyerr()?;
    Ok(())
}

// -- Stream: accept uni streams, read each to EOF -----------------------------

impl Stream for WtBytesFramed {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if this.recv_terminated {
            return Poll::Ready(None);
        }

        match ready!(this.recv_fut.poll(cx)) {
            Ok(payload) => {
                // Immediately set up the next recv.
                let conn = this.conn.clone();
                this.recv_fut
                    .set(recv_one_message(conn, this.mode, this.ordered_recv.clone()));
                // The relay protocol never frames an empty message, so an empty
                // payload is malformed. Yield it and let the frame decoder reject
                // it; returning `Pending` here would strand the stream, since the
                // freshly armed `recv_fut` has not been polled to register a waker.
                Poll::Ready(Some(Ok(payload)))
            }
            Err(e) => {
                // Connection closed or error. The recv future has completed and
                // is deliberately not re-armed; fuse the stream so a later poll
                // returns `None` instead of re-polling a finished future.
                this.recv_terminated = true;
                Poll::Ready(Some(Err(e)))
            }
        }
    }
}

// -- Sink: new uni stream per message -----------------------------------------

impl Sink<Bytes> for WtBytesFramed {
    type Error = StreamError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();

        // Flush in-progress send.
        if this.send_busy {
            match ready!(this.send_fut.poll(cx)) {
                Ok(()) => {
                    this.send_busy = false;
                }
                Err(e) => {
                    this.send_busy = false;
                    return Poll::Ready(Err(e));
                }
            }
        }

        // Start sending a pending message.
        if let Some(msg) = this.pending_send.take() {
            let conn = this.conn.clone();
            let header = this.header.clone();
            let dgram_prefix = this.dgram_prefix.clone();
            let priority = this.send_priority;
            let mode = this.mode;
            let ordered_send = this.ordered_send.clone();
            this.send_priority = this.send_priority.saturating_add(1);
            this.send_fut.set(send_one_message(
                conn,
                header,
                dgram_prefix,
                mode,
                ordered_send,
                priority,
                msg,
            ));
            this.send_busy = true;
            let pin = Pin::new(this);
            return pin.poll_ready(cx);
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        self.get_mut().pending_send = Some(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_ready(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_ready(cx)?);
        Poll::Ready(Ok(()))
    }
}
