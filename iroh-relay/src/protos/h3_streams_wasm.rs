//! Browser WebTransport stream adapter for the relay protocol.
//!
//! The browser counterpart to [`h3_streams`](super::h3_streams). It carries each
//! relay message in one of three framings selected at runtime by the
//! [`WtTransferMode`] negotiated in the CONNECT handshake -- a fresh
//! unidirectional stream per message, one datagram per message, or a single
//! ordered uni stream carrying `[varint length][payload]` frames -- exactly like
//! the native path, but over the browser's native WebTransport session
//! ([`web_transport_wasm::Session`]) instead of raw noq streams.
//!
//! Unlike the native adapter, this one does not write the WebTransport stream
//! header or datagram Quarter-Stream-ID prefix itself: the browser's
//! WebTransport layer adds it when a uni stream or datagram is sent and strips it
//! on the receiving side, so we only ever see the payload (and, for the ordered
//! stream, our own length-prefixed frames).

use std::{
    cell::RefCell,
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes, BytesMut};
use n0_error::anyerr;
use n0_future::{Sink, Stream, ready};
use web_transport_proto as wt;
use web_transport_wasm::{RecvStream, SendStream, Session};

use super::streams::StreamError;
use crate::{ExportKeyingMaterial, MAX_PACKET_SIZE, WtTransferMode};

/// Maximum bytes to read from a single uni stream before rejecting.
const MAX_UNI_STREAM_SIZE: usize = MAX_PACKET_SIZE + 64;

type LocalFut<T> = Pin<Box<dyn Future<Output = T>>>;

/// The single persistent send stream for [`WtTransferMode::UniOrdered`], opened
/// lazily on first send. `Rc<RefCell<..>>` (wasm is single-threaded); a
/// per-message send future takes it out, uses it across awaits, and puts it back.
type OrderedSend = Rc<RefCell<Option<SendStream>>>;

/// The single persistent receive stream for [`WtTransferMode::UniOrdered`] plus
/// its leftover-bytes buffer (the browser hands us arbitrary chunks, so we
/// reassemble `[varint length][payload]` frames across them).
type OrderedRecv = Rc<RefCell<OrderedRecvState>>;

#[derive(Default)]
struct OrderedRecvState {
    stream: Option<RecvStream>,
    buf: BytesMut,
}

fn stream_err(err: web_transport_wasm::Error) -> StreamError {
    anyerr!("webtransport stream error: {err}")
}

/// Try to split one `[varint length][payload]` frame off the front of `buf`,
/// returning `Ok(None)` when more bytes are needed for a complete frame.
fn try_take_frame(buf: &mut BytesMut) -> Result<Option<Bytes>, StreamError> {
    let mut cursor: &[u8] = &buf[..];
    let before = cursor.len();
    let len = match wt::VarInt::decode(&mut cursor) {
        Ok(v) => v.into_inner() as usize,
        Err(_) => return Ok(None),
    };
    if len > MAX_UNI_STREAM_SIZE {
        return Err(anyerr!("ordered stream message exceeds max size"));
    }
    let header = before - cursor.len();
    if buf.len() < header + len {
        return Ok(None);
    }
    buf.advance(header);
    Ok(Some(buf.split_to(len).freeze()))
}

/// Relay transport over the browser's WebTransport session.
pub struct WtBytesFramed {
    session: Session,
    /// How relay messages are framed. Both ends agree on this via the CONNECT
    /// handshake, so the receiver reads the same framing the sender writes.
    mode: WtTransferMode,
    /// The single persistent send stream for [`WtTransferMode::UniOrdered`].
    ordered_send: OrderedSend,
    /// The single persistent receive stream for [`WtTransferMode::UniOrdered`].
    ordered_recv: OrderedRecv,
    pending_send: Option<Bytes>,
    send_fut: Option<LocalFut<Result<(), StreamError>>>,
    recv_fut: LocalFut<Result<Bytes, StreamError>>,
    recv_terminated: bool,
    send_priority: i32,
}

impl std::fmt::Debug for WtBytesFramed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WtBytesFramed").finish()
    }
}

impl WtBytesFramed {
    /// Create from an established browser WebTransport session and the negotiated
    /// framing (`mode`).
    pub fn new(session: Session, mode: WtTransferMode) -> Self {
        let ordered_recv: OrderedRecv = Rc::new(RefCell::new(OrderedRecvState::default()));
        let recv_fut = Box::pin(recv_one_message(session.clone(), mode, ordered_recv.clone()));
        Self {
            session,
            mode,
            ordered_send: Rc::new(RefCell::new(None)),
            ordered_recv,
            pending_send: None,
            send_fut: None,
            recv_fut,
            recv_terminated: false,
            send_priority: 0,
        }
    }

    /// Whether this transport carries relay messages as WebTransport datagrams
    /// (rather than unidirectional streams).
    pub fn uses_datagrams(&self) -> bool {
        self.mode == WtTransferMode::Datagrams
    }

    /// Switch to the negotiated framing before the data phase.
    ///
    /// The handshake always runs over per-message uni streams (the browser drops
    /// datagrams the server sends before the WebTransport session is fully
    /// established, so the relay challenge would be lost), so both ends construct
    /// the transport in that mode and call this to switch. Re-arms the pending
    /// receive with the new framing so the next message is read the same way it
    /// is sent.
    pub fn set_transfer_mode(&mut self, mode: WtTransferMode) {
        self.mode = mode;
        self.recv_fut = Box::pin(recv_one_message(
            self.session.clone(),
            mode,
            self.ordered_recv.clone(),
        ));
    }
}

impl ExportKeyingMaterial for WtBytesFramed {
    fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        _output: T,
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> Option<T> {
        // The browser WebTransport API does not expose TLS keying material, so
        // the relay handshake falls back to the challenge-response mechanism.
        None
    }
}

/// Receive one relay message in the negotiated framing. The browser has already
/// stripped the WebTransport stream header or datagram prefix, so we see only the
/// payload (or, for the ordered stream, our own length-prefixed frames).
async fn recv_one_message(
    session: Session,
    mode: WtTransferMode,
    ordered_recv: OrderedRecv,
) -> Result<Bytes, StreamError> {
    match mode {
        WtTransferMode::Datagrams => session.recv_datagram().await.map_err(stream_err),
        WtTransferMode::UniPerPacket => {
            let mut recv = session.accept_uni().await.map_err(stream_err)?;
            let mut out = BytesMut::new();
            while let Some(chunk) = recv.read(MAX_UNI_STREAM_SIZE).await.map_err(stream_err)? {
                out.extend_from_slice(&chunk);
                if out.len() > MAX_UNI_STREAM_SIZE {
                    return Err(anyerr!("uni stream exceeds max size"));
                }
            }
            Ok(out.freeze())
        }
        WtTransferMode::UniOrdered => recv_uni_ordered(session, ordered_recv).await,
    }
}

/// Receive one message from the single persistent [`WtTransferMode::UniOrdered`]
/// stream: accept it (once) and read successive `[varint length][payload]` frames
/// off it, buffering the browser's arbitrary chunk boundaries.
async fn recv_uni_ordered(
    session: Session,
    ordered_recv: OrderedRecv,
) -> Result<Bytes, StreamError> {
    // Take the state out so we do not hold the RefCell borrow across awaits; put
    // it back at the end. Sends/receives are serialized, so this never races.
    let mut state = std::mem::take(&mut *ordered_recv.borrow_mut());
    if state.stream.is_none() {
        state.stream = Some(session.accept_uni().await.map_err(stream_err)?);
    }
    let result = loop {
        match try_take_frame(&mut state.buf) {
            Ok(Some(msg)) => break Ok(msg),
            Err(e) => break Err(e),
            Ok(None) => {
                let stream = state.stream.as_mut().expect("stream just set");
                match stream.read(MAX_UNI_STREAM_SIZE).await.map_err(stream_err)? {
                    Some(chunk) => state.buf.extend_from_slice(&chunk),
                    None => break Err(anyerr!("ordered stream closed mid-frame")),
                }
            }
        }
    };
    *ordered_recv.borrow_mut() = state;
    result
}

/// Send one relay message in the negotiated framing. The browser adds the
/// WebTransport stream header or datagram prefix.
///
/// Datagrams are unreliable and browsers silently drop an over-size one per the
/// WebTransport spec (`web-transport-wasm`'s `Error` has no `TooLarge` variant),
/// so any surfaced error is simply propagated; iroh's own QUIC over the relay
/// retransmits a dropped packet.
async fn send_one_message(
    session: Session,
    mode: WtTransferMode,
    ordered_send: OrderedSend,
    priority: i32,
    payload: Bytes,
) -> Result<(), StreamError> {
    match mode {
        WtTransferMode::Datagrams => session.send_datagram(payload).await.map_err(stream_err),
        WtTransferMode::UniPerPacket => {
            let mut stream = session.open_uni().await.map_err(stream_err)?;
            stream.set_priority(priority);
            stream.write(&payload).await.map_err(stream_err)?;
            stream.finish().map_err(stream_err)?;
            Ok(())
        }
        WtTransferMode::UniOrdered => send_uni_ordered(session, ordered_send, payload).await,
    }
}

/// Send one message on the single persistent [`WtTransferMode::UniOrdered`]
/// stream: open it (once) and write successive `[varint length][payload]` frames.
/// The stream is never finished, so all messages stay ordered and reliable.
async fn send_uni_ordered(
    session: Session,
    ordered_send: OrderedSend,
    payload: Bytes,
) -> Result<(), StreamError> {
    let mut stream = ordered_send.borrow_mut().take();
    if stream.is_none() {
        let mut s = session.open_uni().await.map_err(stream_err)?;
        s.set_priority(1);
        stream = Some(s);
    }
    let s = stream.as_mut().expect("stream just set");
    let mut framed = BytesMut::with_capacity(8 + payload.len());
    wt::VarInt::from_u64(payload.len() as u64)
        .expect("relay message length fits in varint")
        .encode(&mut framed);
    framed.extend_from_slice(&payload);
    let result = s.write(&framed).await.map_err(stream_err);
    *ordered_send.borrow_mut() = stream;
    result
}

impl Stream for WtBytesFramed {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.recv_terminated {
            return Poll::Ready(None);
        }
        match ready!(this.recv_fut.as_mut().poll(cx)) {
            Ok(payload) => {
                this.recv_fut = Box::pin(recv_one_message(
                    this.session.clone(),
                    this.mode,
                    this.ordered_recv.clone(),
                ));
                Poll::Ready(Some(Ok(payload)))
            }
            Err(e) => {
                // The recv future has completed and is deliberately not re-armed.
                // Fuse the stream so a subsequent poll returns `None` instead of
                // re-polling a finished future, which would panic.
                this.recv_terminated = true;
                Poll::Ready(Some(Err(e)))
            }
        }
    }
}

impl Sink<Bytes> for WtBytesFramed {
    type Error = StreamError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();

        if let Some(fut) = this.send_fut.as_mut() {
            match ready!(fut.as_mut().poll(cx)) {
                Ok(()) => this.send_fut = None,
                Err(e) => {
                    this.send_fut = None;
                    return Poll::Ready(Err(e));
                }
            }
        }

        if let Some(msg) = this.pending_send.take() {
            let priority = this.send_priority;
            this.send_priority = this.send_priority.saturating_add(1);
            this.send_fut = Some(Box::pin(send_one_message(
                this.session.clone(),
                this.mode,
                this.ordered_send.clone(),
                priority,
                msg,
            )));
            return Pin::new(this).poll_ready(cx);
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
