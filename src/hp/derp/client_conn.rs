use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

use anyhow::Result;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::Receiver;
use tokio::sync::oneshot::Sender;

use crate::hp::key::node::PublicKey;

use super::client::ClientInfo;
use super::conn::Conn;
use super::{write_frame, FRAME_KEEP_ALIVE, FRAME_PEER_GONE, FRAME_PEER_PRESENT, FRAME_PONG};

type PacketReceiver = Receiver<Packet>;

/// A request to write a dataframe to a Client
struct Packet {
    /// The sender of the packet
    src: PublicKey,
    /// When a packet was put onto a queue before it was sent,
    /// and is used for reporting metrics on the duration of packets
    /// in the queue.
    enqueued_at: SystemTime,

    /// The data packet bytes.
    bytes: Bytes,
}

/// PeerConnState represents whether or not a peer is connected to the server.
struct PeerConnState {
    peer: PublicKey,
    present: bool,
}

#[derive(Debug)]
/// A client's connection to the servber
struct ClientConn<R, W, C>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    C: Conn,
{
    /// Static after construction, process-wide unique counter, incremented each Accept
    conn_num: i64,

    // TODO: in the go impl, we have a ptr to the server & use that ptr to update stats
    // in rust, we should probably have a stats struct separate from the server that we
    // can update in different threads
    // stats: Stats,
    conn: C,
    key: PublicKey,
    info: ClientInfo,
    /// Sent when connection closes
    // TODO: maybe should be a receiver
    done: Sender<()>,
    /// Usually ip:port from `SocketAddr`
    remote_addr: String,
    /// zero if remote_addr is not `ip:port`
    remote_ip_port: u16,
    /// Packets queued to this client
    send_queue: PacketReceiver,
    /// Important packets queued to this client
    disco_send_queue: PacketReceiver,
    /// Pong replies to send to the client,
    send_pong_ch: Receiver<[u8; 8]>,
    /// Write request that a previous sender has disconnected (not used by mesh peers)
    peer_gone: Receiver<PublicKey>,
    /// Write request to write `PEER_STATE_CHANGE`
    mesh_update: Receiver<()>,
    /// When true, the [`ClientInfo`] had the correct mesh token for inter-region routing
    can_mesh: bool,
    /// Whether more than 1 `ClientConn` for one key is connected
    is_dup: AtomicBool,
    /// Whether sends to this peer are disabled due to active/active dups
    is_disabled: AtomicBool,

    /// Controls how quickly two connections with the same client key can kick
    /// each other off the server by taking ownership of a key
    // TODO: replace with rate limiter
    replace_limiter: bool,

    reader: R,
    connected_at: SystemTime,
    preferred: bool,
    writer: W,
    //// Guarded by s.mu
    ////
    //// peerStateChange is used by mesh peers (a set of regional
    //// DERP servers) and contains records that need to be sent to
    //// the client for them to update their map of who's connected
    //// to this node.
    //peerStateChange []peerConnState
}

impl<R, W, C> ClientConn<R, W, C>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    C: Conn,
{
    fn set_preferred(&mut self, v: bool) {
        if self.preferred == v {
            return;
        }
        self.preferred = v;
        // TODO: stats
        // var homeMove *expvar.Int
        // if v {
        // 	c.s.curHomeClients.Add(1)
        // 	homeMove = &c.s.homeMovesIn
        // } else {
        // 	c.s.curHomeClients.Add(-1)
        // 	homeMove = &c.s.homeMovesOut
        // }

        // // Keep track of varz for home serve moves in/out.  But ignore
        // // the initial packet set when a client connects, which we
        // // assume happens within 5 seconds. In any case, just for
        // // graphs, so not important to miss a move. But it shouldn't:
        // // the netcheck/re-STUNs in magicsock only happen about every
        // // 30 seconds.
        // if time.Since(c.connectedAt) > 5*time.Second {
        // 	homeMove.Add(1)
        // }
    }

    // TODO: stats
    // // expMovingAverage returns the new moving average given the previous average,
    // // a new value, and an alpha decay factor.
    // // https://en.wikipedia.org/wiki/Moving_average#Exponential_moving_average
    // func expMovingAverage(prev, newValue, alpha float64) float64 {
    //   return alpha*newValue + (1-alpha)*prev
    // }

    // TODO: stats
    // // recordQueueTime updates the average queue duration metric after a packet has been sent.
    // func (c *sclient) recordQueueTime(enqueuedAt time.Time) {
    // elapsed := float64(time.Since(enqueuedAt).Milliseconds())
    // for {
    // old := atomic.LoadUint64(c.s.avgQueueDuration)
    // newAvg := expMovingAverage(math.Float64frombits(old), elapsed, 0.1)
    // if atomic.CompareAndSwapUint64(c.s.avgQueueDuration, old, math.Float64bits(newAvg)) {
    // break
    // }
    // }
    // }

    fn send_loop(&mut self) -> Result<()> {
        todo!();
    }

    // TODO: should probably wrap "sends" in a select w/ timeout instead of setting this, as it
    // doesn't seem to make sense in a rust context
    fn set_write_deadline(&mut self) {
        // error is ignored in golang impl
        let _ = self.conn.set_write_deadline(super::server::WRITE_TIMEOUT);
    }

    /// Send  `FRAME_KEEP_ALIVE`
    // go impl does not flush
    async fn send_keep_alive(&mut self) -> Result<()> {
        self.set_write_deadline();
        write_frame(&mut self.writer, FRAME_KEEP_ALIVE, vec![]).await
    }

    /// Send a `pong` frame
    // go impl does not flush
    async fn send_pong(&mut self, data: &[u8]) -> Result<()> {
        // TODO: stats
        // c.s.peerGoneFrames.Add(1)
        self.set_write_deadline();
        write_frame(&mut self.writer, FRAME_PONG, vec![data]).await
    }

    /// Sends a peer gone frame
    // go impl does not flush
    async fn send_peer_gone(&mut self, peer: PublicKey) -> Result<()> {
        // TODO: stats
        // c.s.peerGoneFrames.Add(1)
        self.set_write_deadline();
        write_frame(&mut self.writer, FRAME_PEER_GONE, vec![peer.as_bytes()]).await
    }

    /// Sends a peer present frame
    // go impl does not flush
    async fn send_peer_present(&mut self, peer: PublicKey) -> Result<()> {
        self.set_write_deadline();
        write_frame(&mut self.writer, FRAME_PEER_PRESENT, vec![peer.as_bytes()]).await
    }
}
