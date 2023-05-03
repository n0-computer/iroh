//! The client side API
//!
//! The main entry point is [`run`]. This function takes callbacks that will
//! be invoked when blobs or collections are received. It is up to the caller
//! to store the received data.
use std::error::Error;
use std::fmt::{self, Debug};
use std::io::{self, Cursor, SeekFrom};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::blobs::Collection;
use crate::protocol::{write_lp, AuthToken, Handshake, RangeSpecSeq, Request};
use crate::provider::Ticket;
use crate::subnet::{same_subnet_v4, same_subnet_v6};
use crate::tls::{self, Keypair, PeerId};
use crate::tokio_util::{SeekOptimized, TrackingReader, TrackingWriter};
use crate::IROH_BLOCK_SIZE;
use anyhow::{anyhow, Context, Result};
use bao_tree::io::error::DecodeError;
use bao_tree::io::tokio::DecodeResponseStreamRef;
use bao_tree::io::DecodeResponseItem;
use bao_tree::outboard::PreOrderMemOutboard;
use bao_tree::{BaoTree, ByteNum, ChunkNum};
use bytes::BytesMut;
use default_net::Interface;
use futures::{Future, StreamExt};
use postcard::experimental::max_size::MaxSize;
use quinn::RecvStream;
use range_collections::RangeSet2;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, debug_span, error};
use tracing_futures::Instrument;

pub use crate::util::Hash;

/// Options for the client
#[derive(Clone, Debug)]
pub struct Options {
    /// The address to connect to
    pub addr: SocketAddr,
    /// The peer id to expect
    pub peer_id: Option<PeerId>,
    /// Whether to log the SSL keys when `SSLKEYLOGFILE` environment variable is set.
    pub keylog: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            addr: "127.0.0.1:4433".parse().unwrap(),
            peer_id: None,
            keylog: false,
        }
    }
}

/// Create a quinn client endpoint
pub fn make_client_endpoint(
    bind_addr: SocketAddr,
    peer_id: Option<PeerId>,
    alpn_protocols: Vec<Vec<u8>>,
    keylog: bool,
) -> Result<quinn::Endpoint> {
    let keypair = Keypair::generate();

    let tls_client_config = tls::make_client_config(&keypair, peer_id, alpn_protocols, keylog)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(tls_client_config));
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(1)));
    client_config.transport_config(Arc::new(transport_config));

    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Establishes a QUIC connection to the provided peer.
pub async fn dial_peer(opts: Options) -> Result<quinn::Connection> {
    let bind_addr = match opts.addr.is_ipv6() {
        true => SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0).into(),
        false => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into(),
    };
    let endpoint =
        make_client_endpoint(bind_addr, opts.peer_id, vec![tls::P2P_ALPN.to_vec()], false)?;

    debug!("connecting to {}", opts.addr);
    let connect = endpoint.connect(opts.addr, "localhost")?;
    let connection = connect.await.context("failed connecting to provider")?;

    Ok(connection)
}

/// Stats about the transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stats {
    /// The number of bytes written
    pub bytes_written: u64,
    /// The number of bytes read
    pub bytes_read: u64,
    /// The time it took to transfer the data
    pub elapsed: Duration,
}

impl Stats {
    /// Transfer rate in megabits per second
    pub fn mbits(&self) -> f64 {
        let data_len_bit = self.bytes_read * 8;
        data_len_bit as f64 / (1000. * 1000.) / self.elapsed.as_secs_f64()
    }
}

/// Gets a collection and all its blobs using a [`Ticket`].
pub async fn run_ticket<A, C, FutA, FutC, U>(
    ticket: &Ticket,
    request: Request,
    keylog: bool,
    max_concurrent: u8,
    on_connected: A,
    on_blob: C,
    user: U,
) -> Result<(U, Stats)>
where
    A: FnOnce() -> FutA,
    FutA: Future<Output = Result<()>>,
    C: FnMut(OnBlobData<U>) -> FutC,
    FutC: Future<Output = Result<OnBlobResult<U>>>,
{
    let span = debug_span!("get", hash=%ticket.hash());
    async move {
        let connection = dial_ticket(ticket, keylog, max_concurrent.into()).await?;
        let span = debug_span!("connection", remote_addr=%connection.remote_address());
        run_connection(
            connection,
            request,
            ticket.token(),
            on_connected,
            on_blob,
            user,
        )
        .instrument(span)
        .await
    }
    .instrument(span)
    .await
}

async fn dial_ticket(
    ticket: &Ticket,
    keylog: bool,
    max_concurrent: usize,
) -> Result<quinn::Connection> {
    // Sort the interfaces to make sure local ones are at the front of the list.
    let interfaces = default_net::get_interfaces();
    let (mut addrs, other_addrs) = ticket
        .addrs()
        .iter()
        .partition::<Vec<_>, _>(|addr| is_same_subnet(addr, &interfaces));
    addrs.extend(other_addrs);

    let mut conn_stream = futures::stream::iter(addrs)
        .map(|addr| {
            let opts = Options {
                addr,
                peer_id: Some(ticket.peer()),
                keylog,
            };
            dial_peer(opts)
        })
        .buffer_unordered(max_concurrent);
    while let Some(res) = conn_stream.next().await {
        match res {
            Ok(conn) => return Ok(conn),
            Err(_) => continue,
        }
    }
    Err(anyhow!("Failed to establish connection to peer"))
}

fn is_same_subnet(addr: &SocketAddr, interfaces: &[Interface]) -> bool {
    for interface in interfaces {
        match addr {
            SocketAddr::V4(peer_addr) => {
                for net in interface.ipv4.iter() {
                    if same_subnet_v4(net.addr, *peer_addr.ip(), net.prefix_len) {
                        return true;
                    }
                }
            }
            SocketAddr::V6(peer_addr) => {
                for net in interface.ipv6.iter() {
                    if same_subnet_v6(net.addr, *peer_addr.ip(), net.prefix_len) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Get a collection and all its blobs from a provider
pub async fn run<A, C, FutA, FutC, U>(
    request: Request,
    auth_token: AuthToken,
    opts: Options,
    on_connected: A,
    on_blob: C,
    user: U,
) -> Result<(U, Stats)>
where
    A: FnOnce() -> FutA,
    FutA: Future<Output = Result<()>>,
    C: FnMut(OnBlobData<U>) -> FutC,
    FutC: Future<Output = Result<OnBlobResult<U>>>,
{
    let span = debug_span!("get", %request.hash);
    async move {
        let connection = dial_peer(opts).await?;
        let span = debug_span!("connection", remote_addr=%connection.remote_address());
        run_connection(connection, request, auth_token, on_connected, on_blob, user)
            .instrument(span)
            .await
    }
    .instrument(span)
    .await
}

/// State that gets threaded through each async on_blob call.
///
/// This is guaranteed to be accessed sequentially, and therefore does not need
/// to be synchronized. This state includes the (hidden) quinn RecvStream as well
/// as custom user-provided state.
#[derive(Debug)]
pub struct OnBlobData<T> {
    /// the offset of the current blob. 0 is for the item itself (the collection)
    offset: u64,
    /// the total size of the blob
    size: u64,
    /// the ranges we requested
    ranges: RangeSet2<ChunkNum>,
    /// out: limit on the collection
    limit: Option<u64>,
    /// check if the blob was consumed
    completed: bool,
    /// the reader for the encoded range
    reader: TrackingReader<RecvStream>,
    /// user data
    pub user: T,
}

///
#[derive(Debug)]
pub struct OnBlobResult<T> {
    reader: TrackingReader<RecvStream>,
    user: T,
    limit: Option<u64>,
}

impl<U> OnBlobData<U> {
    /// the offset of the current blob. 0 is for the item itself (the collection)
    /// child offsets start with 1
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// the total size of the blob
    pub fn size(&self) -> u64 {
        self.size
    }

    /// true if this is the root blob
    pub fn is_root(&self) -> bool {
        self.offset == 0
    }

    ///
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = Some(limit)
    }

    /// child offset
    pub fn child_offset(&self) -> Option<u64> {
        self.offset.checked_sub(1)
    }

    /// the bao tree for this blob
    pub fn tree(&self) -> BaoTree {
        BaoTree::new(ByteNum(self.size), IROH_BLOCK_SIZE)
    }

    /// Read the entire blob into a `Vec<u8>`
    ///
    /// Make sure to check the size of the blob before calling this.
    pub async fn read_blob(&mut self, hash: Hash) -> anyhow::Result<Vec<u8>> {
        let mut target = Vec::new();
        self.write_all(hash, Cursor::new(&mut target)).await?;
        Ok(target)
    }

    /// Read the entire blob into a `Vec<u8>` and then decode it as a Collection
    pub async fn read_collection(&mut self, hash: Hash) -> anyhow::Result<Collection> {
        let data = self.read_blob(hash).await?;
        Collection::from_bytes(&data)
    }

    /// The ranges we requested
    pub fn ranges(&self) -> &RangeSet2<ChunkNum> {
        &self.ranges
    }

    /// End working with the blob
    pub fn end(self) -> anyhow::Result<OnBlobResult<U>> {
        anyhow::ensure!(self.completed, "blob was not fully consumed or drained");
        Ok(OnBlobResult {
            reader: self.reader,
            user: self.user,
            limit: self.limit,
        })
    }

    /// for testing
    #[cfg(test)]
    pub fn end_unchecked(self) -> anyhow::Result<OnBlobResult<U>> {
        Ok(OnBlobResult {
            reader: self.reader,
            user: self.user,
            limit: self.limit,
        })
    }

    /// Shortcut for `write_all_with_outboard` where outboard is None
    pub async fn write_all<O>(
        &mut self,
        hash: Hash,
        target: O,
    ) -> std::result::Result<(), DecodeError>
    where
        O: AsyncWrite + AsyncSeek + Unpin,
    {
        self.write_all_with_outboard::<O, O, _>(hash, target, None, |_, _| {})
            .await
    }

    fn stream(&mut self, hash: Hash) -> DecodeResponseStreamRef<&mut TrackingReader<RecvStream>> {
        DecodeResponseStreamRef::new_with_tree(
            hash.into(),
            self.tree(),
            &self.ranges,
            &mut self.reader,
        )
    }

    /// Just validate and drain the stream
    pub async fn drain(&mut self, hash: Hash) -> std::result::Result<(), DecodeError> {
        if self.completed {
            return Err(DecodeError::Io(io::Error::new(
                io::ErrorKind::Other,
                "already completed",
            )));
        }
        let mut stream = self.stream(hash);
        while let Some(msg) = stream.next().await {
            msg?;
        }
        drop(stream);
        self.completed = true;
        Ok(())
    }

    /// concatenate all the data into a single writer
    pub async fn concatenate<W, OW>(
        &mut self,
        hash: Hash,
        mut target: W,
        mut on_write: OW,
    ) -> std::result::Result<(), DecodeError>
    where
        W: AsyncWrite + Unpin,
        OW: FnMut(u64, usize),
    {
        if self.completed {
            return Err(DecodeError::Io(io::Error::new(
                io::ErrorKind::Other,
                "already completed",
            )));
        }
        let mut stream = self.stream(hash);
        while let Some(chunk) = stream.next().await {
            if let DecodeResponseItem::Leaf(leaf) = chunk? {
                on_write(leaf.offset.0, leaf.data.len());
                target.write_all(&leaf.data).await?;
            }
        }
        drop(stream);
        self.completed = true;
        Ok(())
    }

    /// write all the data to a file or buffer
    ///
    /// `target` is the main file
    /// `outboard` is an optional outboard file
    /// `on_write` is a callback for writes, e.g. to update a progress bar
    pub async fn write_all_with_outboard<T, O, OW>(
        &mut self,
        hash: Hash,
        target: T,
        outboard: Option<O>,
        mut on_write: OW,
    ) -> std::result::Result<(), DecodeError>
    where
        T: AsyncWrite + AsyncSeek + Unpin,
        O: AsyncWrite + AsyncSeek + Unpin,
        OW: FnMut(u64, usize),
    {
        if self.completed {
            return Err(DecodeError::Io(io::Error::new(
                io::ErrorKind::Other,
                "already completed",
            )));
        }
        let mut target = SeekOptimized::new(target);
        let mut outboard = outboard.map(SeekOptimized::new);
        let tree = self.tree();
        let mut reader = DecodeResponseStreamRef::new_with_tree(
            hash.into(),
            tree,
            &self.ranges,
            &mut self.reader,
        );
        if let Some(outboard) = outboard.as_mut() {
            outboard.seek(SeekFrom::Start(0)).await?;
            outboard.write_all(&self.size.to_le_bytes()).await?;
        }
        while let Some(item) = reader.next().await {
            match item? {
                DecodeResponseItem::Header { .. } => {
                    // we already read the header
                    unreachable!()
                }
                DecodeResponseItem::Parent(bao_tree::io::Parent {
                    node,
                    pair: (l_hash, r_hash),
                }) => {
                    let offset = tree.pre_order_offset(node).unwrap();
                    let byte_offset = offset * 64 + 8;
                    if let Some(outboard) = outboard.as_mut() {
                        // due to tokio, we need to call flush before seeking, or else
                        // the call to start_seek will fail with "other file operation is pending".
                        //
                        // Just because a tokio write returns Ready(Ok(())) does not mean that the
                        // underlying write has completed.
                        outboard.seek(SeekFrom::Start(byte_offset)).await?;
                        outboard.write_all(l_hash.as_bytes()).await?;
                        outboard.write_all(r_hash.as_bytes()).await?;
                    }
                }
                DecodeResponseItem::Leaf(bao_tree::io::Leaf { offset, data }) => {
                    on_write(offset.0, data.len());
                    target.seek(SeekFrom::Start(offset.0)).await?;
                    target.write_all(&data).await?;
                }
            }
        }
        self.completed = true;
        Ok(())
    }
}

///
pub mod get_response_machine {
    use super::*;

    use bao_tree::io::fsm::{
        ResponseDecoderReading, ResponseDecoderReadingNext, ResponseDecoderStart,
    };
    use derive_more::From;
    use ouroboros::self_referencing;

    #[self_referencing]
    struct RangesIterInner {
        owner: RangeSpecSeq,
        #[borrows(owner)]
        #[covariant]
        iter: crate::protocol::NonEmptyRequestRangeSpecIter<'this>,
    }

    /// Owned iterator for the ranges in a request
    ///
    /// We need an owned iterator for a fsm style API, otherwise we would have
    /// to drag a lifetime around every single state.
    struct RangesIter(RangesIterInner);

    impl fmt::Debug for RangesIter {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("RangesIter").finish()
        }
    }

    impl RangesIter {
        pub fn new(owner: RangeSpecSeq) -> Self {
            Self(RangesIterInner::new(owner, |owner| owner.non_empty_iter()))
        }
    }

    impl Iterator for RangesIter {
        type Item = (u64, RangeSet2<ChunkNum>);

        fn next(&mut self) -> Option<Self::Item> {
            self.0.with_iter_mut(|iter| {
                iter.next()
                    .map(|(offset, ranges)| (offset, ranges.to_chunk_ranges()))
            })
        }
    }

    /// Initial state of the get response machine
    #[derive(Debug)]
    pub struct AtInitial {
        connection: quinn::Connection,
        request: Request,
        auth_token: AuthToken,
    }

    impl AtInitial {
        /// Create a new get response
        ///
        /// `connection` is an existing connection
        /// `request` is the request to be sent
        /// `auth_token` is the auth token for the request
        pub fn new(connection: quinn::Connection, request: Request, auth_token: AuthToken) -> Self {
            Self {
                connection,
                request,
                auth_token,
            }
        }

        /// Initiate a new bidi stream to use for the get response
        pub async fn next(self) -> Result<AtConnected, quinn::ConnectionError> {
            let start = Instant::now();
            let (writer, reader) = self.connection.open_bi().await?;
            let reader = TrackingReader::new(reader);
            let writer = TrackingWriter::new(writer);
            Ok(AtConnected {
                start,
                reader,
                writer,
                request: self.request,
                auth_token: self.auth_token,
            })
        }
    }

    /// State of the get response machine after the handshake has been sent
    #[derive(Debug)]
    pub struct AtConnected {
        start: Instant,
        reader: TrackingReader<quinn::RecvStream>,
        writer: TrackingWriter<quinn::SendStream>,
        request: Request,
        auth_token: AuthToken,
    }

    /// Possible next states after the handshake has been sent
    #[derive(Debug, From)]
    pub enum ConnectedNext {
        ///
        StartChild(AtStartChild),
        ///
        StartCollection(AtStartCollection),
        ///
        Finished(AtFinish),
    }

    impl AtConnected {
        /// Send the request and move to the next state
        ///
        /// The next state will be either `Start` or `StartCollection` depending on whether
        /// the request requests part of the collection or not.
        ///
        /// If the request is empty, this can also move directly to `Finished`.
        pub async fn next(self) -> Result<ConnectedNext, GetResponseError> {
            let Self {
                start,
                reader,
                mut writer,
                request,
                auth_token,
            } = self;
            let mut out_buffer = BytesMut::zeroed(Handshake::POSTCARD_MAX_SIZE);

            // 1. Send Handshake
            {
                debug!("sending handshake");
                let handshake = Handshake::new(auth_token);
                let used = postcard::to_slice(&handshake, &mut out_buffer)?;
                write_lp(&mut writer, used).await?;
            }

            // 2. Send Request
            {
                debug!("sending request");
                let request_bytes = postcard::to_stdvec(&request)?;
                write_lp(&mut writer, &request_bytes).await?;
            }
            let (mut writer, bytes_written) = writer.into_parts();
            writer.finish().await?;
            let hash = request.hash;
            let ranges_iter = RangesIter::new(request.ranges);
            // this is in a box so we don't have to memcpy it on every state transition
            let mut misc = Box::new(Misc {
                start,
                bytes_written,
                ranges_iter,
            });
            Ok(match misc.ranges_iter.next() {
                Some((offset, ranges)) => {
                    if offset == 0 {
                        AtStartCollection {
                            reader,
                            ranges,
                            misc,
                            hash,
                        }
                        .into()
                    } else {
                        AtStartChild {
                            reader,
                            ranges,
                            misc,
                            child_offset: offset - 1,
                        }
                        .into()
                    }
                }
                None => AtFinish::new(misc, reader).into(),
            })
        }
    }

    /// State of the get response when we start reading a collection
    #[derive(Debug)]
    pub struct AtStartCollection {
        ranges: RangeSet2<ChunkNum>,
        reader: TrackingReader<quinn::RecvStream>,
        misc: Box<Misc>,
        hash: Hash,
    }

    /// State of the get response when we start reading a child
    #[derive(Debug)]
    pub struct AtStartChild {
        ranges: RangeSet2<ChunkNum>,
        reader: TrackingReader<quinn::RecvStream>,
        misc: Box<Misc>,
        child_offset: u64,
    }

    impl AtStartChild {
        /// The offset of the child we are currently reading
        ///
        /// This must be used to determine the hash needed to call next
        pub fn child_offset(&self) -> u64 {
            self.child_offset
        }

        /// The ranges we have requested for the child
        pub fn ranges(&self) -> &RangeSet2<ChunkNum> {
            &self.ranges
        }

        /// Go into the next state, reading the header
        ///
        /// This requires passing in the hash of the child for validation
        pub fn next(self, hash: Hash) -> AtHeader {
            let stream = ResponseDecoderStart::<TrackingReader<RecvStream>>::new(
                hash.into(),
                self.ranges,
                IROH_BLOCK_SIZE,
                self.reader,
            );
            AtHeader {
                stream,
                misc: self.misc,
            }
        }

        /// Finish the get response without reading further
        pub fn finish(self) -> AtFinish {
            AtFinish::new(self.misc, self.reader)
        }
    }

    impl AtStartCollection {
        /// The ranges we have requested for the child
        pub fn ranges(&self) -> &RangeSet2<ChunkNum> {
            &self.ranges
        }

        /// Go into the next state, reading the header
        ///
        /// For the collection we already know the hash, since it was part of the request
        pub fn next(self) -> AtHeader {
            let stream = ResponseDecoderStart::new(
                self.hash.into(),
                self.ranges,
                IROH_BLOCK_SIZE,
                self.reader,
            );
            AtHeader {
                stream,
                misc: self.misc,
            }
        }

        /// Finish the get response without reading further
        pub fn finish(self) -> AtFinish {
            AtFinish::new(self.misc, self.reader)
        }
    }

    /// State before reading a size header
    #[derive(Debug)]
    pub struct AtHeader {
        stream: ResponseDecoderStart<TrackingReader<RecvStream>>,
        misc: Box<Misc>,
    }

    impl AtHeader {
        /// Read the size header, returning it and going into the `Content` state.
        pub async fn next(self) -> Result<(AtContent, u64), io::Error> {
            let (stream, size) = self.stream.next().await?;
            Ok((
                AtContent {
                    stream,
                    misc: self.misc,
                },
                size,
            ))
        }

        /// Drain the response and throw away the result
        pub async fn drain(self) -> std::result::Result<AtEnd, DecodeError> {
            let (mut content, _size) = self.next().await?;
            loop {
                match content.next().await {
                    ContentNext::More((content1, Ok(_))) => {
                        content = content1;
                    }
                    ContentNext::More((_, Err(e))) => {
                        return Err(e);
                    }
                    ContentNext::Done(end) => {
                        return Ok(end);
                    }
                }
            }
        }
    }

    /// State while we are reading content
    #[derive(Debug)]
    pub struct AtContent {
        stream: ResponseDecoderReading<TrackingReader<RecvStream>>,
        misc: Box<Misc>,
    }

    ///
    #[derive(Debug, From)]
    pub enum ContentNext {
        ///
        More(
            (
                AtContent,
                std::result::Result<DecodeResponseItem, DecodeError>,
            ),
        ),
        ///
        Done(AtEnd),
    }

    impl AtContent {
        /// Read the next item, either content, an error, or the end of the blob
        pub async fn next(self) -> ContentNext {
            match self.stream.next().await {
                ResponseDecoderReadingNext::More((stream, res)) => {
                    let next = Self { stream, ..self };
                    (next, res).into()
                }
                ResponseDecoderReadingNext::Done(stream) => AtEnd {
                    stream,
                    misc: self.misc,
                }
                .into(),
            }
        }
    }

    /// State after we have read all the content for a blob
    #[derive(Debug)]
    pub struct AtEnd {
        stream: TrackingReader<RecvStream>,
        misc: Box<Misc>,
    }

    ///
    #[derive(Debug, From)]
    pub enum DoneNext {
        ///
        MoreChildren(AtStartChild),
        ///
        Finished(AtFinish),
    }

    impl AtEnd {
        /// Read the next child, or finish
        pub fn next(mut self) -> DoneNext {
            if let Some((offset, ranges)) = self.misc.ranges_iter.next() {
                AtStartChild {
                    reader: self.stream,
                    child_offset: offset - 1,
                    ranges,
                    misc: self.misc,
                }
                .into()
            } else {
                AtFinish::new(self.misc, self.stream).into()
            }
        }
    }

    /// State when finishing the get response
    #[derive(Debug)]
    pub struct AtFinish {
        misc: Box<Misc>,
        reader: TrackingReader<RecvStream>,
    }

    impl AtFinish {
        fn new(misc: Box<Misc>, reader: TrackingReader<RecvStream>) -> Self {
            Self { misc, reader }
        }

        /// Finish the get response, returning statistics
        pub async fn next(self) -> std::result::Result<Stats, io::Error> {
            // Shut down the stream
            let (mut reader, bytes_read) = self.reader.into_parts();
            if let Some(chunk) = reader.read_chunk(8, false).await? {
                reader.stop(0u8.into()).ok();
                error!("Received unexpected data from the provider: {chunk:?}");
            }
            Ok(Stats {
                elapsed: self.misc.start.elapsed(),
                bytes_written: self.misc.bytes_written,
                bytes_read,
            })
        }
    }

    /// Stuff we need to hold on to while going through the machine states
    #[derive(Debug)]
    struct Misc {
        /// start time for statistics
        start: Instant,
        /// bytes written for statistics
        bytes_written: u64,
        /// iterator over the ranges of the collection and the children
        ranges_iter: RangesIter,
    }
}

///
pub async fn run_fsm(
    request: Request,
    auth_token: AuthToken,
    opts: Options,
) -> anyhow::Result<get_response_machine::AtInitial> {
    let connection = dial_peer(opts).await?;
    Ok(run_connection_fsm(connection, request, auth_token))
}

/// Do a get request and return a stream of responses
pub fn run_connection_fsm(
    connection: quinn::Connection,
    request: Request,
    auth_token: AuthToken,
) -> get_response_machine::AtInitial {
    get_response_machine::AtInitial::new(connection, request, auth_token)
}

/// Error when processing a response
#[derive(thiserror::Error, Debug)]
pub enum GetResponseError {
    /// Error when opening a stream
    #[error("connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// Error when writing the handshake or request to the stream
    #[error("write: {0}")]
    Write(#[from] quinn::WriteError),
    /// Error when reading from the stream
    #[error("read: {0}")]
    Read(#[from] quinn::ReadError),
    /// Error when decoding, e.g. hash mismatch
    #[error("decode: {0}")]
    Decode(bao_tree::io::error::DecodeError),
    /// A generic error
    #[error("generic: {0}")]
    Generic(anyhow::Error),
}

impl From<postcard::Error> for GetResponseError {
    fn from(cause: postcard::Error) -> Self {
        Self::Generic(cause.into())
    }
}

impl From<bao_tree::io::error::DecodeError> for GetResponseError {
    fn from(cause: bao_tree::io::error::DecodeError) -> Self {
        match cause {
            bao_tree::io::error::DecodeError::Io(cause) => {
                // try to downcast to specific quinn errors
                if let Some(source) = cause.source() {
                    if let Some(error) = source.downcast_ref::<quinn::ConnectionError>() {
                        return Self::Connection(error.clone());
                    }
                    if let Some(error) = source.downcast_ref::<quinn::ReadError>() {
                        return Self::Read(error.clone());
                    }
                    if let Some(error) = source.downcast_ref::<quinn::WriteError>() {
                        return Self::Write(error.clone());
                    }
                }
                Self::Generic(cause.into())
            }
            _ => Self::Decode(cause),
        }
    }
}

impl From<anyhow::Error> for GetResponseError {
    fn from(cause: anyhow::Error) -> Self {
        Self::Generic(cause)
    }
}

/// Gets a collection and all its blobs from a provider on the established connection.
async fn run_connection<A, C, FutA, FutC, U>(
    connection: quinn::Connection,
    request: Request,
    auth_token: AuthToken,
    on_connected: A,
    mut on_blob: C,
    mut user: U,
) -> Result<(U, Stats)>
where
    A: FnOnce() -> FutA,
    FutA: Future<Output = Result<()>>,
    C: FnMut(OnBlobData<U>) -> FutC,
    FutC: Future<Output = Result<OnBlobResult<U>>>,
{
    let start = Instant::now();
    // expect to get blob data in the order they appear in the collection
    let ranges_iter = request.ranges.non_empty_iter();
    let (writer, reader) = connection.open_bi().await?;
    let mut reader = TrackingReader::new(reader);
    let mut writer = TrackingWriter::new(writer);

    on_connected().await?;

    let mut out_buffer = BytesMut::zeroed(Handshake::POSTCARD_MAX_SIZE);

    // 1. Send Handshake
    {
        debug!("sending handshake");
        let handshake = Handshake::new(auth_token);
        let used = postcard::to_slice(&handshake, &mut out_buffer)?;
        write_lp(&mut writer, used).await?;
    }

    // 2. Send Request
    {
        debug!("sending request");
        let request_bytes = postcard::to_stdvec(&request)?;
        write_lp(&mut writer, &request_bytes).await?;
    }
    let (mut writer, bytes_written) = writer.into_parts();
    writer.finish().await?;
    drop(writer);

    // 3. Read response
    debug!("reading response");
    let mut limit = None;
    for (offset, query) in ranges_iter {
        if let Some(limit) = limit {
            if offset >= limit {
                break;
            }
        }
        let size = reader.read_u64_le().await?;
        debug!("reading item {} {:?} size {}", offset, query, size);
        let res = on_blob(OnBlobData {
            user,
            offset,
            size,
            ranges: query.to_chunk_ranges(),
            reader,
            limit,
            completed: false,
        })
        .await?;
        reader = res.reader;
        user = res.user;
        limit = res.limit;
    }

    // Shut down the stream
    let (mut reader, bytes_read) = reader.into_parts();
    if let Some(chunk) = reader.read_chunk(8, false).await? {
        reader.stop(0u8.into()).ok();
        error!("Received unexpected data from the provider: {chunk:?}");
    }
    drop(reader);
    Ok((
        user,
        Stats {
            elapsed: start.elapsed(),
            bytes_written,
            bytes_read,
        },
    ))
}

/// Given a directory, make a partial download of it.
#[cfg(any(test, feature = "cli"))]
pub fn make_partial_download(out_dir: impl AsRef<Path>) -> anyhow::Result<crate::Hash> {
    use crate::provider::{create_collection, create_data_sources, BlobOrCollection};

    let out_dir: &Path = out_dir.as_ref();
    let temp_dir = out_dir.join(".iroh-tmp");
    anyhow::ensure!(!temp_dir.exists());
    std::fs::create_dir_all(&temp_dir)?;
    let sources = create_data_sources(out_dir.to_owned())?;
    println!("{:?}", sources);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (db, hash) = rt.block_on(create_collection(sources))?;
    let db = db.to_inner();
    for (hash, boc) in db {
        let text = blake3::Hash::from(hash).to_hex();
        let mut outboard_path = temp_dir.join(text.as_str());
        outboard_path.set_extension("outboard.part");
        let mut data_path = temp_dir.join(text.as_str());
        match boc {
            BlobOrCollection::Blob { outboard, path, .. } => {
                data_path.set_extension("data.part");
                std::fs::write(outboard_path, outboard)?;
                std::fs::rename(path, data_path)?;
            }
            BlobOrCollection::Collection { outboard, data } => {
                data_path.set_extension("data");
                std::fs::write(outboard_path, outboard)?;
                std::fs::write(data_path, data)?;
            }
        }
    }
    Ok(hash)
}

/// Create a pathbuf from a name.
pub fn pathbuf_from_name(name: &str) -> PathBuf {
    let mut path = PathBuf::new();
    for part in name.split('/') {
        path.push(part);
    }
    path
}

/// Get missing range for a single file, given a temp and target directory
pub fn get_missing_range(
    hash: &Hash,
    name: &str,
    temp_dir: impl AsRef<Path>,
    target_dir: impl AsRef<Path>,
) -> io::Result<RangeSpecSeq> {
    let target_dir = target_dir.as_ref();
    let temp_dir = temp_dir.as_ref();
    if target_dir.exists() && !temp_dir.exists() {
        // target directory exists yet does not contain the temp dir
        // refuse to continue
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Target directory exists but does not contain temp directory",
        ));
    }
    let range = get_missing_range_impl(hash, name, temp_dir, target_dir)?;
    let spec = RangeSpecSeq::new(vec![range]);
    Ok(spec)
}

/// Get missing range for a single file
fn get_missing_range_impl(
    hash: &Hash,
    name: &str,
    temp_dir: impl AsRef<Path>,
    target_dir: impl AsRef<Path>,
) -> io::Result<RangeSet2<ChunkNum>> {
    let paths = FilePaths::new(hash, name, temp_dir, target_dir);
    Ok(if paths.is_final() {
        tracing::debug!("Found final file: {:?}", paths.target);
        // we assume that the file is correct
        RangeSet2::empty()
    } else if paths.is_incomplete() {
        tracing::debug!("Found incomplete file: {:?}", paths.temp);
        // we got incomplete data
        let outboard = std::fs::read(&paths.outboard)?;
        let outboard = PreOrderMemOutboard::new((*hash).into(), IROH_BLOCK_SIZE, outboard, false);
        match outboard {
            Ok(outboard) => {
                // compute set of valid ranges from the outboard and the file
                //
                // We assume that the file is correct and does not contain holes.
                // Otherwise, we would have to rehash the file.
                //
                // Do a quick check of the outboard in case something went wrong when writing.
                let mut valid = bao_tree::outboard::valid_ranges(&outboard)?;
                let valid_from_file =
                    RangeSet2::from(..ByteNum(paths.temp.metadata()?.len()).full_chunks());
                tracing::debug!("valid_from_file: {:?}", valid_from_file);
                tracing::debug!("valid_from_outboard: {:?}", valid);
                valid &= valid_from_file;
                RangeSet2::all().difference(&valid)
            }
            Err(cause) => {
                tracing::debug!("Outboard damaged, assuming missing {cause:?}");
                // the outboard is invalid, so we assume that the file is missing
                RangeSet2::all()
            }
        }
    } else {
        tracing::debug!("Found missing file: {:?}", paths.target);
        // we don't know anything about this file, so we assume it's missing
        RangeSet2::all()
    })
}

/// Given a target directory and a temp directory, get a set of ranges that we are missing
pub fn get_missing_ranges(
    hash: Hash,
    target_dir: impl AsRef<Path>,
    temp_dir: impl AsRef<Path>,
) -> io::Result<(RangeSpecSeq, Option<Collection>)> {
    let target_dir = target_dir.as_ref();
    let temp_dir = temp_dir.as_ref();
    if target_dir.exists() && !temp_dir.exists() {
        // target directory exists yet does not contain the temp dir
        // refuse to continue
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Target directory exists but does not contain temp directory",
        ));
    }
    // try to load the collection from the temp directory
    let collection = load_collection(temp_dir, hash)?;
    let collection = match collection {
        Some(collection) => collection,
        None => return Ok((RangeSpecSeq::all(), None)),
    };
    let mut ranges = collection
        .blobs()
        .iter()
        .map(|blob| get_missing_range_impl(&blob.hash, blob.name.as_str(), temp_dir, target_dir))
        .collect::<io::Result<Vec<_>>>()?;
    ranges
        .iter()
        .zip(collection.blobs())
        .for_each(|(ranges, blob)| {
            if ranges.is_empty() {
                tracing::debug!("{} is complete", blob.name);
            } else if ranges.is_all() {
                tracing::debug!("{} is missing", blob.name);
            } else {
                tracing::debug!("{} is partial {:?}", blob.name, ranges);
            }
        });
    // make room for the collection at offset 0
    // if we get here, we already have the collection, so we don't need to ask for it again.
    ranges.insert(0, RangeSet2::empty());
    Ok((RangeSpecSeq::new(ranges), Some(collection)))
}

#[derive(Debug)]
struct FilePaths {
    target: PathBuf,
    temp: PathBuf,
    outboard: PathBuf,
}

impl FilePaths {
    fn new(
        hash: &Hash,
        name: &str,
        temp_dir: impl AsRef<Path>,
        target_dir: impl AsRef<Path>,
    ) -> Self {
        let target = target_dir.as_ref().join(pathbuf_from_name(name));
        let hash = blake3::Hash::from(*hash).to_hex();
        let temp = temp_dir.as_ref().join(format!("{}.data.part", hash));
        let outboard = temp_dir.as_ref().join(format!("{}.outboard.part", hash));
        Self {
            target,
            temp,
            outboard,
        }
    }

    fn is_final(&self) -> bool {
        self.target.exists()
    }

    fn is_incomplete(&self) -> bool {
        self.temp.exists() && self.outboard.exists()
    }
}

/// get data path for a hash
pub fn get_data_path(dir: impl AsRef<Path>, hash: Hash) -> PathBuf {
    let data_path = dir.as_ref();
    let hash = blake3::Hash::from(hash).to_hex();
    data_path.join(format!("{}.data", hash))
}

/// Load a collection from a data path
fn load_collection(data_path: impl AsRef<Path>, hash: Hash) -> io::Result<Option<Collection>> {
    let collection_path = get_data_path(data_path, hash);
    Ok(if collection_path.exists() {
        let collection = std::fs::read(&collection_path)?;
        // todo: error
        let collection = Collection::from_bytes(&collection).unwrap();
        Some(collection)
    } else {
        None
    })
}
