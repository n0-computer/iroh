//! The client side API
//!
//! The main entry point is [`run`]. This function takes callbacks that will
//! be invoked when blobs or collections are received. It is up to the caller
//! to store the received data.
use std::fmt::Debug;
use std::io::{self, Cursor, SeekFrom};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use crate::blobs::{Blob, Collection};
use crate::protocol::{
    read_bao_encoded, read_lp, write_lp, AuthToken, Handshake, RangeSpec, RangeSpecSeq, Request,
    Res, Response,
};
use crate::provider::Ticket;
use crate::subnet::{same_subnet_v4, same_subnet_v6};
use crate::tls::{self, Keypair, PeerId};
use crate::util::pathbuf_from_name;
use crate::IROH_BLOCK_SIZE;
use anyhow::{anyhow, bail, Context, Result};
use bao_tree::io::error::DecodeError;
use bao_tree::io::tokio::DecodeResponseStream;
use bao_tree::io::DecodeResponseItem;
use bao_tree::outboard::PreOrderMemOutboard;
use bao_tree::{ByteNum, ChunkNum};
use bytes::{Bytes, BytesMut};
use default_net::Interface;
use futures::stream::FusedStream;
use futures::{ready, Future, Stream, StreamExt};
use postcard::experimental::max_size::MaxSize;
use quinn::RecvStream;
use range_collections::RangeSet2;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tokio_util::either::Either;
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
async fn dial_peer(opts: Options) -> Result<quinn::Connection> {
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
    /// The number of bytes transferred
    pub data_len: u64,
    /// The time it took to transfer the data
    pub elapsed: Duration,
}

impl Stats {
    /// Transfer rate in megabits per second
    pub fn mbits(&self) -> f64 {
        let data_len_bit = self.data_len * 8;
        data_len_bit as f64 / (1000. * 1000.) / self.elapsed.as_secs_f64()
    }
}

/// A verified stream of data coming from the provider
///
/// We guarantee that the data is correct by incrementally verifying a hash
#[repr(transparent)]
#[derive(Debug)]
pub struct DataStream(DecodeResponseStream<Either<quinn::RecvStream, Cursor<Bytes>>>);

impl DataStream {
    fn new(
        inner: Either<quinn::RecvStream, Cursor<Bytes>>,
        hash: Hash,
        ranges: RangeSet2<ChunkNum>,
    ) -> Self {
        let decoder = DecodeResponseStream::new(hash.into(), ranges, IROH_BLOCK_SIZE, inner);
        DataStream(decoder)
    }

    /// write all the data to a file or buffer
    pub async fn write_all(
        &mut self,
        mut target: impl AsyncWrite + AsyncSeek + Unpin,
    ) -> std::result::Result<(), DecodeError> {
        let mut curr = ByteNum(0);
        while let Some(item) = self.0.next().await {
            match item? {
                DecodeResponseItem::Header { .. } => {
                    // resize the file here?
                    // target.seek(SeekFrom::Start(size.0)).await?;
                    // target.rewind().await?;
                }
                DecodeResponseItem::Parent { .. } => {
                    // don't do anything here
                }
                DecodeResponseItem::Leaf { offset, data } => {
                    // only seek if we have to
                    if curr != offset {
                        target.seek(SeekFrom::Start(offset.0)).await?;
                    }
                    target.write_all(&data).await?;
                    curr = curr + data.len() as u64;
                }
            }
        }
        Ok(())
    }

    /// write all the data to a file or buffer
    ///
    /// `target` is the main file
    /// `create_outboard` is a function that creates an optional outboard file
    /// `on_write` is a callback for writes, e.g. to update a progress bar
    pub async fn write_all_with_outboard<T, O, OS, OW, Fut>(
        &mut self,
        target: T,
        mut create_outboard: OS,
        mut on_write: OW,
    ) -> std::result::Result<Option<O>, DecodeError>
    where
        T: AsyncWrite + AsyncSeek + Unpin + Debug,
        O: AsyncWrite + AsyncSeek + Unpin + Debug,
        OS: FnMut(u64) -> Fut,
        OW: FnMut(u64, usize),
        Fut: Future<Output = io::Result<Option<O>>>,
    {
        let mut target = OptimizedSeek::new(target);
        let tree = self.0.read_tree().await?;
        let mut outboard = None;
        while let Some(item) = self.0.next().await {
            match item? {
                DecodeResponseItem::Header { size } => {
                    // only seek if we have to
                    outboard = create_outboard(size.0).await?.map(OptimizedSeek::new);
                    if let Some(outboard) = outboard.as_mut() {
                        outboard.seek(SeekFrom::Start(0)).await?;
                        outboard.write_all(&size.0.to_le_bytes()).await?;
                    }
                }
                DecodeResponseItem::Parent {
                    node,
                    pair: (l_hash, r_hash),
                } => {
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
                DecodeResponseItem::Leaf { offset, data } => {
                    on_write(offset.0, data.len());
                    target.seek(SeekFrom::Start(offset.0)).await?;
                    target.write_all(&data).await?;
                }
            }
        }
        Ok(outboard.map(|x| x.into_inner()))
    }

    /// Read the size of the file this is about
    pub async fn read_size(&mut self) -> io::Result<u64> {
        let tree = self.0.read_tree().await?;
        Ok(tree.size().0)
    }

    /// drain the entire stream, checking for errors but discarding the data
    #[cfg(test)]
    pub(crate) async fn drain(&mut self) -> std::result::Result<(), DecodeError> {
        while let Some(item) = self.0.next().await {
            let _ = item?;
        }
        Ok(())
    }

    fn into_inner(self) -> Either<quinn::RecvStream, Cursor<Bytes>> {
        self.0.into_inner()
    }
}

impl Stream for DataStream {
    type Item = std::result::Result<DecodeResponseItem, DecodeError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.0).poll_next(cx)
    }
}

impl FusedStream for DataStream {
    fn is_terminated(&self) -> bool {
        self.0.is_terminated()
    }
}

/// Gets a collection and all its blobs using a [`Ticket`].
pub async fn run_ticket<A, B, C, FutA, FutB, FutC>(
    ticket: &Ticket,
    request: Request,
    keylog: bool,
    max_concurrent: u8,
    on_connected: A,
    on_collection: B,
    on_blob: C,
) -> Result<Stats>
where
    A: FnOnce() -> FutA,
    FutA: Future<Output = Result<()>>,
    B: FnOnce(Bytes, &Collection) -> FutB,
    FutB: Future<Output = Result<()>>,
    C: FnMut(Hash, DataStream, String) -> FutC,
    FutC: Future<Output = Result<DataStream>>,
{
    let span = debug_span!("get", hash=%ticket.hash());
    async move {
        let start = Instant::now();
        let connection = dial_ticket(ticket, keylog, max_concurrent.into()).await?;
        let span = debug_span!("connection", remote_addr=%connection.remote_address());
        run_connection(
            connection,
            request,
            ticket.token(),
            start,
            on_connected,
            on_collection,
            on_blob,
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

#[derive(Debug)]
struct FilePaths {
    target: PathBuf,
    temp: PathBuf,
    outboard: PathBuf,
}

impl FilePaths {
    fn new(entry: &Blob, tempdir: impl AsRef<Path>, target_dir: impl AsRef<Path>) -> Self {
        let target = target_dir.as_ref().join(pathbuf_from_name(&entry.name));
        let hash = blake3::Hash::from(entry.hash).to_hex();
        let temp = tempdir.as_ref().join(format!("{}.data.part", hash));
        let outboard = tempdir.as_ref().join(format!("{}.outboard.part", hash));
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

///
pub fn get_data_path(temp_dir: impl AsRef<Path>, hash: Hash) -> PathBuf {
    let data_path = temp_dir.as_ref();
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

/// Given a target directory and a temp directory, get a set of ranges that we are missing
pub fn get_missing_data(
    hash: Hash,
    path: impl AsRef<Path>,
    temp: impl AsRef<Path>,
) -> io::Result<(RangeSpecSeq, Option<Collection>)> {
    let path = path.as_ref();
    let temp = temp.as_ref();
    if path.exists() && !temp.exists() {
        // target directory exists yet does not contain the temp dir
        // refuse to continue
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Target directory exists but does not contain temp directory",
        ));
    }
    // try to load the collection from the temp directory
    let collection = load_collection(temp, hash)?;
    let collection = match collection {
        Some(collection) => collection,
        None => return Ok((RangeSpecSeq::all(), None)),
    };
    let mut ranges = collection
        .blobs()
        .iter()
        .map(|blob| {
            let paths = FilePaths::new(blob, &temp, &path);
            io::Result::Ok(if paths.is_final() {
                tracing::debug!("Found final file: {:?}", paths.target);
                // we assume that the file is correct
                RangeSet2::empty()
            } else if paths.is_incomplete() {
                tracing::debug!("Found incomplete file: {:?}", paths.temp);
                // we got incomplete data
                let outboard = std::fs::read(&paths.outboard)?;
                let outboard =
                    PreOrderMemOutboard::new(blob.hash.into(), IROH_BLOCK_SIZE, outboard, false);
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
        })
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

/// Get a collection and all its blobs from a provider
pub async fn run<A, B, C, FutA, FutB, FutC>(
    request: Request,
    auth_token: AuthToken,
    opts: Options,
    on_connected: A,
    on_collection: B,
    on_blob: C,
) -> Result<Stats>
where
    A: FnOnce() -> FutA,
    FutA: Future<Output = Result<()>>,
    B: FnOnce(Bytes, &Collection) -> FutB,
    FutB: Future<Output = Result<()>>,
    C: FnMut(Hash, DataStream, String) -> FutC,
    FutC: Future<Output = Result<DataStream>>,
{
    let span = debug_span!("get", %request.name);
    async move {
        let now = Instant::now();
        let connection = dial_peer(opts).await?;
        let span = debug_span!("connection", remote_addr=%connection.remote_address());
        run_connection(
            connection,
            request,
            auth_token,
            now,
            on_connected,
            on_collection,
            on_blob,
        )
        .instrument(span)
        .await
    }
    .instrument(span)
    .await
}

/// Gets a collection and all its blobs from a provider on the established connection.
async fn run_connection<A, B, C, FutA, FutB, FutC>(
    connection: quinn::Connection,
    request: Request,
    auth_token: AuthToken,
    start_time: Instant,
    on_connected: A,
    on_collection: B,
    mut on_blob: C,
) -> Result<Stats>
where
    A: FnOnce() -> FutA,
    FutA: Future<Output = Result<()>>,
    B: FnOnce(Bytes, &Collection) -> FutB,
    FutB: Future<Output = Result<()>>,
    C: FnMut(Hash, DataStream, String) -> FutC,
    FutC: Future<Output = Result<DataStream>>,
{
    let hash = request.name;
    // expect to get blob data in the order they appear in the collection
    let mut ranges_iter = request.ranges.iter();
    let (mut writer, mut reader) = connection.open_bi().await?;

    on_connected().await?;

    let mut out_buffer = BytesMut::zeroed(Handshake::POSTCARD_MAX_SIZE);
    let mut data_len = 0;

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
        let serialized = postcard::to_stdvec(&request)?;
        write_lp(&mut writer, &serialized).await?;
    }
    writer.finish().await?;
    drop(writer);

    // 3. Read response
    {
        debug!("reading response");
        let mut in_buffer = BytesMut::with_capacity(1024);

        // track total amount of blob data transferred
        // read next message
        match read_lp(&mut reader, &mut in_buffer).await? {
            Some(response_buffer) => {
                let response: Response = postcard::from_bytes(&response_buffer)?;
                match response.data {
                    // server is sending over a collection of blobs
                    Res::Found => {
                        let collection_ranges = ranges_iter.next().unwrap();
                        // read entire collection data into buffer
                        let data: Bytes = read_bao_encoded(&mut reader, hash, collection_ranges)
                            .await?
                            .into();

                        // decode the collection
                        let collection = Collection::from_bytes(&data)?;
                        on_collection(data.clone(), &collection).await?;

                        for (blob, ranges) in collection
                            .into_inner()
                            .into_iter()
                            .zip(request.ranges.iter())
                        {
                            let blob_reader =
                                handle_blob_response(blob.hash, reader, ranges, &mut in_buffer)
                                    .await?;

                            let mut blob_reader =
                                on_blob(blob.hash, blob_reader, blob.name).await?;
                            data_len += blob_reader.read_size().await?;

                            if !blob_reader.is_terminated() {
                                bail!("`on_blob` callback did not fully read the blob content")
                            }
                            reader = match blob_reader.into_inner() {
                                Either::Left(reader) => reader,
                                Either::Right(_) => unreachable!(),
                            };
                        }
                    }

                    // data associated with the hash is not found
                    Res::NotFound => {
                        Err(anyhow!("data not found"))?;
                    }
                }

                // Shut down the stream
                if let Some(chunk) = reader.read_chunk(8, false).await? {
                    reader.stop(0u8.into()).ok();
                    error!("Received unexpected data from the provider: {chunk:?}");
                }
                drop(reader);

                let elapsed = start_time.elapsed();

                let stats = Stats { data_len, elapsed };

                Ok(stats)
            }
            None => {
                bail!("provider closed stream");
            }
        }
    }
}

struct OnBlobData<'a> {
    // the offset of the current blob. 0 is for the item itself (the collection)
    // child offsets start with 1
    offset: usize,
    // the total size of the blob
    size: u64,
    // the ranges we have requested for this blob
    ranges: &'a RangeSpec,
    // the reader for the encoded range
    reader: RecvStream,
}

/// Gets a collection and all its blobs from a provider on the established connection.
async fn run_connection_2<A, B, C, FutA, FutB, FutC>(
    connection: quinn::Connection,
    request: Request,
    auth_token: AuthToken,
    on_connected: A,
    mut on_blob: C,
) -> Result<()>
where
    A: FnOnce() -> FutA,
    FutA: Future<Output = Result<()>>,
    C: FnMut(&mut OnBlobData) -> FutC,
    FutC: Future<Output = Result<bool>>,
{
    // expect to get blob data in the order they appear in the collection
    let mut ranges_iter = request.ranges.non_empty_iter();
    let (mut writer, reader) = connection.open_bi().await?;

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
        let serialized = postcard::to_stdvec(&request)?;
        write_lp(&mut writer, &serialized).await?;
    }
    writer.finish().await?;
    drop(writer);

    // 3. Read response
    debug!("reading response");
    let mut data = OnBlobData {
        offset: 0,
        size: 0,
        ranges: &RangeSpec::EMPTY,
        reader,
    };
    while let Some((offset, query)) = ranges_iter.next() {
        assert!(!query.is_empty());
        data.offset = offset;
        data.size = data.reader.read_u64_le().await?;
        data.ranges = query;
        debug!("reading item {} {:?} size {}", offset, query, data.size);
        let done = !on_blob(&mut data).await?;
        if done {
            break;
        }
    }
    let mut reader = data.reader;

    // Shut down the stream
    if let Some(chunk) = reader.read_chunk(8, false).await? {
        reader.stop(0u8.into()).ok();
        error!("Received unexpected data from the provider: {chunk:?}");
    }
    drop(reader);
    Ok(())
}

/// Read next response, and if `Res::Found`, reads the next blob of data off the reader.
///
/// Returns an `AsyncReader`
/// The `AsyncReader` can be used to read the content.
async fn handle_blob_response(
    hash: Hash,
    mut reader: quinn::RecvStream,
    ranges: &RangeSpec,
    buffer: &mut BytesMut,
) -> Result<DataStream> {
    match read_lp(&mut reader, buffer).await? {
        Some(response_buffer) => {
            let response: Response = postcard::from_bytes(&response_buffer)?;
            match response.data {
                // blob data not found
                Res::NotFound => Err(anyhow!("data for {} not found", hash))?,
                // next blob in collection will be sent over
                Res::Found => {
                    assert!(buffer.is_empty());
                    let decoder =
                        DataStream::new(Either::Left(reader), hash, ranges.to_chunk_ranges());
                    Ok(decoder)
                }
            }
        }
        None => Err(anyhow!("server disconnected"))?,
    }
}

///
#[derive(Debug)]
pub struct OptimizedSeek<T> {
    inner: T,
    state: OptimizedSeekState,
}

impl<T> OptimizedSeek<T> {
    ///
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            state: OptimizedSeekState::Unknown,
        }
    }

    ///
    pub fn into_inner(self) -> T {
        self.inner
    }
}

#[derive(Debug)]
enum OptimizedSeekState {
    Unknown,
    Seeking,
    FakeSeeking(u64),
    Known(u64),
}

impl OptimizedSeekState {
    fn take(&mut self) -> Self {
        std::mem::replace(self, OptimizedSeekState::Unknown)
    }

    fn is_seeking(&self) -> bool {
        match self {
            OptimizedSeekState::Seeking => true,
            OptimizedSeekState::FakeSeeking(_) => true,
            _ => false,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for OptimizedSeek<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(if self.state.is_seeking() {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "cannot read while seeking",
            ))
        } else {
            let before = buf.remaining();
            ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
            let after = buf.remaining();
            let read = before - after;
            if let OptimizedSeekState::Known(offset) = &mut self.state {
                *offset += read as u64;
            }
            Ok(())
        })
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for OptimizedSeek<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(if self.state.is_seeking() {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "cannot write while seeking",
            ))
        } else {
            let result = ready!(Pin::new(&mut self.inner).poll_write(cx, buf))?;
            if let OptimizedSeekState::Known(offset) = &mut self.state {
                *offset += result as u64;
            }
            Ok(result)
        })
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<T: AsyncSeek + Unpin + Debug> AsyncSeek for OptimizedSeek<T> {
    fn start_seek(mut self: Pin<&mut Self>, seek_from: SeekFrom) -> io::Result<()> {
        self.state = match (self.state.take(), seek_from) {
            (OptimizedSeekState::Known(offset), SeekFrom::Current(0)) => {
                // somebody wants to know the current position
                OptimizedSeekState::FakeSeeking(offset)
            }
            (OptimizedSeekState::Known(offset), SeekFrom::Start(current)) if offset == current => {
                // seek to the current position
                OptimizedSeekState::FakeSeeking(offset)
            }
            _ => {
                // if start_seek fails, we go into unknown state
                Pin::new(&mut self.inner).start_seek(seek_from)?;
                OptimizedSeekState::Seeking
            }
        };
        Ok(())
    }

    fn poll_complete(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<u64>> {
        // if we are in fakeseeking state, intercept the call to the inner
        if let OptimizedSeekState::FakeSeeking(offset) = self.state {
            self.state = OptimizedSeekState::Known(offset);
            return Poll::Ready(Ok(offset));
        }
        // in all other cases we have to do the call to the inner
        //
        // a tokio file can be busy even when it seems idle, because write ops
        // are buffered. so we have to poll_complete until it returns Ok.
        let res = ready!(Pin::new(&mut self.inner).poll_complete(cx))?;
        if let OptimizedSeekState::Seeking = self.state {
            self.state = OptimizedSeekState::Known(res);
        }
        Poll::Ready(Ok(res))
    }
}
