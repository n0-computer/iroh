//! The client side API
//!
//! The main entry point is [`run`]. This function takes callbacks that will
//! be invoked when blobs or collections are received. It is up to the caller
//! to store the received data.
use std::fmt::Debug;
use std::io::{self, Cursor, SeekFrom};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::blobs::{Blob, Collection};
use crate::protocol::{write_lp, AuthToken, Handshake, RangeSpecSeq, Request};
use crate::provider::Ticket;
use crate::subnet::{same_subnet_v4, same_subnet_v6};
use crate::tls::{self, Keypair, PeerId};
use crate::tokio_util::{TrackingReader, SeekOptimized, TrackingWriter};
use crate::util::pathbuf_from_name;
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
            let paths = FilePaths::new(blob, temp, path);
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
    let span = debug_span!("get", %request.name);
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

///
#[derive(Debug)]
pub struct OnBlobData<T> {
    /// the offset of the current blob. 0 is for the item itself (the collection)
    offset: usize,
    /// the total size of the blob
    size: u64,
    /// the ranges we requested
    ranges: RangeSet2<ChunkNum>,
    /// out: limit on the collection
    limit: Option<usize>,
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
    limit: Option<usize>,
}

impl<U> OnBlobData<U> {
    /// the offset of the current blob. 0 is for the item itself (the collection)
    /// child offsets start with 1
    pub fn offset(&self) -> usize {
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
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = Some(limit)
    }

    /// child offset
    pub fn child_offset(&self) -> Option<usize> {
        self.offset.checked_sub(1)
    }

    /// the bao tree for this blob
    pub fn tree(&self) -> BaoTree {
        BaoTree::new(ByteNum(self.size), IROH_BLOCK_SIZE)
    }

    /// Read the entire blob into a Vec<u8>
    ///
    /// Make sure to check the size of the blob before calling this.
    pub async fn read_blob(&mut self, hash: Hash) -> anyhow::Result<Vec<u8>> {
        let mut target = Vec::new();
        self.write_all(hash, Cursor::new(&mut target)).await?;
        Ok(target)
    }

    /// Read the entire blob into a Vec<u8> and then decode it as a Collection
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
            if let DecodeResponseItem::Leaf { data, offset, .. } = chunk? {
                on_write(offset.0, data.len());
                target.write_all(&data).await?;
            }
        }
        drop(stream);
        self.completed = true;
        Ok(())
    }

    /// write all the data to a file or buffer
    ///
    /// `target` is the main file
    /// `create_outboard` is a function that creates an optional outboard file
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
        self.completed = true;
        Ok(())
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
        let serialized = postcard::to_stdvec(&request)?;
        write_lp(&mut writer, &serialized).await?;
    }
    let bytes_written = writer.bytes_written();
    let mut writer = writer.into_inner();
    writer.finish().await?;
    drop(writer);

    // 3. Read response
    debug!("reading response");
    let mut limit = None;
    for (offset, query) in ranges_iter {
        assert!(!query.is_empty());
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
    let bytes_read = reader.bytes_read();
    let mut reader = reader.into_inner();
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
