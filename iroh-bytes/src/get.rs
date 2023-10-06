//! The client side API
//!
//! To get data, create a connection using the `dial` function or use any quinn
//! connection that was obtained in another way.
//!
//! Create a request describing the data you want to get.
//!
//! Then create a state machine using [fsm::start] and
//! drive it to completion by calling next on each state.
//!
//! For some states you have to provide additional arguments when calling next,
//! or you can choose to finish early.
use std::error::Error;
use std::fmt::{self, Debug};
use std::time::{Duration, Instant};

use crate::util::Hash;
use anyhow::Result;
use bao_tree::io::fsm::BaoContentItem;
use bao_tree::ChunkNum;
use quinn::RecvStream;
use range_collections::RangeSet2;
use tracing::{debug, error};

use crate::protocol::RangeSpecSeq;
use crate::util::io::{TrackingReader, TrackingWriter};
use crate::IROH_BLOCK_SIZE;

/// Stats about the transfer.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
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

/// Finite state machine for get responses
///
#[doc = include_str!("../docs/img/get_machine.drawio.svg")]
pub mod fsm {
    use std::{io, result};

    use crate::protocol::{GetRequest, NonEmptyRequestRangeSpecIter, Request, MAX_MESSAGE_SIZE};

    use super::*;

    use bao_tree::{
        blake3,
        io::{
            fsm::{
                OutboardMut, ResponseDecoderReading, ResponseDecoderReadingNext,
                ResponseDecoderStart,
            },
            StartDecodeError,
        },
        TreeNode,
    };
    use derive_more::From;
    use iroh_io::AsyncSliceWriter;
    use tokio::io::AsyncWriteExt;

    self_cell::self_cell! {
        struct RangesIterInner {
            owner: RangeSpecSeq,
            #[covariant]
            dependent: NonEmptyRequestRangeSpecIter,
        }
    }

    /// The entry point of the get response machine
    pub fn start(connection: quinn::Connection, request: GetRequest) -> AtInitial {
        AtInitial::new(connection, request)
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
            Self(RangesIterInner::new(owner, |owner| owner.iter_non_empty()))
        }
    }

    impl Iterator for RangesIter {
        type Item = (u64, RangeSet2<ChunkNum>);

        fn next(&mut self) -> Option<Self::Item> {
            self.0.with_dependent_mut(|_owner, iter| {
                iter.next()
                    .map(|(offset, ranges)| (offset, ranges.to_chunk_ranges()))
            })
        }
    }

    /// Initial state of the get response machine
    #[derive(Debug)]
    pub struct AtInitial {
        connection: quinn::Connection,
        request: GetRequest,
    }

    impl AtInitial {
        /// Create a new get response
        ///
        /// `connection` is an existing connection
        /// `request` is the request to be sent
        pub fn new(connection: quinn::Connection, request: GetRequest) -> Self {
            Self {
                connection,
                request,
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
            })
        }
    }

    /// State of the get response machine after the handshake has been sent
    #[derive(Debug)]
    pub struct AtConnected {
        start: Instant,
        reader: TrackingReader<quinn::RecvStream>,
        writer: TrackingWriter<quinn::SendStream>,
        request: GetRequest,
    }

    /// Possible next states after the handshake has been sent
    #[derive(Debug, From)]
    pub enum ConnectedNext {
        /// First response is either a collection or a single blob
        StartRoot(AtStartRoot),
        /// First response is a child
        StartChild(AtStartChild),
        /// Request is empty
        Closing(AtClosing),
    }

    /// Error that you can get from [`AtConnected::next`]
    #[derive(Debug, thiserror::Error)]
    pub enum ConnectedNextError {
        /// Error when serializing the request
        #[error("postcard ser: {0}")]
        PostcardSer(postcard::Error),
        /// The serialized request is too long to be sent
        #[error("request too big")]
        RequestTooBig,
        /// Error when writing the request to the [`quinn::SendStream`]
        #[error("write: {0}")]
        Write(#[from] quinn::WriteError),
        /// A generic io error
        #[error("io {0}")]
        Io(io::Error),
    }

    impl ConnectedNextError {
        fn from_io(cause: io::Error) -> Self {
            if let Some(inner) = cause.get_ref() {
                if let Some(e) = inner.downcast_ref::<quinn::WriteError>() {
                    Self::Write(e.clone())
                } else {
                    Self::Io(cause)
                }
            } else {
                Self::Io(cause)
            }
        }
    }

    impl From<ConnectedNextError> for io::Error {
        fn from(cause: ConnectedNextError) -> Self {
            match cause {
                ConnectedNextError::Write(cause) => cause.into(),
                ConnectedNextError::Io(cause) => cause,
                ConnectedNextError::PostcardSer(cause) => {
                    io::Error::new(io::ErrorKind::Other, cause)
                }
                _ => io::Error::new(io::ErrorKind::Other, cause),
            }
        }
    }

    impl AtConnected {
        /// Send the request and move to the next state
        ///
        /// The next state will be either `StartRoot` or `StartChild` depending on whether
        /// the request requests part of the collection or not.
        ///
        /// If the request is empty, this can also move directly to `Finished`.
        pub async fn next(self) -> Result<ConnectedNext, ConnectedNextError> {
            let Self {
                start,
                reader,
                mut writer,
                mut request,
            } = self;
            // 1. Send Request
            {
                debug!("sending request");
                let wrapped = Request::Get(request);
                let request_bytes =
                    postcard::to_stdvec(&wrapped).map_err(ConnectedNextError::PostcardSer)?;
                let Request::Get(x) = wrapped;
                request = x;

                if request_bytes.len() > MAX_MESSAGE_SIZE {
                    return Err(ConnectedNextError::RequestTooBig);
                }

                // write the request itself
                writer
                    .write_all(&request_bytes)
                    .await
                    .map_err(ConnectedNextError::from_io)?;
            }

            // 2. Finish writing before expecting a response
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
                        AtStartRoot {
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
                None => AtClosing::new(misc, reader).into(),
            })
        }
    }

    /// State of the get response when we start reading a collection
    #[derive(Debug)]
    pub struct AtStartRoot {
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
        /// This must be used to determine the hash needed to call next.
        /// If this is larger than the number of children in the collection,
        /// you can call finish to stop reading the response.
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
        pub fn next(self, hash: Hash) -> AtBlobHeader {
            let stream = ResponseDecoderStart::<TrackingReader<RecvStream>>::new(
                hash.into(),
                self.ranges,
                IROH_BLOCK_SIZE,
                self.reader,
            );
            AtBlobHeader {
                stream,
                misc: self.misc,
            }
        }

        /// Finish the get response without reading further
        ///
        /// This is used if you know that there are no more children from having
        /// read the collection, or when you want to stop reading the response
        /// early.
        pub fn finish(self) -> AtClosing {
            AtClosing::new(self.misc, self.reader)
        }
    }

    impl AtStartRoot {
        /// The ranges we have requested for the child
        pub fn ranges(&self) -> &RangeSet2<ChunkNum> {
            &self.ranges
        }

        /// Hash of the root blob
        pub fn hash(&self) -> &Hash {
            &self.hash
        }

        /// Go into the next state, reading the header
        ///
        /// For the collection we already know the hash, since it was part of the request
        pub fn next(self) -> AtBlobHeader {
            let stream = ResponseDecoderStart::new(
                self.hash.into(),
                self.ranges,
                IROH_BLOCK_SIZE,
                self.reader,
            );
            AtBlobHeader {
                stream,
                misc: self.misc,
            }
        }

        /// Finish the get response without reading further
        pub fn finish(self) -> AtClosing {
            AtClosing::new(self.misc, self.reader)
        }
    }

    /// State before reading a size header
    #[derive(Debug)]
    pub struct AtBlobHeader {
        stream: ResponseDecoderStart<TrackingReader<RecvStream>>,
        misc: Box<Misc>,
    }

    /// Error that you can get from [`AtBlobHeader::next`]
    #[derive(Debug, thiserror::Error)]
    pub enum AtBlobHeaderNextError {
        /// Eof when reading the size header
        ///
        /// This indicates that the provider does not have the requested data.
        #[error("not found")]
        NotFound,
        /// Quinn read error when reading the size header
        #[error("read: {0}")]
        Read(quinn::ReadError),
        /// Generic io error
        #[error("io: {0}")]
        Io(io::Error),
    }

    impl From<AtBlobHeaderNextError> for io::Error {
        fn from(cause: AtBlobHeaderNextError) -> Self {
            match cause {
                AtBlobHeaderNextError::NotFound => {
                    io::Error::new(io::ErrorKind::UnexpectedEof, cause)
                }
                AtBlobHeaderNextError::Read(cause) => cause.into(),
                AtBlobHeaderNextError::Io(cause) => cause,
            }
        }
    }

    impl AtBlobHeader {
        /// Read the size header, returning it and going into the `Content` state.
        pub async fn next(self) -> Result<(AtBlobContent, u64), AtBlobHeaderNextError> {
            match self.stream.next().await {
                Ok((stream, size)) => Ok((
                    AtBlobContent {
                        stream,
                        misc: self.misc,
                    },
                    size,
                )),
                Err(cause) => Err(match cause {
                    StartDecodeError::NotFound => AtBlobHeaderNextError::NotFound,
                    StartDecodeError::Io(cause) => {
                        if let Some(inner) = cause.get_ref() {
                            if let Some(e) = inner.downcast_ref::<quinn::ReadError>() {
                                AtBlobHeaderNextError::Read(e.clone())
                            } else {
                                AtBlobHeaderNextError::Io(cause)
                            }
                        } else {
                            AtBlobHeaderNextError::Io(cause)
                        }
                    }
                }),
            }
        }

        /// Drain the response and throw away the result
        pub async fn drain(self) -> result::Result<AtEndBlob, DecodeError> {
            let (mut content, _size) = self.next().await?;
            loop {
                match content.next().await {
                    BlobContentNext::More((content1, Ok(_))) => {
                        content = content1;
                    }
                    BlobContentNext::More((_, Err(e))) => return Err(e),
                    BlobContentNext::Done(end) => {
                        return Ok(end);
                    }
                }
            }
        }

        /// Concatenate the entire response into a vec
        ///
        /// For a request that does not request the complete blob, this will just
        /// concatenate the ranges that were requested.
        pub async fn concatenate_into_vec(
            self,
        ) -> result::Result<(AtEndBlob, Vec<u8>), DecodeError> {
            let (mut curr, size) = self.next().await?;
            let mut res = Vec::with_capacity(size as usize);
            let done = loop {
                match curr.next().await {
                    BlobContentNext::More((next, data)) => {
                        if let BaoContentItem::Leaf(leaf) = data? {
                            res.extend_from_slice(&leaf.data);
                        }
                        curr = next;
                    }
                    BlobContentNext::Done(done) => {
                        // we are done with the root blob
                        break done;
                    }
                }
            };
            Ok((done, res))
        }

        /// Write the entire blob to a slice writer.
        pub async fn write_all<D: AsyncSliceWriter>(
            self,
            data: D,
        ) -> result::Result<AtEndBlob, DecodeError> {
            let (content, _size) = self.next().await?;
            let res = content.write_all(data).await?;
            Ok(res)
        }

        /// Write the entire blob to a slice writer and to an optional outboard.
        ///
        /// The outboard is only written to if the blob is larger than a single
        /// chunk group.
        pub async fn write_all_with_outboard<D, O>(
            self,
            outboard: Option<O>,
            data: D,
        ) -> result::Result<AtEndBlob, DecodeError>
        where
            D: AsyncSliceWriter,
            O: OutboardMut,
        {
            let (content, _size) = self.next().await?;
            let res = content.write_all_with_outboard(outboard, data).await?;
            Ok(res)
        }

        /// The hash of the blob we are reading.
        pub fn hash(&self) -> Hash {
            (*self.stream.hash()).into()
        }

        /// The ranges we have requested for the current hash.
        pub fn ranges(&self) -> &RangeSet2<ChunkNum> {
            self.stream.ranges()
        }
    }

    /// State while we are reading content
    #[derive(Debug)]
    pub struct AtBlobContent {
        stream: ResponseDecoderReading<TrackingReader<RecvStream>>,
        misc: Box<Misc>,
    }

    /// Decode error that you can get once you have sent the request and are
    /// decoding the response, e.g. from [`AtBlobContent::next`].
    ///
    /// This is similar to [`bao_tree::io::DecodeError`], but takes into account
    /// that we are reading from a [`quinn::RecvStream`], so read errors will be
    /// propagated as [`DecodeError::Read`], containing a [`quinn::ReadError`].
    /// This carries more concrete information about the error than an [`io::Error`].
    ///
    /// When the provider finds that it does not have a chunk that we requested,
    /// or that the chunk is invalid, it will stop sending data without producing
    /// an error. This is indicated by either the [`DecodeError::ParentNotFound`] or
    /// [`DecodeError::LeafNotFound`] variant, which can be used to detect that data
    /// is missing but the connection as well that the provider is otherwise healthy.
    ///
    /// The [`DecodeError::ParentHashMismatch`] and [`DecodeError::LeafHashMismatch`]
    /// variants indicate that the provider has sent us invalid data. A well-behaved
    /// provider should never do this, so this is an indication that the provider is
    /// not behaving correctly.
    ///
    /// The [`DecodeError::Io`] variant is just a fallback for any other io error that
    /// is not actually a [`quinn::ReadError`].
    #[derive(Debug, thiserror::Error)]
    pub enum DecodeError {
        /// A chunk was not found or invalid, so the provider stopped sending data
        #[error("not found")]
        NotFound,
        /// A parent was not found or invalid, so the provider stopped sending data
        #[error("parent not found {0:?}")]
        ParentNotFound(TreeNode),
        /// A parent was not found or invalid, so the provider stopped sending data
        #[error("chunk not found {0}")]
        LeafNotFound(ChunkNum),
        /// The hash of a parent did not match the expected hash
        #[error("parent hash mismatch: {0:?}")]
        ParentHashMismatch(TreeNode),
        /// The hash of a leaf did not match the expected hash
        #[error("leaf hash mismatch: {0}")]
        LeafHashMismatch(ChunkNum),
        /// Error when reading from the stream
        #[error("read: {0}")]
        Read(quinn::ReadError),
        /// A generic io error
        #[error("io: {0}")]
        Io(#[from] io::Error),
    }

    impl From<AtBlobHeaderNextError> for DecodeError {
        fn from(cause: AtBlobHeaderNextError) -> Self {
            match cause {
                AtBlobHeaderNextError::NotFound => Self::NotFound,
                AtBlobHeaderNextError::Read(cause) => Self::Read(cause),
                AtBlobHeaderNextError::Io(cause) => Self::Io(cause),
            }
        }
    }

    impl From<DecodeError> for io::Error {
        fn from(cause: DecodeError) -> Self {
            match cause {
                DecodeError::ParentNotFound(_) => {
                    io::Error::new(io::ErrorKind::UnexpectedEof, cause)
                }
                DecodeError::LeafNotFound(_) => io::Error::new(io::ErrorKind::UnexpectedEof, cause),
                DecodeError::Read(cause) => cause.into(),
                DecodeError::Io(cause) => cause,
                _ => io::Error::new(io::ErrorKind::Other, cause),
            }
        }
    }

    impl From<bao_tree::io::DecodeError> for DecodeError {
        fn from(value: bao_tree::io::DecodeError) -> Self {
            match value {
                bao_tree::io::DecodeError::ParentNotFound(x) => Self::ParentNotFound(x),
                bao_tree::io::DecodeError::LeafNotFound(x) => Self::LeafNotFound(x),
                bao_tree::io::DecodeError::ParentHashMismatch(node) => {
                    Self::ParentHashMismatch(node)
                }
                bao_tree::io::DecodeError::LeafHashMismatch(chunk) => Self::LeafHashMismatch(chunk),
                bao_tree::io::DecodeError::Io(cause) => {
                    if let Some(inner) = cause.get_ref() {
                        if let Some(e) = inner.downcast_ref::<quinn::ReadError>() {
                            Self::Read(e.clone())
                        } else {
                            Self::Io(cause)
                        }
                    } else {
                        Self::Io(cause)
                    }
                }
            }
        }
    }

    /// The next state after reading a content item
    #[derive(Debug, From)]
    pub enum BlobContentNext {
        /// We expect more content
        More((AtBlobContent, result::Result<BaoContentItem, DecodeError>)),
        /// We are done with this blob
        Done(AtEndBlob),
    }

    impl AtBlobContent {
        /// Read the next item, either content, an error, or the end of the blob
        pub async fn next(self) -> BlobContentNext {
            match self.stream.next().await {
                ResponseDecoderReadingNext::More((stream, res)) => {
                    let next = Self { stream, ..self };
                    let res = res.map_err(DecodeError::from);
                    BlobContentNext::More((next, res))
                }
                ResponseDecoderReadingNext::Done(stream) => BlobContentNext::Done(AtEndBlob {
                    stream,
                    misc: self.misc,
                }),
            }
        }

        /// The geometry of the tree we are currently reading.
        pub fn tree(&self) -> bao_tree::BaoTree {
            self.stream.tree()
        }

        /// The hash of the blob we are reading.
        pub fn hash(&self) -> &blake3::Hash {
            self.stream.hash()
        }

        /// Write the entire blob to a slice writer and to an optional outboard.
        ///
        /// The outboard is only written to if the blob is larger than a single
        /// chunk group.
        pub async fn write_all_with_outboard<D, O>(
            self,
            mut outboard: Option<O>,
            mut data: D,
        ) -> result::Result<AtEndBlob, DecodeError>
        where
            D: AsyncSliceWriter,
            O: OutboardMut,
        {
            let mut content = self;
            loop {
                match content.next().await {
                    BlobContentNext::More((content1, item)) => {
                        content = content1;
                        match item? {
                            BaoContentItem::Parent(parent) => {
                                if let Some(outboard) = outboard.as_mut() {
                                    outboard.save(parent.node, &parent.pair).await?;
                                }
                            }
                            BaoContentItem::Leaf(leaf) => {
                                data.write_bytes_at(leaf.offset.0, leaf.data).await?;
                            }
                        }
                    }
                    BlobContentNext::Done(end) => {
                        return Ok(end);
                    }
                }
            }
        }

        /// Write the entire blob to a slice writer.
        pub async fn write_all<D>(self, mut data: D) -> result::Result<AtEndBlob, DecodeError>
        where
            D: AsyncSliceWriter,
        {
            let mut content = self;
            loop {
                match content.next().await {
                    BlobContentNext::More((content1, item)) => {
                        content = content1;
                        match item? {
                            BaoContentItem::Parent(_) => {}
                            BaoContentItem::Leaf(leaf) => {
                                data.write_bytes_at(leaf.offset.0, leaf.data).await?;
                            }
                        }
                    }
                    BlobContentNext::Done(end) => {
                        return Ok(end);
                    }
                }
            }
        }
    }

    /// State after we have read all the content for a blob
    #[derive(Debug)]
    pub struct AtEndBlob {
        stream: TrackingReader<RecvStream>,
        misc: Box<Misc>,
    }

    /// The next state after the end of a blob
    #[derive(Debug, From)]
    pub enum EndBlobNext {
        /// Response is expected to have more children
        MoreChildren(AtStartChild),
        /// No more children expected
        Closing(AtClosing),
    }

    impl AtEndBlob {
        /// Read the next child, or finish
        pub fn next(mut self) -> EndBlobNext {
            if let Some((offset, ranges)) = self.misc.ranges_iter.next() {
                AtStartChild {
                    reader: self.stream,
                    child_offset: offset - 1,
                    ranges,
                    misc: self.misc,
                }
                .into()
            } else {
                AtClosing::new(self.misc, self.stream).into()
            }
        }
    }

    /// State when finishing the get response
    #[derive(Debug)]
    pub struct AtClosing {
        misc: Box<Misc>,
        reader: TrackingReader<RecvStream>,
    }

    impl AtClosing {
        fn new(misc: Box<Misc>, reader: TrackingReader<RecvStream>) -> Self {
            Self { misc, reader }
        }

        /// Finish the get response, returning statistics
        pub async fn next(self) -> result::Result<Stats, quinn::ReadError> {
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
    Decode(bao_tree::io::DecodeError),
    /// A generic error
    #[error("generic: {0}")]
    Generic(anyhow::Error),
}

impl From<postcard::Error> for GetResponseError {
    fn from(cause: postcard::Error) -> Self {
        Self::Generic(cause.into())
    }
}

impl From<bao_tree::io::DecodeError> for GetResponseError {
    fn from(cause: bao_tree::io::DecodeError) -> Self {
        match cause {
            bao_tree::io::DecodeError::Io(cause) => {
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

impl From<GetResponseError> for std::io::Error {
    fn from(cause: GetResponseError) -> Self {
        Self::new(std::io::ErrorKind::Other, cause)
    }
}
