#![allow(dead_code)]
//! An implementation of the bao SliceDecoder allowing both sync and async usage
//!
//! this is a stripped down version of a crate that does the blake3 outboard in
//! traversal order, whereas the bao crate itself does it in post-order and then
//! flips to pre-order.
use futures::{ready, Stream};

use blake3::guts::CHUNK_LEN;
use std::{
    io::{self, Read},
    ops::Range,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::ReadBuf;
const CHUNK_LEN_U64: u64 = CHUNK_LEN as u64;
type BlockNum = u64;
type NodeNum = u64;

/// Root offset given a number of leaves.
fn root(leafs: BlockNum) -> NodeNum {
    leafs.next_power_of_two() - 1
}

/// Level for an offset. 0 is for leaves, 1 is for the first level of branches, etc.
fn level(offset: NodeNum) -> u32 {
    (!offset).trailing_zeros()
}

/// number of blocks, given a size in bytes
fn blocks(len: u64) -> BlockNum {
    const BLOCK_SIZE: u64 = CHUNK_LEN as u64;
    len / BLOCK_SIZE + u64::from(len % BLOCK_SIZE != 0)
}

/// number of hashes (leaf or branch) given a number of blocks
fn num_hashes(blocks: BlockNum) -> NodeNum {
    if blocks > 0 {
        blocks * 2 - 1
    } else {
        1
    }
}

/// span of an offset - 1 for leaf nodes
fn span(offset: NodeNum) -> NodeNum {
    1 << level(offset)
}

/// left child of a node
fn left_child(offset: NodeNum) -> Option<NodeNum> {
    let span = span(offset);
    if span == 1 {
        None
    } else {
        Some(offset - span / 2)
    }
}

/// right child of a node
fn right_child(offset: NodeNum) -> Option<NodeNum> {
    let span = span(offset);
    if span == 1 {
        None
    } else {
        Some(offset + span / 2)
    }
}

/// valid right descendant for an offset
fn right_descendant(offset: NodeNum, len: NodeNum) -> Option<NodeNum> {
    let mut offset = right_child(offset)?;
    while offset >= len {
        offset = left_child(offset)?;
    }
    Some(offset)
}

pub struct SliceIter {
    len: u64,
    range: Range<u64>,
    res: Option<std::iter::Peekable<std::vec::IntoIter<StreamItem>>>,
}

impl SliceIter {
    pub fn new(len: u64, range: Range<u64>) -> Self {
        SliceIter {
            len,
            range,
            res: None,
        }
    }

    /// set the length of the slice
    ///
    /// this can only be done before the first call to next
    pub fn set_len(&mut self, len: u64) {
        assert!(self.res.is_none());
        self.len = len;
    }

    // todo: it is easy to make this a proper iterator, and even possible
    // to make it an iterator without any state, but let's just keep it simple
    // for now.
    fn iterate(len: u64, range: Range<u64>) -> Vec<StreamItem> {
        struct State {
            len: u64,
            range: Range<u64>,
            res: Vec<StreamItem>,
        }
        // make sure the range is within 0..len
        let mut range = range;
        range.start = range.start.min(len);
        range.end = range.end.min(len);
        impl State {
            fn hashes(&self) -> u64 {
                num_hashes(blocks(self.len))
            }

            fn traverse(&mut self, offset: u64) {
                let position = (offset + 1) / 2 * CHUNK_LEN_U64;
                let is_root = offset == root(blocks(self.len));
                if level(offset) > 0 {
                    let (left, right) = if self.range.end <= position {
                        (true, false)
                    } else if self.range.start >= position {
                        (false, true)
                    } else {
                        (true, true)
                    };
                    self.res.push(StreamItem::Hashes {
                        left,
                        right,
                        is_root,
                    });
                    if left {
                        self.traverse(left_child(offset).unwrap());
                    }
                    if right {
                        self.traverse(right_descendant(offset, self.hashes()).unwrap());
                    }
                } else {
                    let start = position;
                    let end = (start + CHUNK_LEN_U64).min(self.len);
                    self.res.push(StreamItem::Data {
                        start,
                        end,
                        is_root,
                    });
                }
            }
        }
        let mut state = State {
            len,
            range,
            res: vec![],
        };
        state.traverse(root(blocks(len)));
        state.res
    }

    pub fn peek(&mut self) -> Option<StreamItem> {
        match self.res {
            Some(ref mut res) => res.peek().cloned(),
            None => Some(StreamItem::Header),
        }
    }
}

impl Iterator for SliceIter {
    type Item = StreamItem;

    fn next(&mut self) -> Option<StreamItem> {
        match self.res {
            Some(ref mut res) => res.next(),
            None => {
                // compute the actual items, since we now have the length
                self.res = Some(
                    SliceIter::iterate(self.len, self.range.clone())
                        .into_iter()
                        .peekable(),
                );
                Some(StreamItem::Header)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum StreamItem {
    /// expect a 8 byte header
    Header,
    /// you will get 2 hashes, so 64 bytes.
    /// at least one of them will be relevant for later.
    Hashes {
        /// the left hash will be relevant for later and needs to be pushed on the stack
        left: bool,
        /// the right hash will be relevant for later and needs to be pushed on the stack
        right: bool,
        /// is this branch the root
        is_root: bool,
    },
    /// you will get data for this range.
    /// you will need to verify this data against the hashes on the stack.
    /// the data to be actually returned can be just a subset of this.
    Data {
        /// start of the range
        start: u64,
        /// end of the range
        end: u64,
        /// is this leaf the root
        is_root: bool,
    },
}

impl StreamItem {
    /// size of the stream item in bytes, at most CHUNK_LEN
    pub fn size(&self) -> usize {
        match self {
            StreamItem::Header => 8,
            StreamItem::Hashes { .. } => 64,
            StreamItem::Data { start, end, .. } => (end - start) as usize,
        }
    }

    pub fn is_data(&self) -> bool {
        matches!(self, StreamItem::Data { .. })
    }
}

pub struct SliceValidator<R> {
    /// the inner reader
    inner: R,

    /// The slice iterator
    ///
    /// This is used to figure out what to expect from the reader.
    ///
    /// It also stores and provides the total length and the slice range.
    iter: SliceIter,

    // hash stack for validation
    //
    // gets initialized with the root hash
    stack: Vec<blake3::Hash>,

    // buffer for incomplete items
    //
    // this is used for both reading and writing
    //
    // it can contain an 8 byte header, 64 bytes of hashes or up to 1024 bytes of data
    buf: [u8; CHUNK_LEN],

    // start of the buffer
    //
    // when incrementally reading a buffer in the async reader, this indicates the
    // start of the free part of the buffer
    //
    // when incrementally writing a buffer in both the sync and async reader, this
    // indicates the start of the occupied part of the buffer
    //
    // the overall length of the buffer is in both cases determined by the current item
    buf_start: usize,
}

impl<R> SliceValidator<R> {
    /// create a new slice validator for the given hash and range
    pub fn new(inner: R, hash: blake3::Hash, start: u64, len: u64) -> Self {
        let range = start..start.saturating_add(len);
        Self {
            inner,
            iter: SliceIter::new(0, range.start..range.end),
            stack: vec![hash],
            buf: [0; CHUNK_LEN],
            buf_start: 0,
        }
    }

    /// get back the wrapped reader
    pub fn into_inner(self) -> R {
        self.inner
    }

    fn range(&self) -> &Range<u64> {
        &self.iter.range
    }

    /// given a stream item, get the part of the buffer that is relevant for it
    fn get_buffer(&self, item: &StreamItem) -> &[u8] {
        match item {
            StreamItem::Header => &self.buf[0..8],
            StreamItem::Hashes { .. } => &self.buf[0..64],
            StreamItem::Data { start, end, .. } => {
                let range = self.range();
                let start1 = start.max(&range.start);
                let end1 = end.min(&range.end);
                let start2 = (start1 - start) as usize;
                let end2 = (end1 - start) as usize;
                &self.buf[start2..end2]
            }
        }
    }

    fn next_with_full_buffer(&mut self, item: StreamItem) -> Result<Option<StreamItem>, &str> {
        match item {
            StreamItem::Header => {
                let len = u64::from_le_bytes(self.buf[0..8].try_into().unwrap());
                self.iter.set_len(len);
            }
            StreamItem::Hashes {
                left,
                right,
                is_root,
            } => {
                let lc = blake3::Hash::from(<[u8; 32]>::try_from(&self.buf[0..32]).unwrap());
                let rc = blake3::Hash::from(<[u8; 32]>::try_from(&self.buf[32..64]).unwrap());
                let expected = self.stack.pop().unwrap();
                let actual = blake3::guts::parent_cv(&lc, &rc, is_root);
                if expected != actual {
                    return Err("invalid branch hash");
                }
                // push the hashes on the stack in *reverse* order
                if right {
                    self.stack.push(rc);
                }
                if left {
                    self.stack.push(lc);
                }
            }
            StreamItem::Data {
                start,
                end,
                is_root,
            } => {
                debug_assert!(start % CHUNK_LEN_U64 == 0);
                let chunk = start / CHUNK_LEN_U64;
                let mut hasher = blake3::guts::ChunkState::new(chunk);
                let size = end - start;
                hasher.update(&self.buf[0..size as usize]);
                let expected = self.stack.pop().unwrap();
                let actual = hasher.finalize(is_root);
                if expected != actual {
                    return Err("invalid leaf hash");
                }
            }
        }
        Ok(self.iter.next())
    }

    /// get the stream item we would get next
    fn peek(&mut self) -> Option<StreamItem> {
        self.iter.peek()
    }
}

impl<R: Read> Iterator for SliceValidator<R> {
    type Item = std::io::Result<StreamItem>;

    fn next(&mut self) -> Option<Self::Item> {
        let iter = &mut self.iter;

        // get next item - if there is none, we are done
        let item = iter.peek()?;

        // read the item, whatever it is
        if let Err(cause) = self.inner.read_exact(&mut self.buf[0..item.size()]) {
            return Some(Err(cause));
        }

        // validate and return the item
        self.next_with_full_buffer(item)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
            .transpose()
    }
}

pub struct AsyncSliceValidator<R: tokio::io::AsyncRead + Unpin>(SliceValidator<R>);

impl<R: tokio::io::AsyncRead + Unpin> AsyncSliceValidator<R> {
    /// create a new slice validator for the given hash and range
    pub fn new(inner: R, hash: blake3::Hash, start: u64, len: u64) -> Self {
        Self(SliceValidator::new(inner, hash, start, len))
    }

    pub fn into_inner(self) -> R {
        self.0.into_inner()
    }
}

impl<R: tokio::io::AsyncRead + Unpin> SliceValidator<R> {
    /// fill the buffer with at least `size` bytes
    fn fill_buffer(&mut self, cx: &mut Context<'_>, size: usize) -> Poll<io::Result<()>> {
        debug_assert!(size <= self.buf.len());
        debug_assert!(self.buf_start <= size);
        let mut buf = ReadBuf::new(&mut self.buf[..size]);
        buf.advance(self.buf_start);
        while buf.filled().len() < size {
            let len0 = buf.filled().len();
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buf)?);
            if buf.filled().len() == len0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                )));
            }
            self.buf_start = buf.filled().len();
        }
        self.buf_start = 0;
        Poll::Ready(Ok(()))
    }

    fn poll_next_impl(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<tokio::io::Result<StreamItem>>> {
        let current = match self.peek() {
            Some(item) => item,
            None => return Poll::Ready(None),
        };
        let size = current.size();
        ready!(self.fill_buffer(cx, size))?;

        let item = self
            .next_with_full_buffer(current)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
        Poll::Ready(item.transpose())
    }
}

impl<R: tokio::io::AsyncRead + Unpin> Stream for AsyncSliceValidator<R> {
    type Item = tokio::io::Result<StreamItem>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.poll_next_impl(cx)
    }
}

pub struct SliceDecoder<R> {
    inner: SliceValidator<R>,
    current_item: Option<StreamItem>,
}

impl<R: Read> SliceDecoder<R> {
    pub fn new(inner: R, hash: &blake3::Hash, start: u64, len: u64) -> Self {
        Self {
            inner: SliceValidator::new(inner, *hash, start, len),
            current_item: None,
        }
    }

    pub fn into_inner(self) -> R {
        self.inner.into_inner()
    }
}

impl<R: Read> Read for SliceDecoder<R> {
    fn read(&mut self, tgt: &mut [u8]) -> io::Result<usize> {
        loop {
            // if we have no current item, get the next one
            if self.current_item.is_none() {
                self.current_item = match self.inner.next().transpose()? {
                    Some(item) if item.is_data() => Some(item),
                    Some(_) => continue,
                    None => break Ok(0),
                };
                self.inner.buf_start = 0;
            }

            // if we get here we we have a data item.
            let item = self.current_item.as_ref().unwrap();
            let src = self.inner.get_buffer(item);
            if src.is_empty() {
                self.current_item = None;
                self.inner.buf_start = 0;
                continue;
            }
            let n = (src.len() - self.inner.buf_start).min(tgt.len());
            let end = self.inner.buf_start + n;
            tgt[0..n].copy_from_slice(&src[self.inner.buf_start..end]);
            if end < src.len() {
                self.inner.buf_start = end;
            } else {
                self.current_item = None;
                self.inner.buf_start = 0;
            }
            debug_assert!(n > 0, "we should have read something");
            break Ok(n);
        }
    }
}

pub struct AsyncSliceDecoder<R: tokio::io::AsyncRead + Unpin> {
    inner: SliceValidator<R>,
    current_item: Option<StreamItem>,
}

impl<R: tokio::io::AsyncRead + Unpin> AsyncSliceDecoder<R> {
    pub fn new(inner: R, hash: blake3::Hash, start: u64, len: u64) -> Self {
        Self {
            inner: SliceValidator::new(inner, hash, start, len),
            current_item: None,
        }
    }

    pub fn into_inner(self) -> R {
        self.inner.into_inner()
    }
}

impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for AsyncSliceDecoder<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        tgt: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let res = Poll::Ready(loop {
            // if we have no current item, get the next one
            if self.current_item.is_none() {
                self.current_item = match ready!(self.inner.poll_next_impl(cx)).transpose()? {
                    Some(item) if item.is_data() => Some(item),
                    Some(_) => continue,
                    None => break Ok(()),
                };
                self.inner.buf_start = 0;
            }

            // if we get here we we have a data item.
            let item = self.current_item.as_ref().unwrap();
            let src = self.inner.get_buffer(item);
            if src.is_empty() {
                self.current_item = None;
                self.inner.buf_start = 0;
                continue;
            }
            let start = self.inner.buf_start;
            let n = (src.len() - start).min(tgt.remaining());
            let end = start + n;
            tgt.put_slice(&src[start..end]);
            if end < src.len() {
                self.inner.buf_start = end;
            } else {
                self.current_item = None;
                self.inner.buf_start = 0;
            }
            debug_assert!(n > 0, "we should have read something");
            break Ok(());
        });
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bao::encode::SliceExtractor;
    use futures::StreamExt;
    use proptest::prelude::*;
    use std::io::{Cursor, Read};
    use tokio::io::AsyncReadExt;

    fn create_test_data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i / CHUNK_LEN) as u8).collect()
    }

    /// Encode a slice of the given data and return the hash and the encoded slice, using the bao encoder
    fn encode_slice(data: &[u8], slice_start: u64, slice_len: u64) -> (blake3::Hash, Vec<u8>) {
        let (encoded, hash) = bao::encode::encode(data);
        let mut extractor = SliceExtractor::new(Cursor::new(&encoded), slice_start, slice_len);
        let mut slice = vec![];
        extractor.read_to_end(&mut slice).unwrap();
        (hash, slice)
    }

    /// Test implementation for the test_decode_all test, to be called by both proptest and hardcoded tests
    fn test_decode_all_sync_impl(len: u64) {
        // create a slice encoding the entire data - equivalent to the bao inline encoding
        let test_data = create_test_data(len as usize);
        let (hash, slice) = encode_slice(&test_data, 0, len);

        // test just validation without reading
        let mut cursor = Cursor::new(&slice);
        let validator = SliceValidator::new(&mut cursor, hash, 0, len);
        for item in validator {
            assert!(item.is_ok());
        }
        // check that we have read the entire slice
        assert_eq!(cursor.position(), slice.len() as u64);

        // test validation and reading
        let mut cursor = std::io::Cursor::new(&slice);
        let mut reader = SliceDecoder::new(&mut cursor, &hash, 0, len);
        let mut data = vec![];
        reader.read_to_end(&mut data).unwrap();
        assert_eq!(data, test_data);

        // check that we have read the entire slice
        assert_eq!(cursor.position(), slice.len() as u64);
    }

    /// Test implementation for the test_decode_all test, to be called by both proptest and hardcoded tests
    async fn test_decode_all_async_impl(len: u64) {
        // create a slice encoding the entire data - equivalent to the bao inline encoding
        let test_data = create_test_data(len as usize);
        let (hash, slice) = encode_slice(&test_data, 0, len);

        // test just validation without reading
        let mut cursor = std::io::Cursor::new(&slice);
        let mut validator = AsyncSliceValidator::new(&mut cursor, hash, 0, len);
        while let Some(item) = validator.next().await {
            assert!(item.is_ok());
        }
        // check that we have read the entire slice
        assert_eq!(cursor.position(), slice.len() as u64);

        // test validation and reading
        let mut cursor = std::io::Cursor::new(&slice);
        let mut reader = AsyncSliceDecoder::new(&mut cursor, hash, 0, len);
        let mut data = vec![];
        reader.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, test_data);

        // check that we have read the entire slice
        assert_eq!(cursor.position(), slice.len() as u64);
    }

    /// Test implementation for the test_decode_part test, to be called by both proptest and hardcoded tests
    fn test_decode_part_sync_impl(len: u64, slice_start: u64, slice_len: u64) {
        let test_data = create_test_data(len as usize);
        // create a slice encoding the given range
        let (hash, slice) = encode_slice(&test_data, slice_start, slice_len);
        // SliceIter::print_bao_encoded(len, slice_start..slice_start + slice_len, &slice);

        // create an inner decoder to decode the entire slice
        let mut cursor = Cursor::new(&slice);
        let validator = SliceValidator::new(&mut cursor, hash, slice_start, slice_len);
        for item in validator {
            assert!(item.is_ok());
        }
        // check that we have read the entire slice
        assert_eq!(cursor.position(), slice.len() as u64);

        let mut cursor = Cursor::new(&slice);
        let mut reader = SliceDecoder::new(&mut cursor, &hash, slice_start, slice_len);
        let mut data = vec![];
        reader.read_to_end(&mut data).unwrap();
        // check that we have read the entire slice
        assert_eq!(cursor.position(), slice.len() as u64);
        // check that we have read the correct data
        let start = slice_start.min(len) as usize;
        let end = (slice_start + slice_len).min(len) as usize;
        assert_eq!(data, test_data[start..end]);
    }

    /// Test implementation for the test_decode_part test, to be called by both proptest and hardcoded tests
    async fn test_decode_part_async_impl(len: u64, slice_start: u64, slice_len: u64) {
        let test_data = create_test_data(len as usize);
        // create a slice encoding the given range
        let (hash, slice) = encode_slice(&test_data, slice_start, slice_len);
        // SliceIter::print_bao_encoded(len, slice_start..slice_start + slice_len, &slice);

        // create an inner decoder to decode the entire slice
        let mut cursor = std::io::Cursor::new(&slice);
        let mut validator = AsyncSliceValidator::new(&mut cursor, hash, slice_start, slice_len);
        while let Some(item) = validator.next().await {
            assert!(item.is_ok());
        }
        // check that we have read the entire slice
        assert_eq!(cursor.position(), slice.len() as u64);

        let mut cursor = std::io::Cursor::new(&slice);
        let mut reader = AsyncSliceDecoder::new(&mut cursor, hash, slice_start, slice_len);
        let mut data = vec![];
        reader.read_to_end(&mut data).await.unwrap();
        // check that we have read the entire slice
        assert_eq!(cursor.position(), slice.len() as u64);
        // check that we have read the correct data
        let start = slice_start.min(len) as usize;
        let end = (slice_start + slice_len).min(len) as usize;
        assert_eq!(data, test_data[start..end]);
    }

    /// Generate a random size, start and len
    fn size_start_len() -> impl Strategy<Value = (u64, u64, u64)> {
        (0u64..65536).prop_flat_map(|size| {
            let start = 0u64..size;
            let len = 0u64..size;
            (Just(size), start, len)
        })
    }

    fn test_decode_all_impl(size: u64) {
        test_decode_all_sync_impl(size);
        futures::executor::block_on(test_decode_all_async_impl(size));
    }

    fn test_decode_part_impl(size: u64, start: u64, len: u64) {
        test_decode_part_sync_impl(size, start, len);
        futures::executor::block_on(test_decode_part_async_impl(size, start, len));
    }

    proptest! {
        #[test]
        fn test_decode_all(len in 1u64..32768) {
            test_decode_all_impl(len)
        }

        #[test]
        fn test_decode_part((size, start, len) in size_start_len()) {
            test_decode_part_impl(size, start, len);
        }
    }

    /// manual tests for decode_all for a few interesting cases
    #[test]
    fn test_decode_all_manual() {
        // test_decode_all_impl(0);
        test_decode_all_impl(1);
        // test_decode_all_impl(1024);
        // test_decode_all_impl(1025);
        // test_decode_all_impl(2049);
        // test_decode_all_impl(12343465);
    }

    /// manual tests for decode_part for a few interesting cases
    #[test]
    fn test_decode_part_manual() {
        test_decode_part_impl(1, 0, 0);
        test_decode_part_impl(2048, 0, 1024);
        test_decode_part_impl(2048, 1024, 1024);
        test_decode_part_impl(4096, 0, 1024);
        test_decode_part_impl(4096, 1024, 1024);
        test_decode_part_impl(548, 520, 505);
        test_decode_part_impl(2126, 2048, 1);
        test_decode_part_impl(3073, 1024, 1025);
    }

    /// prints a bao encoded slice
    ///
    /// this is a simple use case for how to use the slice iterator to figure
    /// out what is what.
    #[allow(dead_code)]
    fn print_bao_encoded(len: u64, range: Range<u64>, slice: &[u8]) {
        let mut offset = 0;
        for item in SliceIter::new(len, range) {
            if slice.len() < offset + item.size() {
                println!("incomplete slice");
                return;
            }
            match item {
                StreamItem::Header => {
                    let data = &slice[offset..offset + 8];
                    println!(
                        "header  {} {}",
                        hex::encode(data),
                        u64::from_le_bytes(data.try_into().unwrap())
                    );
                }
                StreamItem::Hashes {
                    left,
                    right,
                    is_root,
                } => {
                    let data = &slice[offset..offset + 64];
                    let used = |b| if b { "*" } else { " " };
                    println!("hashes root={is_root}");
                    println!("{} {}", hex::encode(&data[..32]), used(left));
                    println!("{} {}", hex::encode(&data[32..]), used(right));
                }
                StreamItem::Data {
                    start,
                    end,
                    is_root,
                } => {
                    let size = end - start;
                    let data = &slice[offset..offset + size as usize];
                    println!("data range={}..{} root={}", start, start + size, is_root);
                    for chunk in data.chunks(32) {
                        println!("{}", hex::encode(chunk));
                    }
                }
            }
            println!();
            offset += item.size();
        }
    }

    #[test]
    fn test_right_descendant() {
        assert_eq!(right_descendant(1, 9), Some(2));
        assert_eq!(right_descendant(2, 9), None);
        assert_eq!(right_descendant(3, 9), Some(5));
        assert_eq!(right_descendant(4, 9), None);
        assert_eq!(right_descendant(5, 9), Some(6));
        assert_eq!(right_descendant(6, 9), None);
        assert_eq!(right_descendant(7, 9), Some(8));
        assert_eq!(right_descendant(8, 9), None);
        assert_eq!(right_descendant(9, 9), None);
        assert_eq!(right_descendant(10, 9), None);
    }

    #[test]
    fn test_span() {
        assert_eq!(span(0), 1);
        assert_eq!(span(1), 2);
        assert_eq!(span(2), 1);
        assert_eq!(span(3), 4);
    }

    #[test]
    fn test_level() {
        assert_eq!(level(0), 0);
        assert_eq!(level(1), 1);
        assert_eq!(level(2), 0);
        assert_eq!(level(3), 2);
    }

    #[test]
    fn test_root() {
        assert_eq!(root(0), 0);
        assert_eq!(root(1), 0);
        assert_eq!(root(2), 1);
        assert_eq!(root(3), 3);
        assert_eq!(root(4), 3);
        assert_eq!(root(5), 7);
        assert_eq!(root(6), 7);
        assert_eq!(root(7), 7);
        assert_eq!(root(8), 7);
        assert_eq!(root(9), 15);
        assert_eq!(root(10), 15);
        assert_eq!(root(11), 15);
        assert_eq!(root(12), 15);
        assert_eq!(root(13), 15);
        assert_eq!(root(14), 15);
        assert_eq!(root(15), 15);
        assert_eq!(root(16), 15);
        assert_eq!(root(17), 31);
    }
}
