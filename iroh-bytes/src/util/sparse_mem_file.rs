use std::io;

use bao_tree::io::sync::{ReadAt, Size, WriteAt};
use derive_more::Deref;
use range_collections::{range_set::RangeSetRange, RangeSet2};

/// A file that is sparse in memory
///
/// It is not actually using sparse storage to make reading faster, so it will
/// not conserve memory. It is just a way to remember the gaps so we can
/// write it to a file in a sparse way later.
#[derive(derive_more::Debug)]
pub struct SparseMemFile {
    /// The data, with gaps filled with zeros
    #[debug("{} bytes", data.len())]
    data: Vec<u8>,
    /// The ranges that are not zeros, so we can distinguish between zeros and gaps
    ranges: RangeSet2<usize>,
}

impl Default for SparseMemFile {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec<u8>> for SparseMemFile {
    fn from(data: Vec<u8>) -> Self {
        let ranges = RangeSet2::from(0..data.len());
        Self { data, ranges }
    }
}

impl TryInto<Vec<u8>> for SparseMemFile {
    type Error = io::Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let (data, ranges) = self.into_parts();
        if ranges == RangeSet2::from(0..data.len()) {
            Ok(data)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SparseMemFile has gaps",
            ))
        }
    }
}

impl SparseMemFile {
    /// Create a new, empty SparseMemFile
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            ranges: RangeSet2::empty(),
        }
    }

    /// Get the data and the valid ranges
    pub fn into_parts(self) -> (Vec<u8>, RangeSet2<usize>) {
        (self.data, self.ranges)
    }

    /// Persist the SparseMemFile to a WriteAt
    ///
    /// This will not persist the gaps, only the data that was written.
    pub fn persist(&self, mut target: impl WriteAt) -> io::Result<()> {
        let size = self.data.len();
        for range in self.ranges.iter() {
            let range = match range {
                RangeSetRange::Range(range) => *range.start..*range.end,
                RangeSetRange::RangeFrom(range) => *range.start..size,
            };
            let start = range.start.try_into().unwrap();
            let buf = &self.data[range];
            target.write_at(start, buf)?;
        }
        Ok(())
    }
}

impl AsRef<[u8]> for SparseMemFile {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Deref for SparseMemFile {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl ReadAt for SparseMemFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.data.read_at(offset, buf)
    }
}

impl WriteAt for SparseMemFile {
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<usize> {
        let start: usize = offset.try_into().map_err(|_| io::ErrorKind::InvalidInput)?;
        let end = start
            .checked_add(buf.len())
            .ok_or(io::ErrorKind::InvalidInput)?;
        let n = self.data.write_at(offset, buf)?;
        self.ranges |= RangeSet2::from(start..end);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Size for SparseMemFile {
    fn size(&self) -> io::Result<Option<u64>> {
        Ok(Some(self.data.len() as u64))
    }
}
