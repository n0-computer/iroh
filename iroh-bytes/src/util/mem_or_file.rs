use std::{fs::File, io};

use bao_tree::io::sync::{ReadAt, Size};
use bytes::Bytes;

/// This is a general purpose Either, just like Result, except that the two cases
/// are Mem for something that is in memory, and File for something that is somewhere
/// external and only available via io.
#[derive(Debug)]
pub enum MemOrFile<M, F> {
    /// We got it all in memory
    Mem(M),
    /// A file
    File(F),
}

/// Helper methods for a common way to use MemOrFile, where the memory part is something
/// like a slice, and the file part is a tuple consisiting of path or file and size.
impl<M, F> MemOrFile<M, (F, u64)>
where
    M: AsRef<[u8]>,
{
    /// Get the size of the MemOrFile
    pub fn size(&self) -> u64 {
        match self {
            MemOrFile::Mem(mem) => mem.as_ref().len() as u64,
            MemOrFile::File((_, size)) => *size,
        }
    }
}

impl ReadAt for MemOrFile<Bytes, File> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            MemOrFile::Mem(mem) => mem.as_ref().read_at(offset, buf),
            MemOrFile::File(file) => file.read_at(offset, buf),
        }
    }
}

impl Size for MemOrFile<Bytes, File> {
    fn size(&self) -> io::Result<Option<u64>> {
        match self {
            MemOrFile::Mem(mem) => Ok(Some(mem.len() as u64)),
            MemOrFile::File(file) => file.size(),
        }
    }
}

impl<M: Default, F> Default for MemOrFile<M, F> {
    fn default() -> Self {
        MemOrFile::Mem(Default::default())
    }
}

impl<M, F> MemOrFile<M, F> {
    /// Turn a reference to a MemOrFile into a MemOrFile of references
    pub fn as_ref(&self) -> MemOrFile<&M, &F> {
        match self {
            MemOrFile::Mem(mem) => MemOrFile::Mem(mem),
            MemOrFile::File(file) => MemOrFile::File(file),
        }
    }

    /// True if this is a Mem
    pub fn is_mem(&self) -> bool {
        self.mem().is_some()
    }

    /// Get the mem part
    pub fn mem(&self) -> Option<&M> {
        match self {
            MemOrFile::Mem(mem) => Some(mem),
            MemOrFile::File(_) => None,
        }
    }

    /// Map the file part of this MemOrFile
    pub fn map_file<F2>(self, f: impl FnOnce(F) -> F2) -> MemOrFile<M, F2> {
        match self {
            MemOrFile::Mem(mem) => MemOrFile::Mem(mem),
            MemOrFile::File(file) => MemOrFile::File(f(file)),
        }
    }

    /// Try to map the file part of this MemOrFile
    pub fn try_map_file<F2, E>(
        self,
        f: impl FnOnce(F) -> Result<F2, E>,
    ) -> Result<MemOrFile<M, F2>, E> {
        match self {
            MemOrFile::Mem(mem) => Ok(MemOrFile::Mem(mem)),
            MemOrFile::File(file) => f(file).map(MemOrFile::File),
        }
    }

    /// Map the memory part of this MemOrFile
    pub fn map_mem<M2>(self, f: impl FnOnce(M) -> M2) -> MemOrFile<M2, F> {
        match self {
            MemOrFile::Mem(mem) => MemOrFile::Mem(f(mem)),
            MemOrFile::File(file) => MemOrFile::File(file),
        }
    }
}
