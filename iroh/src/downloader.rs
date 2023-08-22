//! Handle downloading blobs and collections concurrently and from multiple peers.
//!

#![allow(clippy::all, unused, missing_docs)]

use iroh_bytes::{
    protocol::{RangeSpec, RangeSpecSeq},
    Hash,
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub struct Downloader;

/// Download requests the [`Downloader`] handles.
#[derive(Debug)]
pub enum Download {
    /// Download a single blob entirely.
    Blob {
        /// Blob to be downloaded.
        hash: Hash,
    },
    /// Download ranges of a blob.
    BlobRanges {
        /// Blob to be downloaded.
        hash: Hash,
        /// Ranges to be downloaded from this blob.
        range_set: RangeSpec,
    },
    /// Download a collection entirely.
    Collection {
        /// Blob to be downloaded.
        hash: Hash,
    },
    /// Download ranges of a collection.
    CollectionRanges {
        /// Blob to be downloaded.
        hash: Hash,
        /// Sequence of ranges to be downloaded from this collection.
        range_set_seq: RangeSpecSeq,
    },
}

/// Handle to interact with a download request.
#[derive(Debug)]
pub struct DownloadHandle {
    /// Id used to identify the request in the [`Downloader`].
    id: u64,
    /// Token used to cancel this request.
    cancellation_token: CancellationToken,
    /// Receiver to retrieve the return value of this download.
    // TODO(@divma): what's the return value?
    receiver: oneshot::Receiver<u64>,
}

impl DownloadHandle {
    /// Cancels the request consuming the handle.
    pub fn cancel(self) {
        self.cancellation_token.cancel()
    }
}

impl Drop for DownloadHandle {
    fn drop(&mut self) {
        // directly cancel the request on drop
        self.cancellation_token.cancel();
    }
}
