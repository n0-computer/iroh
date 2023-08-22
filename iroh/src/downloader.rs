//! Handle downloading blobs and collections concurrently and from multiple peers.
//!

#![allow(clippy::all, unused, missing_docs)]

use std::collections::HashMap;

use iroh_bytes::{
    protocol::{RangeSpec, RangeSpecSeq},
    Hash,
};
use iroh_net::key::PublicKey;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

/// Download identifier.
// Mainly for readability.
pub type Id = u64;

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

/// Kind of sources that canm be used to perform a download.
// TODO(@divma): likely we will end up using only onme of these. Curiously, I'm not sure which is
// more ilkely
#[derive(Debug)]
pub enum Source {
    /// Perform the download from any available source.
    ///
    /// Sources can be added via [`Downloader::add_source`] with [`DownloadHandle::id`].
    // TODO(@divma): do we want to add an optional initial source?
    // - we want. Maybe this saves a subsequent, awkward call to `add_source`
    // - we don't want. Whatever discovery mechanism we have will be asked and the optional initial
    // source should be registered there. If the sources registry has no peer for this download
    // then the download fails without more retries. Reasoning behind this would be that there is
    // no way to know when to check again for sources for this download.
    // both options sound likely/reasonable
    Available,
    /// Perform the download only from sources registered for the request.
    ///
    /// Sources can be added via [`Downloader::add_source`] with [`DownloadHandle::id`].
    Specific {
        // TODO(@divma): what are we supposed to call this now?
        source_key: PublicKey,
    },
}

/// Handle to interact with a download request.
#[derive(derive_more::Debug)]
pub struct DownloadHandle {
    /// Id used to identify the request in the [`Downloader`].
    id: u64,
    /// Token used to cancel this request.
    #[debug(skip)]
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

#[derive(Debug)]
pub struct Downloader;

#[derive(Debug)]
struct DownloadInfo {
    /// Kind of download we are performing. This maintains the intent as registerd with the
    /// downloader.
    // NOTE: this is useful and necessary because the wire request associated to a download will be
    // different in different instants depending on what local data we already have
    kind: Download,
    /// How many times can this request be attempted again before declearing it failed.
    // TODO(@divma): we likely want to distinguish between io/transport errors and unexpected
    // conditions/miss-behaviours such as the source not having the requested data, decoding
    // errors, etc. Transport errors could allow for more attempts than serious errors such as the
    // source sending that that can't be decoded, or not having the requested data.
    remaining_retries: u8,
}

#[derive(Debug)]
pub struct DownloadService {
    /// Download requests as received by the
    current_downloads: HashMap<Id, DownloadInfo>,
}

impl Downloader {
    pub fn add_source(&self, id: u64, source: PublicKey) {
        // TODO(@divma): send the add source message
    }
}
