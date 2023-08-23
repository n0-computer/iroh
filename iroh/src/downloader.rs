//! Handle downloading blobs and collections concurrently and from multiple peers.
//!

#![allow(clippy::all, unused, missing_docs)]

use std::{
    collections::{hash_map::Entry, HashMap},
    task::Poll::{Pending, Ready},
};

use futures::{stream::FuturesUnordered, FutureExt};
use iroh_bytes::{
    baomap::range_collections::RangeSet2,
    protocol::{RangeSpec, RangeSpecSeq},
    Hash,
};
use iroh_net::key::PublicKey;
use tokio::sync::oneshot;
use tokio_util::{sync::CancellationToken, time::delay_queue};

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

impl Download {
    /// Get the requested hash.
    const fn hash(&self) -> &Hash {
        match self {
            Download::Blob { hash }
            | Download::BlobRanges { hash, .. }
            | Download::Collection { hash }
            | Download::CollectionRanges { hash, .. } => hash,
        }
    }

    /// Get the ranges this download is requesting.
    fn ranges(&self) -> RangeSpecSeq {
        match self {
            Download::Blob { .. } => RangeSpecSeq::new([RangeSet2::all()]),
            Download::BlobRanges { range_set, .. } => {
                RangeSpecSeq::new([range_set.to_chunk_ranges()])
            }
            Download::Collection { hash } => RangeSpecSeq::all(),
            Download::CollectionRanges {
                hash,
                range_set_seq,
            } => range_set_seq.clone(),
        }
    }
}

// TODO(@divma): mot likely drop this. Useful for now
#[derive(Debug)]
pub enum DownloadResult {
    Success,
    Failed,
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
#[derive(Debug)]
pub struct DownloadHandle {
    /// Id used to identify the request in the [`Downloader`].
    id: u64,
    /// Receiver to retrieve the return value of this download.
    receiver: oneshot::Receiver<DownloadResult>,
}

impl std::future::Future for DownloadHandle {
    type Output = DownloadResult;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        use std::task::Poll::*;
        // make it easier on holders of the handle to poll the result, removing the receiver error
        // from the middle
        match self.receiver.poll_unpin(cx) {
            Ready(Ok(result)) => Ready(result),
            Ready(Err(_recv_err)) => Ready(DownloadResult::Failed),
            Pending => Pending,
        }
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
    /// oneshot to return the download result back to the requester.
    // TODO(@divma): download futures return the id of the intent they belong to so that it can be
    // removed afterwards.
    // problem with this is that a download future could relate to multiple intents. And in the
    // future one intent can have multiple download futures if we paralelize large collection
    // downloads.
    sender: oneshot::Sender<u64>,
}

enum Message {
    Start { kind: Download, id: Id },
    Cancel { id: Id },
}

/// Information about a request.
#[derive(Debug)]
struct RequestInfo {
    /// Ids of intents ([`Download`]) associated with this request.
    intents: Vec<Id>,
    /// State of the request.
    state: RequestState,
}

#[derive(derive_more::Debug)]
enum RequestState {
    /// Request has not yet started.
    Scheduled {
        /// Key to manage the delay associated with this scheduled request.
        #[debug(skip)]
        delay_key: delay_queue::Key,
    },
    /// Request is underway.
    Active {
        /// Token used to cancel the future doing the request.
        #[debug(skip)]
        cancellation: CancellationToken,
    },
}

#[derive(Debug)]
pub struct DownloadService {
    /// Download requests as received by the [`Downloader`]. These requests might be underway or
    /// pending.
    registered_intents: HashMap<Id, DownloadInfo>,
    /// Requests performed for download intents. Two download requests can produce the same
    /// request. This map allows deduplication of efforts. These requests might be underway or
    /// pending.
    current_requests: HashMap<(Hash, RangeSpecSeq), RequestInfo>,
    /// Queue of scheduled requests.
    scheduled_requests: delay_queue::DelayQueue<(Hash, RangeSpecSeq)>,
    /// Downloas underway.
    in_progress_downloads: FuturesUnordered<tokio::time::Sleep>,
}

impl DownloadService {
    fn handle_message(&mut self, msg: Message) {
        match msg {
            Message::Start { kind, id } => todo!(),
            Message::Cancel { id } => todo!(),
        }
    }

    fn cancel_download(&mut self, id: Id) {
        // remove the intent first
        let Some(DownloadInfo { kind, ..  }) = self.registered_intents.remove(&id) else {
            // TODO(@divma): log that the requested intent to be canceled is not present
            return
        };

        // get the hash and ranges this intent maps to
        let download_key = (*kind.hash(), kind.ranges());
        let Entry::Occupied(mut occupied_entry) = self.current_requests.entry(download_key) else {
            unreachable!("registered intents have an associated request")
        };

        // remove the intent from the associated request
        let intents = &mut occupied_entry.get_mut().intents;
        let intent_position = intents
            .iter()
            .position(|&intent_id| intent_id == id)
            .expect("associated request contains intent id");
        intents.remove(intent_position);

        // if this was the last intent associated with the request, cancel it or remove it from the
        // schedule queue accordingly
        if intents.is_empty() {
            let state = occupied_entry.remove().state;
            match state {
                RequestState::Scheduled { delay_key } => {
                    self.scheduled_requests.remove(&delay_key);
                }
                RequestState::Active { cancellation } => {
                    cancellation.cancel();
                }
            }
        }
    }
}

impl Downloader {
    pub fn add_source(&self, id: u64, source: PublicKey) {
        // TODO(@divma): send the add source message
    }
}
