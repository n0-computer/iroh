//! Reexport of iroh-blobs rpc client

use quic_rpc::client::BoxedServiceConnection;

use super::RpcService;
/// Reexport of iroh-blobs rpc client
pub type Client =
    iroh_blobs::rpc::client::blobs::Client<BoxedServiceConnection<RpcService>, RpcService>;

pub use iroh_blobs::rpc::client::blobs::{
    AddDirOpts, AddFileOpts, AddOutcome, AddProgress, AddReaderOpts, BlobInfo, BlobStatus,
    CollectionInfo, DownloadMode, DownloadOptions, DownloadOutcome, DownloadProgress,
    IncompleteBlobInfo, Reader, WrapOption,
};
