//! Get requests in the context of the [`super::Downloader`].

use super::Download;

/// Result of performing a request.
enum DownloadResult {
    /// An error ocurred that prevents the request from being retried at all.
    AbortRequest(anyhow::Error),
    /// An error occurred that suggests the peer should not be used in general.
    DropPeer(anyhow::Error),
    /// An error occurred in which neither the peer nor the request are at fault.
    RetryLater(anyhow::Error),
    /// Download succeeded.
    Success,
}

impl From<quinn::ConnectionError> for DownloadResult {
    fn from(value: quinn::ConnectionError) -> Self {
        // explicit match just to be sure we ar taking everything into account
        match value {
            e @ quinn::ConnectionError::VersionMismatch => {
                // > The peer doesn't implement any supported version
                // unsupported version is likely a long time error, so this peer is not usable
                DownloadResult::DropPeer(e.into())
            }
            e @ quinn::ConnectionError::TransportError(_) => {
                // > The peer violated the QUIC specification as understood by this implementation
                // bad peer we don't want to keep around
                DownloadResult::DropPeer(e.into())
            }
            e @ quinn::ConnectionError::ConnectionClosed(_) => {
                // > The peer's QUIC stack aborted the connection automatically
                // peer might be disconnecting or otherwise unavailable, drop it
                DownloadResult::DropPeer(e.into())
            }
            e @ quinn::ConnectionError::ApplicationClosed(_) => {
                // > The peer closed the connection
                // peer might be disconnecting or otherwise unavailable, drop it
                DownloadResult::DropPeer(e.into())
            }
            e @ quinn::ConnectionError::Reset => {
                // > The peer is unable to continue processing this connection, usually due to having restarted
                // TODO(@divma): peer is unavailable but might be available later, maybe retry?
                DownloadResult::DropPeer(e.into())
            }
            e @ quinn::ConnectionError::TimedOut => {
                // > Communication with the peer has lapsed for longer than the negotiated idle timeout
                // TODO(@divma): my understanding is that quinn should be configured to ping often
                // enough to prevent this. If the peer's connfiguration and our configuration allow
                // this to happen maybe the peer is not really usable
                DownloadResult::DropPeer(e.into())
            }
            e @ quinn::ConnectionError::LocallyClosed => {
                // > The local application closed the connection
                // TODO(@divma): don't see how this is reachable but let's just not use the peer
                DownloadResult::DropPeer(e.into())
            }
        }
    }
}

impl From<quinn::ReadError> for DownloadResult {
    fn from(value: quinn::ReadError) -> Self {
        match value {
            quinn::ReadError::Reset(_)
            | quinn::ReadError::ConnectionLost(_)
            | quinn::ReadError::UnknownStream
            | quinn::ReadError::IllegalOrderedRead
            | quinn::ReadError::ZeroRttRejected => {
                // all these errors indicate the peer is not usable at this moment
                DownloadResult::DropPeer(value.into())
            }
        }
    }
}

impl From<quinn::WriteError> for DownloadResult {
    fn from(value: quinn::WriteError) -> Self {
        match value {
            quinn::WriteError::Stopped(_)
            | quinn::WriteError::ConnectionLost(_)
            | quinn::WriteError::UnknownStream
            | quinn::WriteError::ZeroRttRejected => {
                // all these errors indicate the peer is not usable at this moment
                DownloadResult::DropPeer(value.into())
            }
        }
    }
}

impl From<iroh_bytes::get::fsm::ConnectedNextError> for DownloadResult {
    fn from(value: iroh_bytes::get::fsm::ConnectedNextError) -> Self {
        use iroh_bytes::get::fsm::ConnectedNextError::*;
        match value {
            e @ PostcardSer(_) => {
                // serialization errors indicate something wrong with the request itself
                DownloadResult::AbortRequest(e.into())
            }
            e @ RequestTooBig => {
                // request will never be sent, drop it
                DownloadResult::AbortRequest(e.into())
            }
            Write(e) => e.into(),
            Read(e) => e.into(),
            e @ CustomRequestTooBig => {
                // something wrong with the request itself
                DownloadResult::AbortRequest(e.into())
            }
            e @ Eof => {
                // TODO(@divma): unsure about this based on docs
                DownloadResult::RetryLater(e.into())
            }
            e @ PostcardDe(_) => {
                // serialization errors can't be recovered
                DownloadResult::AbortRequest(e.into())
            }
            e @ Io(_) => {
                // io errors are likely recoverable
                DownloadResult::RetryLater(e.into())
            }
        }
    }
}

impl From<iroh_bytes::get::fsm::AtBlobHeaderNextError> for DownloadResult {
    fn from(value: iroh_bytes::get::fsm::AtBlobHeaderNextError) -> Self {
        use iroh_bytes::get::fsm::AtBlobHeaderNextError::*;
        match value {
            e @ NotFound => {
                // > This indicates that the provider does not have the requested data.
                // peer might have the data later, simply retry it
                DownloadResult::RetryLater(e.into())
            }
            e @ InvalidQueryRange => {
                // we are doing something wrong with this request, drop it
                DownloadResult::AbortRequest(e.into())
            }
            Read(e) => e.into(),
            e @ Io(_) => {
                // io errors are likely recoverable
                DownloadResult::RetryLater(e.into())
            }
        }
    }
}

pub(crate) async fn get(kind: Download, conn: quinn::Connection) -> DownloadResult {}
