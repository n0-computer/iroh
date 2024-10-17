//! [`Getter`] implementation that performs requests over [`Connection`]s.
//!
//! [`Connection`]: iroh_net::endpoint::Connection

use futures_lite::FutureExt;
use iroh_net::endpoint;

use super::{progress::BroadcastProgressSender, DownloadKind, FailureAction, GetStartFut, Getter};
use crate::{
    get::{db::get_to_db_in_steps, error::GetError},
    store::Store,
};

impl From<GetError> for FailureAction {
    fn from(e: GetError) -> Self {
        match e {
            e @ GetError::NotFound(_) => FailureAction::AbortRequest(e.into()),
            e @ GetError::RemoteReset(_) => FailureAction::RetryLater(e.into()),
            e @ GetError::NoncompliantNode(_) => FailureAction::DropPeer(e.into()),
            e @ GetError::Io(_) => FailureAction::RetryLater(e.into()),
            e @ GetError::BadRequest(_) => FailureAction::AbortRequest(e.into()),
            // TODO: what do we want to do on local failures?
            e @ GetError::LocalFailure(_) => FailureAction::AbortRequest(e.into()),
        }
    }
}

/// [`Getter`] implementation that performs requests over [`Connection`]s.
///
/// [`Connection`]: iroh_net::endpoint::Connection
pub(crate) struct IoGetter<S: Store> {
    pub store: S,
}

impl<S: Store> Getter for IoGetter<S> {
    type Connection = endpoint::Connection;
    type NeedsConn = crate::get::db::GetStateNeedsConn;

    fn get(
        &mut self,
        kind: DownloadKind,
        progress_sender: BroadcastProgressSender,
    ) -> GetStartFut<Self::NeedsConn> {
        let store = self.store.clone();
        async move {
            match get_to_db_in_steps(store, kind.hash_and_format(), progress_sender).await {
                Err(err) => Err(err.into()),
                Ok(crate::get::db::GetState::Complete(stats)) => {
                    Ok(super::GetOutput::Complete(stats))
                }
                Ok(crate::get::db::GetState::NeedsConn(needs_conn)) => {
                    Ok(super::GetOutput::NeedsConn(needs_conn))
                }
            }
        }
        .boxed_local()
    }
}

impl super::NeedsConn<endpoint::Connection> for crate::get::db::GetStateNeedsConn {
    fn proceed(self, conn: endpoint::Connection) -> super::GetProceedFut {
        async move {
            let res = self.proceed(conn).await;
            #[cfg(feature = "metrics")]
            track_metrics(&res);
            match res {
                Ok(stats) => Ok(stats),
                Err(err) => Err(err.into()),
            }
        }
        .boxed_local()
    }
}

#[cfg(feature = "metrics")]
fn track_metrics(res: &Result<crate::get::Stats, GetError>) {
    use iroh_metrics::{inc, inc_by};

    use crate::metrics::Metrics;
    match res {
        Ok(stats) => {
            let crate::get::Stats {
                bytes_written,
                bytes_read: _,
                elapsed,
            } = stats;

            inc!(Metrics, downloads_success);
            inc_by!(Metrics, download_bytes_total, *bytes_written);
            inc_by!(Metrics, download_time_total, elapsed.as_millis() as u64);
        }
        Err(e) => match &e {
            GetError::NotFound(_) => inc!(Metrics, downloads_notfound),
            _ => inc!(Metrics, downloads_error),
        },
    }
}
