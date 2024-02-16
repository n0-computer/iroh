//! [`Getter`] implementation that performs requests over [`quinn::Connection`]s.

use crate::{
    get::{db::get_to_db, error::GetError},
    store::Store,
};
use futures::FutureExt;
use iroh_base::hash::HashAndFormat;
#[cfg(feature = "metrics")]
use iroh_metrics::{inc, inc_by};

#[cfg(feature = "metrics")]
use crate::metrics::Metrics;

use super::{progress::BroadcastProgressSender, FailureAction, GetFut, Getter};

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

/// [`Getter`] implementation that performs requests over [`quinn::Connection`]s.
pub(crate) struct IoGetter<S: Store> {
    pub store: S,
}

impl<S: Store> Getter for IoGetter<S> {
    type Connection = quinn::Connection;

    fn get(
        &mut self,
        resource: HashAndFormat,
        conn: Self::Connection,
        progress_sender: BroadcastProgressSender,
    ) -> GetFut {
        let store = self.store.clone();
        let fut = async move {
            let get_conn = || async move { Ok(conn) };
            let res = get_to_db(&store, get_conn, &resource, progress_sender).await;
            match res {
                Ok(stats) => {
                    #[cfg(feature = "metrics")]
                    {
                        let crate::get::Stats {
                            bytes_written,
                            bytes_read: _,
                            elapsed,
                        } = stats;

                        inc!(Metrics, downloads_success);
                        inc_by!(Metrics, download_bytes_total, bytes_written);
                        inc_by!(Metrics, download_time_total, elapsed.as_millis() as u64);
                    }
                    Ok(stats)
                }
                Err(e) => {
                    // record metrics according to the error
                    #[cfg(feature = "metrics")]
                    {
                        match &e {
                            GetError::NotFound(_) => inc!(Metrics, downloads_notfound),
                            _ => inc!(Metrics, downloads_error),
                        }
                    }
                    Err(e.into())
                }
            }
        };
        fut.boxed_local()
    }
}
