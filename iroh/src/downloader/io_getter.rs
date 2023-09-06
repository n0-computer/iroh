//! [`Getter`] implementation that performs requests over [`quinn::Connection`]s.

use futures::FutureExt;
use iroh_bytes::{baomap::Store, collection::CollectionParser};
use tokio_util::sync::CancellationToken;

use super::{get, DownloadFut, DownloadKind, Getter};

/// [`Getter`] implementation that performs requests over [`quinn::Connection`]s.
pub(crate) struct IoGetter<S: Store, C: CollectionParser> {
    pub store: S,
    pub collection_parser: C,
}

impl<S: Store, C: CollectionParser> Getter for IoGetter<S, C> {
    type Connection = quinn::Connection;

    fn get(
        &self,
        kind: DownloadKind,
        conn: Self::Connection,
        cancellation: CancellationToken,
    ) -> DownloadFut {
        let store = self.store.clone();
        let collection_parser = self.collection_parser.clone();
        let fut = async move {
            let get = match kind {
                DownloadKind::Blob { hash } => {
                    get::get(&store, &collection_parser, conn, hash, false)
                }
                DownloadKind::Collection { hash } => {
                    get::get(&store, &collection_parser, conn, hash, true)
                }
            };

            // TODO(@divma): timeout?
            let res = tokio::select! {
                _ = cancellation.cancelled() => Err(get::FailureAction::AbortRequest(anyhow::anyhow!("cancelled"))),
                res = get => res
            };

            // TODO: use stats for metrics
            (kind, res.map(|_stats| ()))
        };
        fut.boxed_local()
    }
}
