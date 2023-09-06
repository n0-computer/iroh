//! [`Getter`] implementation that performs requests over [`quinn::Connection`]s.

use futures::FutureExt;
use iroh_bytes::{baomap::Store, collection::CollectionParser};

use super::{get, DownloadKind, GetFut, Getter};

/// [`Getter`] implementation that performs requests over [`quinn::Connection`]s.
pub(crate) struct IoGetter<S: Store, C: CollectionParser> {
    pub store: S,
    pub collection_parser: C,
}

impl<S: Store, C: CollectionParser> Getter for IoGetter<S, C> {
    type Connection = quinn::Connection;

    fn get(&mut self, kind: DownloadKind, conn: Self::Connection) -> GetFut {
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

            // TODO: use stats for metrics
            get.await.map(|_stats| ())
        };
        fut.boxed_local()
    }
}
