use ahash::AHashMap;
use libp2p::kad::{GetRecordOk, GetRecordResult, PeerRecord, QueryId};
use tokio::sync::mpsc::Sender;

pub struct DhtGetQuery {
    response_channel: Sender<anyhow::Result<PeerRecord>>,
}

impl DhtGetQuery {
    pub fn new(response_channel: Sender<anyhow::Result<PeerRecord>>) -> DhtGetQuery {
        DhtGetQuery { response_channel }
    }
}

#[derive(Default)]
pub struct DhtRecords {
    current_queries: AHashMap<QueryId, DhtGetQuery>,
}

impl DhtRecords {
    pub fn insert(&mut self, query_id: QueryId, query: DhtGetQuery) {
        self.current_queries.insert(query_id, query);
    }

    pub fn handle_get_record_result(&mut self, id: QueryId, get_record_result: GetRecordResult) {
        if let Some(query) = self.current_queries.remove(&id) {
            match get_record_result {
                Ok(GetRecordOk::FoundRecord(record)) => {
                    tokio::spawn(async move { query.response_channel.send(Ok(record)).await.ok() });
                }
                Ok(GetRecordOk::FinishedWithNoAdditionalRecord { cache_candidates }) => {}
                Err(_) => todo!(),
            }
        };
    }
}
