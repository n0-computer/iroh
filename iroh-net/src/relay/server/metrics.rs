use std::{collections::HashSet, sync::Arc, time::Duration};

use iroh_base::key::PublicKey;
use iroh_metrics::{
    core::{Counter, Metric},
    struct_iterable::Iterable,
};
use redis::AsyncCommands;
use tokio::sync::Mutex;

/// Metrics tracked for the relay server
#[allow(missing_docs)]
#[derive(Debug, Clone, Iterable)]
pub struct Metrics {
    /*
     * Metrics about packets
     */
    /// Bytes sent from a `FrameType::SendPacket`
    pub bytes_sent: Counter,
    /// Bytes received from a `FrameType::SendPacket`
    pub bytes_recv: Counter,

    /// `FrameType::SendPacket` sent, that are not disco messages
    pub send_packets_sent: Counter,
    /// `FrameType::SendPacket` received, that are not disco messages
    pub send_packets_recv: Counter,
    /// `FrameType::SendPacket` dropped, that are not disco messages
    pub send_packets_dropped: Counter,

    /// `FrameType::SendPacket` sent that are disco messages
    pub disco_packets_sent: Counter,
    /// `FrameType::SendPacket` received that are disco messages
    pub disco_packets_recv: Counter,
    /// `FrameType::SendPacket` dropped that are disco messages
    pub disco_packets_dropped: Counter,

    /// Packets of other `FrameType`s sent
    pub other_packets_sent: Counter,
    /// Packets of other `FrameType`s received
    pub other_packets_recv: Counter,
    /// Packets of other `FrameType`s dropped
    pub other_packets_dropped: Counter,

    /// Number of `FrameType::Ping`s received
    pub got_ping: Counter,
    /// Number of `FrameType::Pong`s sent
    pub sent_pong: Counter,
    /// Number of `FrameType::Unknown` received
    pub unknown_frames: Counter,

    /*
     * Metrics about peers
     */
    /// Number of connections we have accepted
    pub accepts: Counter,
    /// Number of connections we have removed because of an error
    pub disconnects: Counter,

    /// Number of unique client keys per day for just this relay
    pub unique_client_keys_local_1d: Counter,
    /// Number of unique client keys per day
    pub unique_client_keys_1d: Counter,
    /// Number of unique client keys per 7 days
    pub unique_client_keys_7d: Counter,
    /// Number of unique client keys per 30 days
    pub unique_client_keys_30d: Counter,

    /// Number of accepted websocket connections
    pub websocket_accepts: Counter,
    /// Number of accepted 'iroh derp http' connection upgrades
    pub derp_accepts: Counter,
    // TODO: enable when we can have multiple connections for one node id
    // pub duplicate_client_keys: Counter,
    // pub duplicate_client_conns: Counter,
    // TODO: only important stat that we cannot track right now
    // pub average_queue_duration:
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            /*
             * Metrics about packets
             */
            send_packets_sent: Counter::new("Number of 'send' packets relayed."),
            bytes_sent: Counter::new("Number of bytes sent."),
            send_packets_recv: Counter::new("Number of 'send' packets received."),
            bytes_recv: Counter::new("Number of bytes received."),
            send_packets_dropped: Counter::new("Number of 'send' packets dropped."),
            disco_packets_sent: Counter::new("Number of disco packets sent."),
            disco_packets_recv: Counter::new("Number of disco packets received."),
            disco_packets_dropped: Counter::new("Number of disco packets dropped."),

            other_packets_sent: Counter::new(
                "Number of packets sent that were not disco packets or 'send' packets",
            ),
            other_packets_recv: Counter::new(
                "Number of packets received that were not disco packets or 'send' packets",
            ),
            other_packets_dropped: Counter::new(
                "Number of times a non-disco, non-'send; packet was dropped.",
            ),
            got_ping: Counter::new("Number of times the server has received a Ping from a client."),
            sent_pong: Counter::new("Number of times the server has sent a Pong to a client."),
            unknown_frames: Counter::new("Number of unknown frames sent to this server."),

            /*
             * Metrics about peers
             */
            accepts: Counter::new("Number of times this server has accepted a connection."),
            disconnects: Counter::new("Number of clients that have then disconnected."),

            unique_client_keys_local_1d: Counter::new(
                "Number of unique client keys per day for just this relay.",
            ),
            unique_client_keys_1d: Counter::new("Number of unique client keys per day."),
            unique_client_keys_7d: Counter::new("Number of unique client keys per 7 days."),
            unique_client_keys_30d: Counter::new("Number of unique client keys per 30 days."),

            websocket_accepts: Counter::new("Number of accepted websocket connections"),
            derp_accepts: Counter::new("Number of accepted 'iroh derp http' connection upgrades"),
            // TODO: enable when we can have multiple connections for one node id
            // pub duplicate_client_keys: Counter::new("Number of duplicate client keys."),
            // pub duplicate_client_conns: Counter::new("Number of duplicate client connections."),
            // TODO: only important stat that we cannot track right now
            // pub average_queue_duration:
        }
    }
}

impl Metric for Metrics {
    fn name() -> &'static str {
        "relayserver"
    }
}

#[derive(Default)]
pub(crate) struct ClientCounter {
    client_tx: Option<tokio::sync::mpsc::Sender<PublicKey>>,
}

impl ClientCounter {
    /// Updates the client counter.
    pub async fn update(&mut self, client: PublicKey) {
        if let Some(tx) = &self.client_tx {
            if tx.send(client).await.is_err() {
                tracing::error!("client counter channel closed, not updating client count!");
            }
        }
    }

    /// Creates a new `ClientCounter` instance.
    pub fn new() -> Self {
        let redis_uri = std::env::var("IROH_RELAY_REDIS_URI").unwrap_or_else(|_| "".to_string());
        let redis_suffix =
            std::env::var("IROH_RELAY_REDIS_SUFFIX").unwrap_or_else(|_| "".to_string());
        if redis_uri.is_empty() || redis_suffix.is_empty() {
            tracing::info!(
                "Empty Redis configuration provided, client counter will not be persisted"
            );
            return Self { client_tx: None };
        }
        let rclient = redis::Client::open(redis_uri).unwrap_or_else(|e| {
            tracing::error!("Failed to create Redis client: {}", e);
            std::process::exit(1);
        });
        let clients = Arc::new(Mutex::new(HashSet::new()));

        // This might implicitly limit the number of clients we can accept to 65536 at the timeout interval of the
        // writer task
        let (tx, mut rx) = tokio::sync::mpsc::channel(65536);
        let writer_clients = Arc::clone(&clients);
        tokio::spawn(async move {
            loop {
                let r = rx.recv().await;
                if let Some(client) = r {
                    let mut clients = writer_clients.lock().await;
                    clients.insert(client);
                }
            }
        });

        let batch = Arc::clone(&clients);
        let rclient_clone = rclient.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            let relay_key = format!("unique_nodes_{}", redis_suffix.clone());
            let global_key = "unique_nodes".to_string();

            async fn batch_update_redis(
                client: &redis::Client,
                batch: &HashSet<PublicKey>,
                relay_key: &str,
                global_key: &str,
            ) -> redis::RedisResult<()> {
                let mut conn = client.get_multiplexed_async_connection().await?;
                let mut pipeline = redis::pipe();
                for node_id in batch.iter() {
                    let node_id_str = hex::encode(node_id.as_bytes());
                    pipeline
                        .sadd(format!("{}_1d", relay_key), node_id_str.clone())
                        .ignore();
                    pipeline
                        .sadd(format!("{}_1d", global_key), node_id_str.clone())
                        .ignore();
                    pipeline
                        .sadd(format!("{}_7d", global_key), node_id_str.clone())
                        .ignore();
                    pipeline
                        .sadd(format!("{}_30d", global_key), node_id_str.clone())
                        .ignore();
                }
                pipeline.expire(format!("{}_1d", relay_key), 86400).ignore(); // 1 day
                pipeline
                    .expire(format!("{}_1d", global_key), 86400)
                    .ignore(); // 1 day
                pipeline
                    .expire(format!("{}_7d", global_key), 604800)
                    .ignore(); // 7 days
                pipeline
                    .expire(format!("{}_30d", global_key), 2592000)
                    .ignore(); // 30 days
                pipeline.query_async(&mut conn).await
            }

            async fn get_unique_nodes(
                client: &redis::Client,
                key: &str,
            ) -> redis::RedisResult<u64> {
                let mut conn = client.get_multiplexed_async_connection().await?;
                let count = conn.scard(key).await?;
                Ok(count)
            }

            loop {
                interval.tick().await;
                let batch = Arc::clone(&batch);
                let rclient_clone = rclient_clone.clone();
                let relay_key = relay_key.clone();
                let global_key = global_key.clone();
                tokio::time::timeout(Duration::from_secs(60), async move {
                    {
                        let mut batch = batch.lock().await;
                        // Batch update Redis and clear the batch data
                        if let Err(err) =
                            batch_update_redis(&rclient_clone, &batch, &relay_key, &global_key)
                                .await
                        {
                            tracing::error!("Failed to update Redis: {}", err);
                        }
                        batch.clear();
                    }
                    tracing::debug!("Batch update Redis done");

                    let unique_nodes_local_1d =
                        get_unique_nodes(&rclient_clone, format!("{}_1d", relay_key).as_str())
                            .await
                            .unwrap_or(0);
                    let unique_nodes_1d =
                        get_unique_nodes(&rclient_clone, format!("{}_1d", global_key).as_str())
                            .await
                            .unwrap_or(0);
                    let unique_nodes_7d =
                        get_unique_nodes(&rclient_clone, format!("{}_7d", global_key).as_str())
                            .await
                            .unwrap_or(0);
                    let unique_nodes_30d =
                        get_unique_nodes(&rclient_clone, format!("{}_30d", global_key).as_str())
                            .await
                            .unwrap_or(0);
                    tracing::debug!(
                        "Unique nodes local_1d 1d 7d 30d days: {} {} {} {}",
                        unique_nodes_local_1d,
                        unique_nodes_1d,
                        unique_nodes_7d,
                        unique_nodes_30d
                    );
                    iroh_metrics::set!(Metrics, unique_client_keys_local_1d, unique_nodes_local_1d);
                    iroh_metrics::set!(Metrics, unique_client_keys_1d, unique_nodes_1d);
                    iroh_metrics::set!(Metrics, unique_client_keys_7d, unique_nodes_7d);
                    iroh_metrics::set!(Metrics, unique_client_keys_30d, unique_nodes_30d);
                })
                .await
                .unwrap_or_else(|e| {
                    tracing::error!("Failed to update Redis: {}", e);
                });
            }
        });
        Self {
            client_tx: Some(tx),
        }
    }
}
