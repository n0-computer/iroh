use std::{
    future::Future,
    path::Path,
    result,
    sync::Arc,
    time::{Duration, SystemTime},
};

use iroh_dns::pkarr::{SignedPacket, Timestamp};
use n0_error::{Result, StackResultExt, StdResultExt, anyerr};
use redb::{Database, MultimapTableDefinition, ReadableDatabase, ReadableTable, TableDefinition};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::{metrics::Metrics, util::PublicKeyBytes};

type SignedPacketsKey = [u8; 32];

const SIGNED_PACKETS_TABLE: TableDefinition<&SignedPacketsKey, &[u8]> =
    TableDefinition::new("signed-packets-1");
const UPDATE_TIME_TABLE: MultimapTableDefinition<[u8; 8], SignedPacketsKey> =
    MultimapTableDefinition::new("update-time-1");

#[derive(Debug)]
pub(super) struct SignedPacketStore {
    send: mpsc::Sender<Message>,
    cancel: CancellationToken,
    _write_thread: IoThread,
    _evict_thread: IoThread,
}

impl Drop for SignedPacketStore {
    fn drop(&mut self) {
        // cancel the actor
        self.cancel.cancel();
        // after cancellation, the two threads will be joined
    }
}

#[derive(derive_more::Debug)]
enum Message {
    Upsert {
        packet: SignedPacket,
        res: oneshot::Sender<bool>,
    },
    Get {
        key: PublicKeyBytes,
        res: oneshot::Sender<Option<SignedPacket>>,
    },
    #[cfg(test)]
    Remove {
        key: PublicKeyBytes,
        res: oneshot::Sender<bool>,
    },
    Snapshot {
        #[debug(skip)]
        res: oneshot::Sender<Snapshot>,
    },
    CheckExpired {
        time: Timestamp,
        key: PublicKeyBytes,
    },
}

struct Actor {
    db: Database,
    recv: PeekableReceiver<Message>,
    cancel: CancellationToken,
    options: Options,
    metrics: Arc<Metrics>,
}

/// Configuration for the signed-packet store.
///
/// Controls how incoming packets are batched into write transactions and how
/// long packets are retained before the eviction task removes them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Options {
    /// Maximum number of packets to process in a single write transaction.
    pub(crate) max_batch_size: usize,
    /// Maximum time to keep a write transaction open.
    pub(crate) max_batch_time: Duration,
    /// Time to keep packets in the store before eviction.
    pub(crate) eviction: Duration,
    /// Pause between eviction checks.
    pub(crate) eviction_interval: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            // 64k packets
            max_batch_size: 1024 * 64,
            // this means we lose at most 1 second of data in case of a crash
            max_batch_time: Duration::from_secs(1),
            // 7 days
            eviction: Duration::from_secs(3600 * 24 * 7),
            // eviction can run frequently since it does not do a full scan
            eviction_interval: Duration::from_secs(10),
        }
    }
}

impl Actor {
    async fn run(mut self) {
        match self.run0().await {
            Ok(()) => {}
            Err(e) => {
                tracing::error!("packet store actor failed: {:?}", e);
                self.cancel.cancel();
            }
        }
    }

    async fn run0(&mut self) -> Result<()> {
        while let Some(msg) = self.recv.recv().await {
            // if we get a snapshot message here we don't need to do a write transaction
            let msg = if let Message::Snapshot { res } = msg {
                let snapshot = Snapshot::new(&self.db)?;
                res.send(snapshot).ok();
                continue;
            } else {
                msg
            };
            trace!("batch");
            self.recv.push_back(msg).unwrap();
            let transaction = self.db.begin_write().anyerr()?;
            let mut tables = Tables::new(&transaction).anyerr()?;
            let timeout = tokio::time::sleep(self.options.max_batch_time);
            tokio::pin!(timeout);
            for _ in 0..self.options.max_batch_size {
                tokio::select! {
                    _ = self.cancel.cancelled() => {
                        drop(tables);
                        transaction.commit().anyerr()?;
                        return Ok(());
                    }
                    _ = &mut timeout => break,
                    Some(msg) = self.recv.recv() => self.handle_message(msg, &mut tables)?,
                }
            }
            drop(tables);
            transaction.commit().anyerr()?;
        }
        Ok(())
    }

    fn handle_message(&self, msg: Message, tables: &mut Tables) -> Result<()> {
        match msg {
            Message::Get { key, res } => match get_packet(&tables.signed_packets, &key) {
                Ok(packet) => {
                    trace!("get {key}: {}", packet.is_some());
                    res.send(packet).ok();
                }
                Err(err) => {
                    warn!("get {key} failed: {err:#}");
                    return Err(err).context(format!("get packet for {key} failed"));
                }
            },
            Message::Upsert { packet, res } => {
                let key = PublicKeyBytes::from_signed_packet(&packet);
                trace!("upsert {}", key);
                let replaced = match get_packet(&tables.signed_packets, &key)? {
                    Some(existing) => {
                        if existing.more_recent_than(&packet) {
                            res.send(false).ok();
                            return Ok(());
                        } else {
                            // remove the old packet from the update time index
                            tables
                                .update_time
                                .remove(&existing.timestamp().to_be_bytes(), key.as_bytes())
                                .anyerr()?;
                            true
                        }
                    }
                    _ => false,
                };
                let value = serialize(&packet);
                tables
                    .signed_packets
                    .insert(key.as_bytes(), &value[..])
                    .anyerr()?;
                tables
                    .update_time
                    .insert(&packet.timestamp().to_be_bytes(), key.as_bytes())
                    .anyerr()?;
                if replaced {
                    self.metrics.store_packets_updated.inc();
                } else {
                    self.metrics.store_packets_inserted.inc();
                }
                res.send(true).ok();
            }
            #[cfg(test)]
            Message::Remove { key, res } => {
                trace!("remove {}", key);
                let updated = match tables.signed_packets.remove(key.as_bytes()).anyerr()? {
                    Some(row) => {
                        let packet = deserialize(row.value())?;
                        tables
                            .update_time
                            .remove(&packet.timestamp().to_be_bytes(), key.as_bytes())
                            .anyerr()?;
                        self.metrics.store_packets_removed.inc();
                        true
                    }
                    _ => false,
                };
                res.send(updated).ok();
            }
            Message::Snapshot { res } => {
                trace!("snapshot");
                res.send(Snapshot::new(&self.db)?).ok();
            }
            Message::CheckExpired { key, time } => {
                trace!("check expired {} at {}", key, fmt_time(time));
                match get_packet(&tables.signed_packets, &key)? {
                    Some(packet) => {
                        let expiry_us = self.options.eviction.as_micros() as u64;
                        let expired = Timestamp::from_micros(
                            Timestamp::now().as_micros().saturating_sub(expiry_us),
                        );
                        if packet.timestamp() < expired {
                            tables
                                .update_time
                                .remove(&time.to_be_bytes(), key.as_bytes())
                                .anyerr()?;
                            let _ = tables.signed_packets.remove(key.as_bytes()).anyerr()?;
                            self.metrics.store_packets_expired.inc();
                            debug!("removed expired packet {key}");
                        } else {
                            debug!(
                                "packet {key} is no longer expired, removing obsolete expiry entry"
                            );
                            tables
                                .update_time
                                .remove(&time.to_be_bytes(), key.as_bytes())
                                .anyerr()?;
                        }
                    }
                    None => {
                        debug!("expired packet {key} not found, remove from expiry table");
                        tables
                            .update_time
                            .remove(&time.to_be_bytes(), key.as_bytes())
                            .anyerr()?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn fmt_time(t: Timestamp) -> String {
    let duration = std::time::Duration::from_micros(t.as_micros());
    humantime::format_rfc3339_micros(SystemTime::UNIX_EPOCH + duration).to_string()
}

/// A struct similar to [`redb::Table`] but for all tables that make up the
/// signed packet store.
struct Tables<'a> {
    pub signed_packets: redb::Table<'a, &'static SignedPacketsKey, &'static [u8]>,
    pub update_time: redb::MultimapTable<'a, [u8; 8], SignedPacketsKey>,
}

impl<'txn> Tables<'txn> {
    fn new(tx: &'txn redb::WriteTransaction) -> result::Result<Self, redb::TableError> {
        Ok(Self {
            signed_packets: tx.open_table(SIGNED_PACKETS_TABLE)?,
            update_time: tx.open_multimap_table(UPDATE_TIME_TABLE)?,
        })
    }
}

struct Snapshot {
    #[allow(dead_code)]
    pub signed_packets: redb::ReadOnlyTable<&'static SignedPacketsKey, &'static [u8]>,
    pub update_time: redb::ReadOnlyMultimapTable<[u8; 8], SignedPacketsKey>,
}

impl Snapshot {
    fn new(db: &Database) -> Result<Self> {
        let tx = db.begin_read().anyerr()?;
        Ok(Self {
            signed_packets: tx.open_table(SIGNED_PACKETS_TABLE).anyerr()?,
            update_time: tx.open_multimap_table(UPDATE_TIME_TABLE).anyerr()?,
        })
    }
}

impl SignedPacketStore {
    pub(crate) fn persistent(
        path: impl AsRef<Path>,
        options: Options,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        let path = path.as_ref();
        info!("loading packet database from {}", path.to_string_lossy());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_std_context(|_| {
                format!(
                    "failed to create database directory at {}",
                    path.to_string_lossy()
                )
            })?;
        }
        let db = Database::builder()
            .create(path)
            .std_context("failed to open packet database")?;
        Self::open(db, options, metrics)
    }

    #[cfg(test)]
    pub(crate) fn in_memory(options: Options, metrics: Arc<Metrics>) -> Result<Self> {
        info!("using in-memory packet database");
        let db = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .anyerr()?;
        Self::open(db, options, metrics)
    }

    pub(crate) fn open(db: Database, options: Options, metrics: Arc<Metrics>) -> Result<Self> {
        // create tables
        let write_tx = db.begin_write().anyerr()?;
        let _ = Tables::new(&write_tx).anyerr()?;
        write_tx.commit().anyerr()?;
        let (send, recv) = mpsc::channel(1024);
        let send2 = send.clone();
        let cancel = CancellationToken::new();
        let cancel2 = cancel.clone();
        let cancel3 = cancel.clone();
        let actor = Actor {
            db,
            recv: PeekableReceiver::new(recv),
            cancel: cancel2,
            options,
            metrics,
        };
        // start an io thread and donate it to the tokio runtime so we can do blocking IO
        // inside the thread despite being in a tokio runtime
        let _write_thread = IoThread::new("packet-store-actor", move || actor.run())?;
        let _evict_thread = IoThread::new("packet-store-evict", move || {
            evict_task(send2, options, cancel3)
        })?;
        Ok(Self {
            send,
            cancel,
            _write_thread,
            _evict_thread,
        })
    }

    pub(crate) async fn upsert(&self, packet: SignedPacket) -> Result<bool> {
        let (tx, rx) = oneshot::channel();
        self.send
            .send(Message::Upsert { packet, res: tx })
            .await
            .anyerr()?;
        rx.await.anyerr()
    }

    pub(crate) async fn get(&self, key: &PublicKeyBytes) -> Result<Option<SignedPacket>> {
        let (tx, rx) = oneshot::channel();
        self.send
            .send(Message::Get { key: *key, res: tx })
            .await
            .anyerr()?;
        rx.await.anyerr()
    }

    #[cfg(test)]
    pub(crate) async fn remove(&self, key: &PublicKeyBytes) -> Result<bool> {
        let (tx, rx) = oneshot::channel();
        self.send
            .send(Message::Remove { key: *key, res: tx })
            .await
            .anyerr()?;
        rx.await.anyerr()
    }
}

/// Serialize a signed packet for storage: `<8 bytes last_seen><packet bytes>`.
fn serialize(packet: &SignedPacket) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + packet.as_bytes().len());
    out.extend_from_slice(&Timestamp::now().to_be_bytes());
    out.extend_from_slice(packet.as_bytes());
    out
}

/// Deserialize a signed packet from storage format.
///
/// Handles backwards compatibility with older storage formats that didn't include
/// the `last_seen` prefix.
fn deserialize(data: &[u8]) -> Result<SignedPacket> {
    // Try parsing as <8 bytes last_seen><packet> (pkarr v3 format)
    if data.len() >= 8
        && let Ok(packet) = SignedPacket::from_bytes_unchecked(&data[8..])
    {
        return Ok(packet);
    }
    // Fall back to raw packet bytes (pre-v0.35 format without last_seen prefix)
    SignedPacket::from_bytes_unchecked(data)
        .map_err(|err| anyerr!("Failed to decode stored packet: {err:#}"))
}

fn get_packet(
    table: &impl ReadableTable<&'static SignedPacketsKey, &'static [u8]>,
    key: &PublicKeyBytes,
) -> Result<Option<SignedPacket>> {
    let Some(row) = table
        .get(key.as_ref())
        .std_context("database fetch failed")?
    else {
        return Ok(None);
    };
    Ok(Some(deserialize(row.value())?))
}

async fn evict_task(send: mpsc::Sender<Message>, options: Options, cancel: CancellationToken) {
    let cancel2 = cancel.clone();
    let _ = cancel2
        .run_until_cancelled(async move {
            info!("starting evict task");
            if let Err(cause) = evict_task_inner(send, options).await {
                error!("evict task failed: {:?}", cause);
            }
            // when we are done for whatever reason we want to shut down the actor
            cancel.cancel();
        })
        .await;
}

/// Periodically check for expired packets and remove them.
async fn evict_task_inner(send: mpsc::Sender<Message>, options: Options) -> Result<()> {
    let expiry_us = options.eviction.as_micros() as u64;
    loop {
        let (tx, rx) = oneshot::channel();
        let _ = send.send(Message::Snapshot { res: tx }).await.ok();
        // if we can't get the snapshot we exit the loop, main actor dead
        let snapshot = rx.await.std_context("failed to get snapshot")?;

        let expired =
            Timestamp::from_micros(Timestamp::now().as_micros().saturating_sub(expiry_us));
        trace!("evicting packets older than {}", fmt_time(expired));
        // if getting the range fails we exit the loop and shut down
        // if individual reads fail we log the error and limp on
        for item in snapshot
            .update_time
            .range(..expired.to_be_bytes())
            .anyerr()?
        {
            let (time, keys) = match item {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to read update_time row {:?}", e);
                    continue;
                }
            };
            let time = Timestamp::from_be_bytes(time.value());
            trace!("evicting expired packets at {}", fmt_time(time));
            for item in keys {
                let key = match item {
                    Ok(v) => v,
                    Err(e) => {
                        error!(
                            "failed to read update_time item at {}: {:?}",
                            fmt_time(time),
                            e
                        );
                        continue;
                    }
                };
                // Safety: bytes were originally written from a validated PublicKey.
                // If the database is corrupt, to_z32() may panic downstream.
                let key = PublicKeyBytes::new_unchecked(key.value());

                debug!("evicting expired packet {} {}", fmt_time(time), key);
                send.send(Message::CheckExpired { time, key })
                    .await
                    .anyerr()?;
            }
        }
        // sleep for the eviction interval so we don't constantly check
        tokio::time::sleep(options.eviction_interval).await;
    }
}

/// An io thread that drives a future to completion on the current tokio runtime
///
/// Inside the future, blocking IO can be done without blocking one of the tokio
/// pool threads.
#[derive(Debug)]
struct IoThread {
    handle: Option<std::thread::JoinHandle<()>>,
}

impl IoThread {
    /// Spawn a new io thread.
    ///
    /// Calling this function requires that the current thread is running in a
    /// tokio runtime. It is up to the caller to make sure the future exits,
    /// e.g. by using a cancellation token. Otherwise, drop will block.
    fn new<F, Fut>(name: &str, f: F) -> Result<Self>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = ()>,
    {
        let rt = tokio::runtime::Handle::try_current().std_context("get tokio handle")?;
        let handle = std::thread::Builder::new()
            .name(name.into())
            .spawn(move || rt.block_on(f()))
            .std_context("failed to spawn thread")?;
        Ok(Self {
            handle: Some(handle),
        })
    }
}

impl Drop for IoThread {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A wrapper for a tokio mpsc receiver that allows peeking at the next message.
#[derive(Debug)]
struct PeekableReceiver<T> {
    msg: Option<T>,
    recv: tokio::sync::mpsc::Receiver<T>,
}

#[allow(dead_code)]
impl<T> PeekableReceiver<T> {
    fn new(recv: tokio::sync::mpsc::Receiver<T>) -> Self {
        Self { msg: None, recv }
    }

    /// Receive the next message.
    ///
    /// Will block if there are no messages.
    /// Returns None only if there are no more messages (sender is dropped).
    async fn recv(&mut self) -> Option<T> {
        if let Some(msg) = self.msg.take() {
            return Some(msg);
        }
        self.recv.recv().await
    }

    /// Push back a message. This will only work if there is room for it.
    /// Otherwise, it will fail and return the message.
    fn push_back(&mut self, msg: T) -> std::result::Result<(), T> {
        if self.msg.is_none() {
            self.msg = Some(msg);
            Ok(())
        } else {
            Err(msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;

    use super::*;

    fn test_signed_packet() -> SignedPacket {
        let secret_key = SecretKey::generate();
        SignedPacket::from_txt_strings(&secret_key, "_iroh", ["relay=https://example.com"], 30)
            .expect("valid packet")
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let packet = test_signed_packet();
        let serialized = serialize(&packet);
        let deserialized = deserialize(&serialized).expect("roundtrip should succeed");
        assert_eq!(packet.as_bytes(), deserialized.as_bytes());
    }

    #[test]
    fn deserialize_old_format_without_last_seen_prefix() {
        // Pre-v0.35 format: raw SignedPacket bytes without the 8-byte last_seen prefix
        let packet = test_signed_packet();
        let old_format = packet.as_bytes().to_vec();
        let deserialized = deserialize(&old_format).expect("old format should be readable");
        assert_eq!(packet.as_bytes(), deserialized.as_bytes());
    }

    #[tokio::test]
    async fn remove_in_memory() {
        let store = SignedPacketStore::in_memory(Options::default(), Arc::new(Metrics::default()))
            .expect("in-memory store");
        let packet = test_signed_packet();
        let key = PublicKeyBytes::from_signed_packet(&packet);

        assert!(store.upsert(packet.clone()).await.expect("upsert"));
        assert!(store.get(&key).await.expect("get").is_some());

        assert!(store.remove(&key).await.expect("remove existing"));
        assert!(store.get(&key).await.expect("get after remove").is_none());

        assert!(!store.remove(&key).await.expect("remove missing"));
    }
}
