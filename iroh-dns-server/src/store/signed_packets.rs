use std::{future::Future, path::Path, result, time::Duration};

use anyhow::{Context, Result};
use iroh_metrics::inc;
use pkarr::{SignedPacket, Timestamp};
use redb::{
    backends::InMemoryBackend, Database, MultimapTableDefinition, ReadableTable, TableDefinition,
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace};

use crate::{metrics::Metrics, util::PublicKeyBytes};

pub type SignedPacketsKey = [u8; 32];
const SIGNED_PACKETS_TABLE: TableDefinition<&SignedPacketsKey, &[u8]> =
    TableDefinition::new("signed-packets-1");
const UPDATE_TIME_TABLE: MultimapTableDefinition<[u8; 8], SignedPacketsKey> =
    MultimapTableDefinition::new("update-time-1");

#[derive(Debug)]
pub struct SignedPacketStore {
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
    Remove {
        key: PublicKeyBytes,
        res: oneshot::Sender<bool>,
    },
    Snapshot {
        #[debug(skip)]
        res: oneshot::Sender<Snapshot>,
    },
    CheckExpired {
        time: [u8; 8],
        key: PublicKeyBytes,
    },
}

struct Actor {
    db: Database,
    recv: PeekableReceiver<Message>,
    cancel: CancellationToken,
    options: Options,
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Maximum number of packets to process in a single write transaction.
    pub max_batch_size: usize,
    /// Maximum time to keep a write transaction open.
    pub max_batch_time: Duration,
    /// Time to keep packets in the store before eviction.
    pub eviction: Duration,
    /// Pause between eviction checks.
    pub eviction_interval: Duration,
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

    async fn run0(&mut self) -> anyhow::Result<()> {
        let expiry_us = self.options.eviction.as_micros() as u64;
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
            let transaction = self.db.begin_write()?;
            let mut tables = Tables::new(&transaction)?;
            let timeout = tokio::time::sleep(self.options.max_batch_time);
            let expired = Timestamp::now() - expiry_us;
            tokio::pin!(timeout);
            for _ in 0..self.options.max_batch_size {
                tokio::select! {
                    _ = self.cancel.cancelled() => {
                        drop(tables);
                        transaction.commit()?;
                        return Ok(());
                    }
                    _ = &mut timeout => break,
                    Some(msg) = self.recv.recv() => {
                        match msg {
                            Message::Get { key, res } => {
                                trace!("get {}", key);
                                let packet = get_packet(&tables.signed_packets, &key).context("get packet failed")?;
                                res.send(packet).ok();
                            }
                            Message::Upsert { packet, res } => {
                                let key = PublicKeyBytes::from_signed_packet(&packet);
                                trace!("upsert {}", key);
                                let replaced = if let Some(existing) = get_packet(&tables.signed_packets, &key)? {
                                    if existing.more_recent_than(&packet) {
                                        res.send(false).ok();
                                        continue;
                                    } else {
                                        // remove the packet from the update time index
                                        tables.update_time.remove(&packet.timestamp().to_bytes(), key.as_bytes())?;
                                        true
                                    }
                                } else {
                                    false
                                };
                                let value = packet.serialize();
                                tables.signed_packets.insert(key.as_bytes(), &value[..])?;
                                tables.update_time.insert(&packet.timestamp().to_bytes(), key.as_bytes())?;
                                if replaced {
                                    inc!(Metrics, store_packets_updated);
                                } else {
                                    inc!(Metrics, store_packets_inserted);
                                }
                                res.send(true).ok();
                            }
                            Message::Remove { key, res } => {
                                trace!("remove {}", key);
                                let updated = if let Some(row) = tables.signed_packets.remove(key.as_bytes())? {
                                    let packet = SignedPacket::deserialize(row.value())?;
                                    tables.update_time.remove(&packet.timestamp().to_bytes(), key.as_bytes())?;
                                    inc!(Metrics, store_packets_removed);
                                    true
                                } else {
                                    false
                                };
                                if updated {
                                    inc!(Metrics, store_packets_removed);
                                }
                                res.send(updated).ok();
                            }
                            Message::Snapshot { res } => {
                                trace!("snapshot");
                                res.send(Snapshot::new(&self.db)?).ok();
                            }
                            Message::CheckExpired { key, time } => {
                                trace!("check expired {} at {}", key, u64::from_be_bytes(time));
                                if let Some(packet) = get_packet(&tables.signed_packets, &key)? {
                                    if packet.timestamp() < expired {
                                        tables.update_time.remove(&time, key.as_bytes())?;
                                        let _ = tables.signed_packets.remove(key.as_bytes())?;
                                        inc!(Metrics, store_packets_expired);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            drop(tables);
            transaction.commit()?;
        }
        Ok(())
    }
}

/// A struct similar to [`redb::Table`] but for all tables that make up the
/// signed packet store.
pub(super) struct Tables<'a> {
    pub signed_packets: redb::Table<'a, &'static SignedPacketsKey, &'static [u8]>,
    pub update_time: redb::MultimapTable<'a, [u8; 8], SignedPacketsKey>,
}

impl<'txn> Tables<'txn> {
    pub fn new(tx: &'txn redb::WriteTransaction) -> result::Result<Self, redb::TableError> {
        Ok(Self {
            signed_packets: tx.open_table(SIGNED_PACKETS_TABLE)?,
            update_time: tx.open_multimap_table(UPDATE_TIME_TABLE)?,
        })
    }
}

pub(super) struct Snapshot {
    #[allow(dead_code)]
    pub signed_packets: redb::ReadOnlyTable<&'static SignedPacketsKey, &'static [u8]>,
    pub update_time: redb::ReadOnlyMultimapTable<[u8; 8], SignedPacketsKey>,
}

impl Snapshot {
    pub fn new(db: &Database) -> Result<Self> {
        let tx = db.begin_read()?;
        Ok(Self {
            signed_packets: tx.open_table(SIGNED_PACKETS_TABLE)?,
            update_time: tx.open_multimap_table(UPDATE_TIME_TABLE)?,
        })
    }
}

impl SignedPacketStore {
    pub fn persistent(path: impl AsRef<Path>, options: Options) -> Result<Self> {
        let path = path.as_ref();
        info!("loading packet database from {}", path.to_string_lossy());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create database directory at {}",
                    path.to_string_lossy()
                )
            })?;
        }
        let db = Database::builder()
            .create(path)
            .context("failed to open packet database")?;
        Self::open(db, options)
    }

    pub fn in_memory(options: Options) -> Result<Self> {
        info!("using in-memory packet database");
        let db = Database::builder().create_with_backend(InMemoryBackend::new())?;
        Self::open(db, options)
    }

    pub fn open(db: Database, options: Options) -> Result<Self> {
        // create tables
        let write_tx = db.begin_write()?;
        let _ = Tables::new(&write_tx)?;
        write_tx.commit()?;
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

    pub async fn upsert(&self, packet: SignedPacket) -> Result<bool> {
        let (tx, rx) = oneshot::channel();
        self.send.send(Message::Upsert { packet, res: tx }).await?;
        Ok(rx.await?)
    }

    pub async fn get(&self, key: &PublicKeyBytes) -> Result<Option<SignedPacket>> {
        let (tx, rx) = oneshot::channel();
        self.send.send(Message::Get { key: *key, res: tx }).await?;
        Ok(rx.await?)
    }

    pub async fn remove(&self, key: &PublicKeyBytes) -> Result<bool> {
        let (tx, rx) = oneshot::channel();
        self.send
            .send(Message::Remove { key: *key, res: tx })
            .await?;
        Ok(rx.await?)
    }
}

fn get_packet(
    table: &impl ReadableTable<&'static SignedPacketsKey, &'static [u8]>,
    key: &PublicKeyBytes,
) -> Result<Option<SignedPacket>> {
    let Some(row) = table.get(key.as_ref()).context("database fetch failed")? else {
        return Ok(None);
    };
    let packet = SignedPacket::deserialize(row.value()).context("parsing signed packet failed")?;
    Ok(Some(packet))
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
async fn evict_task_inner(send: mpsc::Sender<Message>, options: Options) -> anyhow::Result<()> {
    let expiry_us = options.eviction.as_micros() as u64;
    loop {
        let (tx, rx) = oneshot::channel();
        let _ = send.send(Message::Snapshot { res: tx }).await.ok();
        // if we can't get the snapshot we exit the loop, main actor dead
        let Ok(snapshot) = rx.await else {
            anyhow::bail!("failed to get snapshot");
        };
        let expired = Timestamp::now() - expiry_us;
        trace!("evicting packets older than {}", expired);
        // if getting the range fails we exit the loop and shut down
        // if individual reads fail we log the error and limp on
        for item in snapshot.update_time.range(..expired.to_bytes())? {
            let (time, keys) = match item {
                Ok(v) => v,
                Err(e) => {
                    error!("failed to read update_time row {:?}", e);
                    continue;
                }
            };
            let time = time.value();
            trace!("evicting expired packets at {}", u64::from_be_bytes(time));
            for item in keys {
                let key = match item {
                    Ok(v) => v,
                    Err(e) => {
                        error!(
                            "failed to read update_time item at {}: {:?}",
                            u64::from_be_bytes(time),
                            e
                        );
                        continue;
                    }
                };
                let key = PublicKeyBytes::new(key.value());
                debug!(
                    "evicting expired packet {} {}",
                    u64::from_be_bytes(time),
                    key
                );
                send.send(Message::CheckExpired { time, key }).await?;
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
        let rt = tokio::runtime::Handle::try_current()?;
        let handle = std::thread::Builder::new()
            .name(name.into())
            .spawn(move || rt.block_on(f()))
            .context("failed to spawn thread")?;
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
pub(super) struct PeekableReceiver<T> {
    msg: Option<T>,
    recv: tokio::sync::mpsc::Receiver<T>,
}

#[allow(dead_code)]
impl<T> PeekableReceiver<T> {
    pub fn new(recv: tokio::sync::mpsc::Receiver<T>) -> Self {
        Self { msg: None, recv }
    }

    /// Receive the next message.
    ///
    /// Will block if there are no messages.
    /// Returns None only if there are no more messages (sender is dropped).
    pub async fn recv(&mut self) -> Option<T> {
        if let Some(msg) = self.msg.take() {
            return Some(msg);
        }
        self.recv.recv().await
    }

    /// Push back a message. This will only work if there is room for it.
    /// Otherwise, it will fail and return the message.
    pub fn push_back(&mut self, msg: T) -> std::result::Result<(), T> {
        if self.msg.is_none() {
            self.msg = Some(msg);
            Ok(())
        } else {
            Err(msg)
        }
    }
}
