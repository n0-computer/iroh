use std::{path::Path, result, time::Duration};

use anyhow::{Context, Result};
use bytes::Bytes;
use iroh_metrics::inc;
use pkarr::{system_time, SignedPacket};
use redb::{backends::InMemoryBackend, Database, ReadableTable, TableDefinition};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::{metrics::Metrics, util::PublicKeyBytes};

pub type SignedPacketsKey = [u8; 32];
const SIGNED_PACKETS_TABLE: TableDefinition<&SignedPacketsKey, &[u8]> =
    TableDefinition::new("signed-packets-1");
const MAX_BATCH_SIZE: usize = 1024 * 64;
const MAX_BATCH_TIME: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub struct SignedPacketStore {
    send: mpsc::Sender<Message>,
    cancel: CancellationToken,
    write_thread: Option<std::thread::JoinHandle<()>>,
    evict_thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for SignedPacketStore {
    fn drop(&mut self) {
        println!("Dropping SignedPacketStore");
        // cancel the actor
        self.cancel.cancel();
        // join the thread. This is important so that Drop implementations that
        // are called from the actor thread can complete before we return.
        if let Some(thread) = self.write_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.evict_thread.take() {
            let _ = thread.join();
        }
    }
}

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
        res: oneshot::Sender<Snapshot>,
    },
    CheckExpired {
        key: PublicKeyBytes,
    },
}

struct Actor {
    db: Database,
    recv: mpsc::Receiver<Message>,
    cancel: CancellationToken,
    options: Options,
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Maximum number of packets to process in a single write transaction.
    max_batch_size: usize,
    /// Maximum time to keep a write transaction open.
    max_batch_time: Duration,
    /// Time to keep packets in the store before eviction.
    eviction: Duration,
    /// Pause between eviction checks.
    eviction_interval: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_batch_size: MAX_BATCH_SIZE,
            max_batch_time: MAX_BATCH_TIME,
            eviction: Duration::from_secs(10),
            eviction_interval: Duration::from_secs(10),
        }
    }
}

impl Actor {
    async fn run(mut self) {
        match self.run0().await {
            Ok(()) => {}
            Err(e) => {
                self.cancel.cancel();
                tracing::error!("packet store actor failed: {:?}", e);
            }
        }
    }

    async fn run0(&mut self) -> anyhow::Result<()> {
        let expired_us = Duration::from_secs(10).as_micros() as u64;
        loop {
            let transaction = self.db.begin_write()?;
            let mut tables = Tables::new(&transaction)?;
            let timeout = tokio::time::sleep(self.options.max_batch_time);
            let expired = system_time() - expired_us;
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
                                let packet = get_packet(&tables.signed_packets, &key)?;
                                res.send(packet).ok();
                            }
                            Message::Upsert { packet, res } => {
                                let key = PublicKeyBytes::from_signed_packet(&packet);
                                let mut replaced = false;
                                if let Some(existing) = get_packet(&tables.signed_packets, &key)? {
                                    if existing.more_recent_than(&packet) {
                                        res.send(false).ok();
                                        continue;
                                    } else {
                                        replaced = true;
                                    }
                                }
                                let value = packet.as_bytes();
                                tables.signed_packets.insert(key.as_bytes(), &value[..])?;
                                if replaced {
                                    inc!(Metrics, store_packets_updated);
                                } else {
                                    inc!(Metrics, store_packets_inserted);
                                }
                                res.send(true).ok();
                            }
                            Message::Remove { key, res } => {
                                let updated =
                                    tables.signed_packets.remove(key.as_bytes())?.is_some()
                                ;
                                if updated {
                                    inc!(Metrics, store_packets_removed);
                                }
                                res.send(updated).ok();
                            }
                            Message::Snapshot { res } => {
                                res.send(Snapshot::new(&self.db)?).ok();
                            }
                            Message::CheckExpired { key } => {
                                if let Some(packet) = get_packet(&tables.signed_packets, &key)? {
                                    if packet.timestamp() < expired {
                                        println!("Removing expired packet");
                                        let _ = tables.signed_packets.remove(key.as_bytes())?;
                                        // inc!(Metrics, store_packets_expired);
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
    }
}

/// A struct similar to [`redb::Table`] but for all tables that make up the
/// signed packet store.
pub(super) struct Tables<'a> {
    pub signed_packets: redb::Table<'a, &'static SignedPacketsKey, &'static [u8]>,
}

impl<'txn> Tables<'txn> {
    pub fn new(tx: &'txn redb::WriteTransaction) -> result::Result<Self, redb::TableError> {
        Ok(Self {
            signed_packets: tx.open_table(SIGNED_PACKETS_TABLE)?,
        })
    }
}

pub(super) struct Snapshot {
    pub signed_packets: redb::ReadOnlyTable<&'static SignedPacketsKey, &'static [u8]>,
}

impl Snapshot {
    pub fn new(db: &Database) -> Result<Self> {
        let tx = db.begin_read()?;
        Ok(Self {
            signed_packets: tx.open_table(SIGNED_PACKETS_TABLE)?,
        })
    }
}

impl SignedPacketStore {
    pub fn persistent(path: impl AsRef<Path>) -> Result<Self> {
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
        Self::open(db)
    }

    pub fn in_memory() -> Result<Self> {
        info!("using in-memory packet database");
        let db = Database::builder().create_with_backend(InMemoryBackend::new())?;
        Self::open(db)
    }

    pub fn open(db: Database) -> Result<Self> {
        // create tables
        let write_tx = db.begin_write()?;
        let _ = Tables::new(&write_tx)?;
        write_tx.commit()?;
        let (send, recv) = mpsc::channel(1024);
        let send2 = send.clone();
        let cancel = CancellationToken::new();
        let cancel2 = cancel.clone();
        let cancel3 = cancel.clone();
        let options = Default::default();
        let actor = Actor {
            db,
            recv,
            cancel: cancel2,
            options,
        };
        // start an io thread and donate it to the tokio runtime so we can do blocking IO
        // inside the thread despite being in a tokio runtime
        let handle = tokio::runtime::Handle::try_current()?;
        let write_thread = std::thread::Builder::new()
            .name("packet-store-actor".into())
            .spawn(move || {
                handle.block_on(actor.run());
            })?;
        let handle = tokio::runtime::Handle::try_current()?;
        let evict_thread = std::thread::Builder::new()
            .name("packet-store-evict".into())
            .spawn(move || {
                handle.block_on(evict_task(send2, options, cancel3));
            })?;
        Ok(Self {
            send,
            cancel,
            write_thread: Some(write_thread),
            evict_thread: Some(evict_thread),
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
    let Some(row) = table.get(key.as_ref())? else {
        return Ok(None);
    };
    let packet = SignedPacket::from_bytes(&row.value().to_vec().into())?;
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
    let expiry_ms = options.eviction.as_micros() as u64;
    loop {
        let (tx, rx) = oneshot::channel();
        let _ = send.send(Message::Snapshot { res: tx }).await.ok();
        let Ok(snapshot) = rx.await else {
            anyhow::bail!("failed to get snapshot");
        };
        let expired = system_time() - expiry_ms;
        for item in snapshot.signed_packets.iter()? {
            let (_, value) = item?;
            let value = Bytes::copy_from_slice(value.value());
            let packet = SignedPacket::from_bytes(&value)?;
            if packet.timestamp() < expired {
                let _ = send
                    .send(Message::CheckExpired {
                        key: PublicKeyBytes::from_signed_packet(&packet),
                    })
                    .await?;
            }
        }
        // sleep for the eviction interval so we don't constantly check
        tokio::time::sleep(options.eviction_interval).await;
    }
}
