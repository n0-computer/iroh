use std::{path::Path, result, time::Duration};

use anyhow::{Context, Result};
use iroh_metrics::inc;
use pkarr::SignedPacket;
use redb::{backends::InMemoryBackend, Database, ReadableTable, TableDefinition};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{metrics::Metrics, util::PublicKeyBytes};

pub type SignedPacketsKey = [u8; 32];
const SIGNED_PACKETS_TABLE: TableDefinition<&SignedPacketsKey, &[u8]> =
    TableDefinition::new("signed-packets-1");

#[derive(Debug)]
pub struct SignedPacketStore {
    send: mpsc::Sender<Message>,
    cancel: CancellationToken,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for SignedPacketStore {
    fn drop(&mut self) {
        // cancel the actor
        self.cancel.cancel();
        // join the thread. This is important so that Drop implementations that
        // are called from the actor thread can complete before we return.
        if let Some(thread) = self.thread.take() {
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
}

struct Actor {
    db: Database,
    recv: mpsc::Receiver<Message>,
    cancel: CancellationToken,
    max_batch_size: usize,
    max_batch_time: Duration,
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
        loop {
            let transaction = self.db.begin_write()?;
            let mut tables = Tables::new(&transaction)?;
            let timeout = tokio::time::sleep(self.max_batch_time);
            tokio::pin!(timeout);
            for _ in 0..self.max_batch_size {
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
        let cancel = CancellationToken::new();
        let cancel2 = cancel.clone();
        let actor = Actor {
            db,
            recv,
            cancel: cancel2,
            max_batch_size: 1024 * 64,
            max_batch_time: Duration::from_secs(1),
        };
        let handle = tokio::runtime::Handle::try_current()?;
        // start an io thread and donate it to the tokio runtime so we can do blocking IO
        // inside the thread despite being in a tokio runtime
        let thread = std::thread::spawn(move || {
            handle.block_on(actor.run());
        });
        Ok(Self {
            send,
            cancel,
            thread: Some(thread),
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
