use std::future::Future;

use anyhow::{anyhow, ensure};
use bytes::{Buf, BufMut, BytesMut};
use futures::SinkExt;
use iroh_net::key::PublicKey;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_stream::StreamExt;
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};
use tracing::{debug, trace, Span};

use crate::{
    actor::SyncHandle,
    net::{AbortReason, AcceptError, AcceptOutcome, ConnectError},
    NamespaceId, SyncOutcome,
};

#[derive(Debug, Default)]
struct SyncCodec;

const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 1024; // This is likely too large, but lets have some restrictions

impl Decoder for SyncCodec {
    type Item = Message;
    type Error = anyhow::Error;
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }
        let bytes: [u8; 4] = src[..4].try_into().unwrap();
        let frame_len = u32::from_be_bytes(bytes) as usize;
        ensure!(
            frame_len <= MAX_MESSAGE_SIZE,
            "received message that is too large: {}",
            frame_len
        );
        if src.len() < 4 + frame_len {
            return Ok(None);
        }

        let message: Message = postcard::from_bytes(&src[4..4 + frame_len])?;
        src.advance(4 + frame_len);
        Ok(Some(message))
    }
}

impl Encoder<Message> for SyncCodec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let len =
            postcard::serialize_with_flavor(&item, postcard::ser_flavors::Size::default()).unwrap();
        ensure!(
            len <= MAX_MESSAGE_SIZE,
            "attempting to send message that is too large {}",
            len
        );

        dst.put_u32(u32::try_from(len).expect("already checked"));
        if dst.len() < 4 + len {
            dst.resize(4 + len, 0u8);
        }
        postcard::to_slice(&item, &mut dst[4..])?;

        Ok(())
    }
}

/// Sync Protocol
///
/// - Init message: signals which namespace is being synced
/// - N Sync messages
///
/// On any error and on success the substream is closed.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Message {
    /// Init message (sent by the dialing peer)
    Init {
        /// Namespace to sync
        namespace: NamespaceId,
        /// Initial message
        message: crate::sync::ProtocolMessage,
    },
    /// Sync messages (sent by both peers)
    Sync(crate::sync::ProtocolMessage),
    /// Abort message (sent by the accepting peer to decline a request)
    Abort { reason: AbortReason },
}

/// Runs the initiator side of the sync protocol.
pub(super) async fn run_alice<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    writer: &mut W,
    reader: &mut R,
    handle: &SyncHandle,
    namespace: NamespaceId,
    peer: PublicKey,
) -> Result<SyncOutcome, ConnectError> {
    let peer_bytes = *peer.as_bytes();
    let mut reader = FramedRead::new(reader, SyncCodec);
    let mut writer = FramedWrite::new(writer, SyncCodec);

    let mut progress = Some(SyncOutcome::default());

    // Init message

    let message = handle
        .sync_initial_message(namespace)
        .await
        .map_err(ConnectError::sync)?;
    let init_message = Message::Init { namespace, message };
    trace!("send init message");
    writer
        .send(init_message)
        .await
        .map_err(ConnectError::sync)?;

    // Sync message loop
    while let Some(msg) = reader.next().await {
        let msg = msg.map_err(ConnectError::sync)?;
        match msg {
            Message::Init { .. } => {
                return Err(ConnectError::sync(anyhow!("unexpected init message")));
            }
            Message::Sync(msg) => {
                trace!("recv process message");
                let current_progress = progress.take().unwrap();
                let (reply, next_progress) = handle
                    .sync_process_message(namespace, msg, peer_bytes, current_progress)
                    .await
                    .map_err(ConnectError::sync)?;
                progress = Some(next_progress);
                if let Some(msg) = reply {
                    trace!("send process message");
                    writer
                        .send(Message::Sync(msg))
                        .await
                        .map_err(ConnectError::sync)?;
                } else {
                    break;
                }
            }
            Message::Abort { reason } => {
                return Err(ConnectError::remote_abort(reason));
            }
        }
    }

    trace!("done");
    Ok(progress.unwrap())
}

/// Runs the receiver side of the sync protocol.
#[cfg(test)]
pub(super) async fn run_bob<R, W, F, Fut>(
    writer: &mut W,
    reader: &mut R,
    handle: SyncHandle,
    accept_cb: F,
    peer: PublicKey,
) -> Result<(NamespaceId, SyncOutcome), AcceptError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: Fn(NamespaceId, PublicKey) -> Fut,
    Fut: Future<Output = AcceptOutcome>,
{
    let mut state = BobState::new(peer);
    let namespace = state.run(writer, reader, handle, accept_cb).await?;
    Ok((namespace, state.into_outcome()))
}

/// State for the receiver side of the sync protocol.
pub struct BobState {
    namespace: Option<NamespaceId>,
    peer: PublicKey,
    progress: Option<SyncOutcome>,
}

impl BobState {
    /// Create a new state for a single connection.
    pub fn new(peer: PublicKey) -> Self {
        Self {
            peer,
            namespace: None,
            progress: Some(Default::default()),
        }
    }

    fn fail(&self, reason: impl Into<anyhow::Error>) -> AcceptError {
        AcceptError::sync(self.peer, self.namespace(), reason.into())
    }

    /// Handle connection and run to end.
    pub async fn run<R, W, F, Fut>(
        &mut self,
        writer: W,
        reader: R,
        sync: SyncHandle,
        accept_cb: F,
    ) -> Result<NamespaceId, AcceptError>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
        F: Fn(NamespaceId, PublicKey) -> Fut,
        Fut: Future<Output = AcceptOutcome>,
    {
        let mut reader = FramedRead::new(reader, SyncCodec);
        let mut writer = FramedWrite::new(writer, SyncCodec);
        while let Some(msg) = reader.next().await {
            let msg = msg.map_err(|e| self.fail(e))?;
            let next = match (msg, self.namespace.as_ref()) {
                (Message::Init { namespace, message }, None) => {
                    Span::current()
                        .record("namespace", tracing::field::display(&namespace.fmt_short()));
                    trace!("recv init message");
                    let accept = accept_cb(namespace, self.peer).await;
                    match accept {
                        AcceptOutcome::Allow => {
                            trace!("allow request");
                        }
                        AcceptOutcome::Reject(reason) => {
                            debug!(?reason, "reject request");
                            writer
                                .send(Message::Abort { reason })
                                .await
                                .map_err(|e| self.fail(e))?;
                            return Err(AcceptError::Abort {
                                namespace,
                                peer: self.peer,
                                reason,
                            });
                        }
                    }
                    let last_progress = self.progress.take().unwrap();
                    let next = sync
                        .sync_process_message(
                            namespace,
                            message,
                            *self.peer.as_bytes(),
                            last_progress,
                        )
                        .await;
                    self.namespace = Some(namespace);
                    next
                }
                (Message::Sync(msg), Some(namespace)) => {
                    trace!("recv process message");
                    let last_progress = self.progress.take().unwrap();
                    sync.sync_process_message(*namespace, msg, *self.peer.as_bytes(), last_progress)
                        .await
                }
                (Message::Init { .. }, Some(_)) => {
                    return Err(self.fail(anyhow!("double init message")))
                }
                (Message::Sync(_), None) => {
                    return Err(self.fail(anyhow!("unexpected sync message before init")))
                }
                (Message::Abort { .. }, _) => {
                    return Err(self.fail(anyhow!("unexpected sync abort message")))
                }
            };
            let (reply, progress) = next.map_err(|e| self.fail(e))?;
            self.progress = Some(progress);
            match reply {
                Some(msg) => {
                    trace!("send process message");
                    writer
                        .send(Message::Sync(msg))
                        .await
                        .map_err(|e| self.fail(e))?;
                }
                None => break,
            }
        }

        trace!("done");

        self.namespace()
            .ok_or_else(|| self.fail(anyhow!("Stream closed before init message")))
    }

    /// Get the namespace that is synced, if available.
    pub fn namespace(&self) -> Option<NamespaceId> {
        self.namespace
    }

    /// Consume self and get the [`SyncOutcome`] for this connection.
    pub fn into_outcome(self) -> SyncOutcome {
        self.progress.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        actor::OpenOpts,
        store::{self, fs::StoreInstance, Query, Store},
        AuthorId, NamespaceSecret,
    };
    use anyhow::Result;
    use iroh_base::hash::Hash;
    use iroh_net::key::SecretKey;
    use rand_core::{CryptoRngCore, SeedableRng};

    use super::*;

    #[tokio::test]
    async fn test_sync_simple() -> Result<()> {
        let mut rng = rand::thread_rng();
        let alice_peer_id = SecretKey::from_bytes(&[1u8; 32]).public();
        let bob_peer_id = SecretKey::from_bytes(&[2u8; 32]).public();

        let mut alice_store = store::Store::memory();
        // For now uses same author on both sides.
        let author = alice_store.new_author(&mut rng).unwrap();

        let namespace = NamespaceSecret::new(&mut rng);

        let mut alice_replica = alice_store.new_replica(namespace.clone()).unwrap();
        let alice_replica_id = alice_replica.id();
        alice_replica
            .hash_and_insert("hello bob", &author, "from alice")
            .unwrap();

        let mut bob_store = store::Store::memory();
        let mut bob_replica = bob_store.new_replica(namespace.clone()).unwrap();
        let bob_replica_id = bob_replica.id();
        bob_replica
            .hash_and_insert("hello alice", &author, "from bob")
            .unwrap();

        assert_eq!(
            bob_store
                .get_many(bob_replica_id, Query::all(),)
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            alice_store
                .get_many(alice_replica_id, Query::all())
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap()
                .len(),
            1
        );

        // close the replicas because now the async actor will take over
        alice_store.close_replica(alice_replica_id);
        bob_store.close_replica(bob_replica_id);

        let (alice, bob) = tokio::io::duplex(64);

        let (mut alice_reader, mut alice_writer) = tokio::io::split(alice);
        let alice_handle = SyncHandle::spawn(alice_store, None, "alice".to_string());
        alice_handle
            .open(namespace.id(), OpenOpts::default().sync())
            .await?;
        let namespace_id = namespace.id();
        let alice_handle2 = alice_handle.clone();
        let alice_task = tokio::task::spawn(async move {
            run_alice(
                &mut alice_writer,
                &mut alice_reader,
                &alice_handle2,
                namespace_id,
                bob_peer_id,
            )
            .await
        });

        let (mut bob_reader, mut bob_writer) = tokio::io::split(bob);
        let bob_handle = SyncHandle::spawn(bob_store, None, "bob".to_string());
        bob_handle
            .open(namespace.id(), OpenOpts::default().sync())
            .await?;
        let bob_handle2 = bob_handle.clone();
        let bob_task = tokio::task::spawn(async move {
            run_bob(
                &mut bob_writer,
                &mut bob_reader,
                bob_handle2,
                |_namespace, _peer| futures::future::ready(AcceptOutcome::Allow),
                alice_peer_id,
            )
            .await
        });

        alice_task.await??;
        bob_task.await??;

        let mut alice_store = alice_handle.shutdown().await?;
        let mut bob_store = bob_handle.shutdown().await?;

        assert_eq!(
            bob_store
                .get_many(namespace.id(), Query::all())
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            alice_store
                .get_many(namespace.id(), Query::all())
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap()
                .len(),
            2
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_sync_many_authors_memory() -> Result<()> {
        let _guard = iroh_test::logging::setup();
        let alice_store = store::Store::memory();
        let bob_store = store::Store::memory();
        test_sync_many_authors(alice_store, bob_store).await
    }

    #[tokio::test]
    async fn test_sync_many_authors_fs() -> Result<()> {
        let _guard = iroh_test::logging::setup();
        let tmpdir = tempfile::tempdir()?;
        let alice_store = store::fs::Store::persistent(tmpdir.path().join("a.db"))?;
        let bob_store = store::fs::Store::persistent(tmpdir.path().join("b.db"))?;
        test_sync_many_authors(alice_store, bob_store).await
    }

    type Message = (AuthorId, Vec<u8>, Hash);

    fn insert_messages(
        mut rng: impl CryptoRngCore,
        replica: &mut crate::sync::Replica<StoreInstance<&mut Store>>,
        num_authors: usize,
        msgs_per_author: usize,
        key_value_fn: impl Fn(&AuthorId, usize) -> (String, String),
    ) -> Vec<Message> {
        let mut res = vec![];
        let authors: Vec<_> = (0..num_authors)
            .map(|_| replica.peer.store.store.new_author(&mut rng).unwrap())
            .collect();

        for i in 0..msgs_per_author {
            for author in authors.iter() {
                let (key, value) = key_value_fn(&author.id(), i);
                let hash = replica.hash_and_insert(key.clone(), author, value).unwrap();
                res.push((author.id(), key.as_bytes().to_vec(), hash));
            }
        }
        res.sort();
        res
    }

    fn get_messages(store: &mut Store, namespace: NamespaceId) -> Vec<Message> {
        let mut msgs = store
            .get_many(namespace, Query::all())
            .unwrap()
            .map(|entry| {
                entry.map(|entry| {
                    (
                        entry.author_bytes(),
                        entry.key().to_vec(),
                        entry.content_hash(),
                    )
                })
            })
            .collect::<Result<Vec<_>>>()
            .unwrap();
        msgs.sort();
        msgs
    }

    async fn test_sync_many_authors(mut alice_store: Store, mut bob_store: Store) -> Result<()> {
        let num_messages = &[1, 2, 5, 10];
        let num_authors = &[2, 3, 4, 5, 10];
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(99);

        for num_messages in num_messages {
            for num_authors in num_authors {
                println!(
                    "bob & alice each using {num_authors} authors and inserting {num_messages} messages per author"
                );

                let alice_node_pubkey = SecretKey::generate_with_rng(&mut rng).public();
                let bob_node_pubkey = SecretKey::generate_with_rng(&mut rng).public();
                let namespace = NamespaceSecret::new(&mut rng);

                let mut all_messages = vec![];

                let mut alice_replica = alice_store.new_replica(namespace.clone()).unwrap();
                let alice_messages = insert_messages(
                    &mut rng,
                    &mut alice_replica,
                    *num_authors,
                    *num_messages,
                    |author, i| {
                        (
                            format!("hello bob {i}"),
                            format!("from alice by {author}: {i}"),
                        )
                    },
                );
                all_messages.extend_from_slice(&alice_messages);

                let mut bob_replica = bob_store.new_replica(namespace.clone()).unwrap();
                let bob_messages = insert_messages(
                    &mut rng,
                    &mut bob_replica,
                    *num_authors,
                    *num_messages,
                    |author, i| {
                        (
                            format!("hello bob {i}"),
                            format!("from bob by {author}: {i}"),
                        )
                    },
                );
                all_messages.extend_from_slice(&bob_messages);

                all_messages.sort();

                let res = get_messages(&mut alice_store, namespace.id());
                assert_eq!(res, alice_messages);

                let res = get_messages(&mut bob_store, namespace.id());
                assert_eq!(res, bob_messages);

                // replicas can be opened only once so close the replicas before spawning the
                // actors
                alice_store.close_replica(namespace.id());
                let alice_handle = SyncHandle::spawn(alice_store, None, "alice".to_string());

                bob_store.close_replica(namespace.id());
                let bob_handle = SyncHandle::spawn(bob_store, None, "bob".to_string());

                run_sync(
                    alice_handle.clone(),
                    alice_node_pubkey,
                    bob_handle.clone(),
                    bob_node_pubkey,
                    namespace.id(),
                )
                .await?;

                alice_store = alice_handle.shutdown().await?;
                bob_store = bob_handle.shutdown().await?;

                let res = get_messages(&mut bob_store, namespace.id());
                assert_eq!(res.len(), all_messages.len());
                assert_eq!(res, all_messages);

                let res = get_messages(&mut bob_store, namespace.id());
                assert_eq!(res.len(), all_messages.len());
                assert_eq!(res, all_messages);
            }
        }

        Ok(())
    }

    async fn run_sync(
        alice_handle: SyncHandle,
        alice_node_pubkey: PublicKey,
        bob_handle: SyncHandle,
        bob_node_pubkey: PublicKey,
        namespace: NamespaceId,
    ) -> Result<()> {
        alice_handle
            .open(namespace, OpenOpts::default().sync())
            .await?;
        bob_handle
            .open(namespace, OpenOpts::default().sync())
            .await?;
        let (alice, bob) = tokio::io::duplex(1024);

        let (mut alice_reader, mut alice_writer) = tokio::io::split(alice);
        let alice_task = tokio::task::spawn(async move {
            run_alice(
                &mut alice_writer,
                &mut alice_reader,
                &alice_handle,
                namespace,
                bob_node_pubkey,
            )
            .await
        });

        let (mut bob_reader, mut bob_writer) = tokio::io::split(bob);
        let bob_task = tokio::task::spawn(async move {
            run_bob(
                &mut bob_writer,
                &mut bob_reader,
                bob_handle,
                |_namespace, _peer| futures::future::ready(AcceptOutcome::Allow),
                alice_node_pubkey,
            )
            .await
        });

        alice_task.await??;
        bob_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn test_sync_timestamps_memory() -> Result<()> {
        let _guard = iroh_test::logging::setup();
        let alice_store = store::Store::memory();
        let bob_store = store::Store::memory();
        test_sync_timestamps(alice_store, bob_store).await
    }

    #[tokio::test]
    async fn test_sync_timestamps_fs() -> Result<()> {
        let _guard = iroh_test::logging::setup();
        let tmpdir = tempfile::tempdir()?;
        let alice_store = store::fs::Store::persistent(tmpdir.path().join("a.db"))?;
        let bob_store = store::fs::Store::persistent(tmpdir.path().join("b.db"))?;
        test_sync_timestamps(alice_store, bob_store).await
    }

    async fn test_sync_timestamps(mut alice_store: Store, mut bob_store: Store) -> Result<()> {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(99);
        let alice_node_pubkey = SecretKey::generate_with_rng(&mut rng).public();
        let bob_node_pubkey = SecretKey::generate_with_rng(&mut rng).public();
        let namespace = NamespaceSecret::new(&mut rng);

        let author = alice_store.new_author(&mut rng)?;
        bob_store.import_author(author.clone())?;

        let key = vec![1u8];
        let value_alice = vec![2u8];
        let value_bob = vec![3u8];
        let mut alice_replica = alice_store.new_replica(namespace.clone()).unwrap();
        let mut bob_replica = bob_store.new_replica(namespace.clone()).unwrap();
        // Insert into alice
        let hash_alice = alice_replica
            .hash_and_insert(&key, &author, &value_alice)
            .unwrap();
        // Insert into bob
        let hash_bob = bob_replica
            .hash_and_insert(&key, &author, &value_bob)
            .unwrap();

        assert_eq!(
            get_messages(&mut alice_store, namespace.id()),
            vec![(author.id(), key.clone(), hash_alice)]
        );

        assert_eq!(
            get_messages(&mut bob_store, namespace.id()),
            vec![(author.id(), key.clone(), hash_bob)]
        );

        alice_store.close_replica(namespace.id());
        bob_store.close_replica(namespace.id());

        let alice_handle = SyncHandle::spawn(alice_store, None, "alice".to_string());
        let bob_handle = SyncHandle::spawn(bob_store, None, "bob".to_string());

        run_sync(
            alice_handle.clone(),
            alice_node_pubkey,
            bob_handle.clone(),
            bob_node_pubkey,
            namespace.id(),
        )
        .await?;
        let mut alice_store = alice_handle.shutdown().await?;
        let mut bob_store = bob_handle.shutdown().await?;

        assert_eq!(
            get_messages(&mut alice_store, namespace.id()),
            vec![(author.id(), key.clone(), hash_bob)]
        );

        assert_eq!(
            get_messages(&mut bob_store, namespace.id()),
            vec![(author.id(), key.clone(), hash_bob)]
        );

        Ok(())
    }
}
