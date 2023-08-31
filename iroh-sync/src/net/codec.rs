use anyhow::{bail, ensure, Result};
use bytes::{Buf, BufMut, BytesMut};
use futures::SinkExt;
use iroh_net::key::PublicKey;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_stream::StreamExt;
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};
use tracing::{debug, trace};

use crate::{store, NamespaceId, Replica};

#[derive(Debug, Default)]
struct SyncCodec;

const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 1024; // This is likely too large, but lets have some restrictions

impl Decoder for SyncCodec {
    type Item = Message;
    type Error = anyhow::Error;
    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
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

    fn encode(
        &mut self,
        item: Message,
        dst: &mut BytesMut,
    ) -> std::result::Result<(), Self::Error> {
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
    Init {
        /// Namespace to sync
        namespace: NamespaceId,
        /// Initial message
        message: crate::sync::ProtocolMessage,
    },
    Sync(crate::sync::ProtocolMessage),
}

/// Runs the initiator side of the sync protocol.
pub(super) async fn run_alice<S: store::Store, R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    writer: &mut W,
    reader: &mut R,
    alice: &Replica<S::Instance>,
    other_peer_id: PublicKey,
) -> Result<()> {
    let other_peer_id = *other_peer_id.as_bytes();
    let mut reader = FramedRead::new(reader, SyncCodec);
    let mut writer = FramedWrite::new(writer, SyncCodec);

    // Init message

    let init_message = Message::Init {
        namespace: alice.namespace(),
        message: alice.sync_initial_message().map_err(Into::into)?,
    };
    trace!("alice -> bob: {:#?}", init_message);
    writer.send(init_message).await?;

    // Sync message loop

    while let Some(msg) = reader.next().await {
        match msg? {
            Message::Init { .. } => {
                bail!("unexpected message: init");
            }
            Message::Sync(msg) => {
                if let Some(msg) = alice
                    .sync_process_message(msg, other_peer_id)
                    .map_err(Into::into)?
                {
                    trace!("alice -> bob: {:#?}", msg);
                    writer.send(Message::Sync(msg)).await?;
                } else {
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Runs the receiver side of the sync protocol.
pub(super) async fn run_bob<S: store::Store, R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    writer: &mut W,
    reader: &mut R,
    replica_store: S,
    other_peer_id: PublicKey,
) -> Result<()> {
    let other_peer_id = *other_peer_id.as_bytes();
    let mut reader = FramedRead::new(reader, SyncCodec);
    let mut writer = FramedWrite::new(writer, SyncCodec);

    let mut replica = None;

    while let Some(msg) = reader.next().await {
        match msg? {
            Message::Init { namespace, message } => {
                ensure!(replica.is_none(), "double init message");

                match replica_store.open_replica(&namespace)? {
                    Some(r) => {
                        debug!("run_bob: process initial message for {}", namespace);
                        if let Some(msg) = r
                            .sync_process_message(message, other_peer_id)
                            .map_err(Into::into)?
                        {
                            trace!("bob -> alice: {:#?}", msg);
                            writer.send(Message::Sync(msg)).await?;
                        } else {
                            break;
                        }
                        replica = Some(r);
                    }
                    None => {
                        bail!("unable to synchronize unknown namespace: {}", namespace);
                    }
                }
            }
            Message::Sync(msg) => match replica {
                Some(ref replica) => {
                    if let Some(msg) = replica
                        .sync_process_message(msg, other_peer_id)
                        .map_err(Into::into)?
                    {
                        trace!("bob -> alice: {:#?}", msg);
                        writer.send(Message::Sync(msg)).await?;
                    } else {
                        break;
                    }
                }
                None => {
                    bail!("unexpected sync message without init");
                }
            },
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        store::{GetFilter, Store},
        sync::Namespace,
        AuthorId,
    };
    use iroh_bytes::Hash;
    use iroh_net::key::SecretKey;
    use rand_core::{CryptoRngCore, SeedableRng};

    use super::*;

    #[tokio::test]
    async fn test_sync_simple() -> Result<()> {
        let mut rng = rand::thread_rng();
        let alice_peer_id = SecretKey::from_bytes(&[1u8; 32]).public();
        let bob_peer_id = SecretKey::from_bytes(&[2u8; 32]).public();

        let alice_replica_store = store::memory::Store::default();
        // For now uses same author on both sides.
        let author = alice_replica_store.new_author(&mut rng).unwrap();

        let namespace = Namespace::new(&mut rng);

        let alice_replica = alice_replica_store.new_replica(namespace.clone()).unwrap();
        alice_replica
            .hash_and_insert("hello bob", &author, "from alice")
            .unwrap();

        let bob_replica_store = store::memory::Store::default();
        let bob_replica = bob_replica_store.new_replica(namespace.clone()).unwrap();
        bob_replica
            .hash_and_insert("hello alice", &author, "from bob")
            .unwrap();

        assert_eq!(
            bob_replica_store
                .get(bob_replica.namespace(), GetFilter::All)
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            alice_replica_store
                .get(alice_replica.namespace(), GetFilter::All)
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap()
                .len(),
            1
        );

        let (alice, bob) = tokio::io::duplex(64);

        let (mut alice_reader, mut alice_writer) = tokio::io::split(alice);
        let replica = alice_replica.clone();
        let alice_task = tokio::task::spawn(async move {
            run_alice::<store::memory::Store, _, _>(
                &mut alice_writer,
                &mut alice_reader,
                &replica,
                bob_peer_id,
            )
            .await
        });

        let (mut bob_reader, mut bob_writer) = tokio::io::split(bob);
        let bob_replica_store_task = bob_replica_store.clone();
        let bob_task = tokio::task::spawn(async move {
            run_bob::<store::memory::Store, _, _>(
                &mut bob_writer,
                &mut bob_reader,
                bob_replica_store_task,
                alice_peer_id,
            )
            .await
        });

        alice_task.await??;
        bob_task.await??;

        assert_eq!(
            bob_replica_store
                .get(bob_replica.namespace(), GetFilter::All)
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            alice_replica_store
                .get(alice_replica.namespace(), GetFilter::All)
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
        let alice_store = store::memory::Store::default();
        let bob_store = store::memory::Store::default();
        test_sync_many_authors(alice_store, bob_store).await
    }

    #[tokio::test]
    async fn test_sync_many_authors_fs() -> Result<()> {
        let _guard = iroh_test::logging::setup();
        let tmpdir = tempfile::tempdir()?;
        let alice_store = store::fs::Store::new(tmpdir.path().join("a.db"))?;
        let bob_store = store::fs::Store::new(tmpdir.path().join("b.db"))?;
        test_sync_many_authors(alice_store, bob_store).await
    }

    type Message = (AuthorId, Vec<u8>, Hash);

    fn insert_messages<S: Store>(
        mut rng: impl CryptoRngCore,
        store: &S,
        replica: &Replica<S::Instance>,
        num_authors: usize,
        msgs_per_author: usize,
        key_value_fn: impl Fn(&AuthorId, usize) -> (String, String),
    ) -> Vec<Message> {
        let mut res = vec![];
        let authors: Vec<_> = (0..num_authors)
            .map(|_| store.new_author(&mut rng).unwrap())
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

    fn get_messages<S: Store>(store: &S, namespace: NamespaceId) -> Vec<Message> {
        let mut msgs = store
            .get(namespace, GetFilter::All)
            .unwrap()
            .map(|entry| {
                entry.map(|entry| (entry.author(), entry.key().to_vec(), entry.content_hash()))
            })
            .collect::<Result<Vec<_>>>()
            .unwrap();
        msgs.sort();
        msgs
    }

    async fn test_sync_many_authors<S: Store>(alice_store: S, bob_store: S) -> Result<()> {
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
                let namespace = Namespace::new(&mut rng);

                let mut all_messages = vec![];

                let alice_replica = alice_store.new_replica(namespace.clone()).unwrap();

                let alice_messages = insert_messages(
                    &mut rng,
                    &alice_store,
                    &alice_replica,
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

                let bob_replica = bob_store.new_replica(namespace.clone()).unwrap();
                let bob_messages = insert_messages(
                    &mut rng,
                    &bob_store,
                    &bob_replica,
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

                let res = get_messages(&alice_store, alice_replica.namespace());
                assert_eq!(res, alice_messages);

                let res = get_messages(&bob_store, bob_replica.namespace());
                assert_eq!(res, bob_messages);

                run_sync(
                    &alice_store,
                    alice_node_pubkey,
                    &bob_store,
                    bob_node_pubkey,
                    namespace.id(),
                )
                .await?;

                let res = get_messages(&bob_store, bob_replica.namespace());
                assert_eq!(res.len(), all_messages.len());
                assert_eq!(res, all_messages);

                let res = get_messages(&bob_store, bob_replica.namespace());
                assert_eq!(res.len(), all_messages.len());
                assert_eq!(res, all_messages);
            }
        }
        Ok(())
    }

    async fn run_sync<S: Store>(
        alice_store: &S,
        alice_node_pubkey: PublicKey,
        bob_store: &S,
        bob_node_pubkey: PublicKey,
        namespace: NamespaceId,
    ) -> Result<()> {
        let (alice, bob) = tokio::io::duplex(1024);

        let (mut alice_reader, mut alice_writer) = tokio::io::split(alice);
        let alice_replica = alice_store.open_replica(&namespace)?.unwrap();
        let alice_task = tokio::task::spawn(async move {
            run_alice::<S, _, _>(
                &mut alice_writer,
                &mut alice_reader,
                &alice_replica,
                bob_node_pubkey,
            )
            .await
        });

        let (mut bob_reader, mut bob_writer) = tokio::io::split(bob);
        let bob_store = bob_store.clone();
        let bob_task = tokio::task::spawn(async move {
            run_bob::<S, _, _>(
                &mut bob_writer,
                &mut bob_reader,
                bob_store,
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
        let alice_store = store::memory::Store::default();
        let bob_store = store::memory::Store::default();
        test_sync_timestamps(alice_store, bob_store).await
    }

    #[tokio::test]
    async fn test_sync_timestamps_fs() -> Result<()> {
        let _guard = iroh_test::logging::setup();
        let tmpdir = tempfile::tempdir()?;
        let alice_store = store::fs::Store::new(tmpdir.path().join("a.db"))?;
        let bob_store = store::fs::Store::new(tmpdir.path().join("b.db"))?;
        test_sync_timestamps(alice_store, bob_store).await
    }

    async fn test_sync_timestamps<S: Store>(alice_store: S, bob_store: S) -> Result<()> {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(99);
        let alice_node_pubkey = SecretKey::generate_with_rng(&mut rng).public();
        let bob_node_pubkey = SecretKey::generate_with_rng(&mut rng).public();
        let namespace = Namespace::new(&mut rng);
        let alice_replica = alice_store.new_replica(namespace.clone()).unwrap();
        let bob_replica = bob_store.new_replica(namespace.clone()).unwrap();

        let author = alice_store.new_author(&mut rng)?;
        bob_store.import_author(author.clone())?;

        let key = vec![1u8];
        let value_alice = vec![2u8];
        let value_bob = vec![3u8];
        // Insert into alice
        let hash_alice = alice_replica
            .hash_and_insert(&key, &author, &value_alice)
            .unwrap();
        // Insert into bob
        let hash_bob = bob_replica
            .hash_and_insert(&key, &author, &value_bob)
            .unwrap();

        assert_eq!(
            get_messages(&alice_store, alice_replica.namespace()),
            vec![(author.id(), key.clone(), hash_alice)]
        );

        assert_eq!(
            get_messages(&bob_store, bob_replica.namespace()),
            vec![(author.id(), key.clone(), hash_bob)]
        );

        run_sync(
            &alice_store,
            alice_node_pubkey,
            &bob_store,
            bob_node_pubkey,
            namespace.id(),
        )
        .await?;

        assert_eq!(
            get_messages(&alice_store, alice_replica.namespace()),
            vec![(author.id(), key.clone(), hash_bob)]
        );

        assert_eq!(
            get_messages(&bob_store, bob_replica.namespace()),
            vec![(author.id(), key.clone(), hash_bob)]
        );

        Ok(())
    }
}
