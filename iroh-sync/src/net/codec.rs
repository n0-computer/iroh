use anyhow::{bail, ensure, Result};
use bytes::{Buf, BufMut, BytesMut};
use futures::SinkExt;
use iroh_net::key::PublicKey;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_stream::StreamExt;
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};
use tracing::debug;

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
                        debug!("starting sync for {}", namespace);
                        if let Some(msg) = r
                            .sync_process_message(message, other_peer_id)
                            .map_err(Into::into)?
                        {
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
        store::{GetFilter, Store as _},
        sync::Namespace,
    };
    use iroh_net::key::SecretKey;

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
                .get(bob_replica.namespace(), GetFilter::all())
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            alice_replica_store
                .get(alice_replica.namespace(), GetFilter::all())
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
                .get(bob_replica.namespace(), GetFilter::all())
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            alice_replica_store
                .get(alice_replica.namespace(), GetFilter::all())
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
        let alice_store = store::memory::Store::default();
        let bob_store = store::memory::Store::default();
        test_sync_many_authors(alice_store, bob_store).await
    }

    #[tokio::test]
    async fn test_sync_many_authors_fs() -> Result<()> {
        let tmpdir = tempfile::tempdir()?;
        let alice_store = store::fs::Store::new(tmpdir.path().join("a.db"))?;
        let bob_store = store::fs::Store::new(tmpdir.path().join("b.db"))?;
        test_sync_many_authors(alice_store, bob_store).await
    }

    async fn test_sync_many_authors<S: store::Store>(
        alice_replica_store: S,
        bob_replica_store: S,
    ) -> Result<()> {
        let mut rng = rand::thread_rng();

        for num_messages in &[1, 2, 5, 10, 20] {
            for num_authors in &[2, 3, 4, 5, 10, 20] {
                println!("Using {num_authors} authors and {num_messages} messages per side");

                let alice_peer_id = SecretKey::generate().public();
                let bob_peer_id = SecretKey::generate().public();
                let namespace = Namespace::new(&mut rng);

                let authors_alice: Vec<_> = (0..*num_authors)
                    .map(|_| alice_replica_store.new_author(&mut rng).unwrap())
                    .collect();

                let alice_replica = alice_replica_store.new_replica(namespace.clone()).unwrap();
                for i in 0..*num_messages {
                    for (author_num, author) in authors_alice.iter().enumerate() {
                        alice_replica
                            .hash_and_insert(
                                format!("hello bob {i}"),
                                author,
                                format!("from alice: {author_num}"),
                            )
                            .unwrap();
                    }
                }

                let authors_bob: Vec<_> = (0..*num_authors)
                    .map(|_| bob_replica_store.new_author(&mut rng).unwrap())
                    .collect();
                let bob_replica = bob_replica_store.new_replica(namespace.clone()).unwrap();
                for i in 0..*num_messages {
                    for (author_num, author) in authors_bob.iter().enumerate() {
                        bob_replica
                            .hash_and_insert(
                                format!("hello alice {i}"),
                                author,
                                format!("from bob: {author_num}"),
                            )
                            .unwrap();
                    }
                }

                assert_eq!(
                    bob_replica_store
                        .get(bob_replica.namespace(), GetFilter::all())
                        .unwrap()
                        .collect::<Result<Vec<_>>>()
                        .unwrap()
                        .len(),
                    num_messages * num_authors
                );
                assert_eq!(
                    alice_replica_store
                        .get(alice_replica.namespace(), GetFilter::all())
                        .unwrap()
                        .collect::<Result<Vec<_>>>()
                        .unwrap()
                        .len(),
                    num_messages * num_authors
                );

                let (alice, bob) = tokio::io::duplex(64 + num_messages);

                println!("syncing");
                let (mut alice_reader, mut alice_writer) = tokio::io::split(alice);
                let replica = alice_replica.clone();
                let alice_task = tokio::task::spawn(async move {
                    run_alice::<S, _, _>(
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
                    run_bob::<S, _, _>(
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
                    alice_replica_store
                        .get(alice_replica.namespace(), GetFilter::all())
                        .unwrap()
                        .collect::<Result<Vec<_>>>()
                        .unwrap()
                        .len(),
                    2 * num_messages * num_authors,
                    "alice is missing messages"
                );

                assert_eq!(
                    bob_replica_store
                        .get(bob_replica.namespace(), GetFilter::all())
                        .unwrap()
                        .collect::<Result<Vec<_>>>()
                        .unwrap()
                        .len(),
                    2 * num_messages * num_authors,
                    "bob is missing messages"
                );
            }
        }
        Ok(())
    }
}
