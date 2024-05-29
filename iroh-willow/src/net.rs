use anyhow::ensure;
use futures_concurrency::future::TryJoin;
use futures_util::future::TryFutureExt;
use iroh_base::{hash::Hash, key::NodeId};
use iroh_net::magic_endpoint::{Connection, RecvStream, SendStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
};
use tracing::{debug, error_span, field::Empty, instrument, trace, warn, Instrument, Span};

use crate::{
    actor::ActorHandle,
    proto::sync::{
        AccessChallenge, ChallengeHash, Channel, LogicalChannel, Message, CHALLENGE_HASH_LENGTH,
        MAX_PAYLOAD_SIZE_POWER,
    },
    session::{
        channels::{
            ChannelReceivers, ChannelSenders, Channels, LogicalChannelReceivers,
            LogicalChannelSenders,
        },
        Role, SessionInit,
    },
    util::channel::{
        inbound_channel, outbound_channel, Guarantees, Reader, Receiver, Sender, Writer,
    },
};

pub const CHANNEL_CAP: usize = 1024 * 64;

#[instrument(skip_all, name = "willow_net", fields(me=%me.fmt_short(), peer=Empty))]
pub async fn run(
    me: NodeId,
    actor: ActorHandle,
    conn: Connection,
    our_role: Role,
    init: SessionInit,
) -> anyhow::Result<()> {
    debug!(?our_role, "connected");
    let peer = iroh_net::magic_endpoint::get_remote_node_id(&conn)?;
    Span::current().record("peer", peer.fmt_short());
    let mut join_set = JoinSet::new();

    let (mut control_send_stream, mut control_recv_stream) = match our_role {
        Role::Alfie => conn.open_bi().await?,
        Role::Betty => conn.accept_bi().await?,
    };
    control_send_stream.set_priority(i32::MAX)?;
    debug!("control channel ready");

    let initial_transmission =
        exchange_commitments(&mut control_send_stream, &mut control_recv_stream).await?;
    debug!("exchanged commitments");

    let (control_send, control_recv) = spawn_channel(
        &mut join_set,
        Channel::Control,
        CHANNEL_CAP,
        CHANNEL_CAP,
        Guarantees::Unlimited,
        control_send_stream,
        control_recv_stream,
    );

    let (logical_send, logical_recv) = open_logical_channels(&mut join_set, conn, our_role).await?;
    debug!("logical channels ready");
    let channels = Channels {
        send: ChannelSenders {
            control_send,
            logical_send,
        },
        recv: ChannelReceivers {
            control_recv,
            logical_recv,
        },
    };
    let handle = actor
        .init_session(peer, our_role, initial_transmission, channels, init)
        .await?;

    join_set.spawn(async move {
        handle.on_finish().await?;
        tracing::info!("session finished");
        Ok(())
    });

    join_all(join_set).await?;
    debug!("all tasks finished");
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[error("missing channel: {0:?}")]
struct MissingChannel(LogicalChannel);

async fn open_logical_channels(
    join_set: &mut JoinSet<anyhow::Result<()>>,
    conn: Connection,
    our_role: Role,
) -> anyhow::Result<(LogicalChannelSenders, LogicalChannelReceivers)> {
    let cap = CHANNEL_CAP;
    let channels = LogicalChannel::all();
    let mut channels = match our_role {
        // Alfie opens a quic stream for each logical channel, and sends a single byte with the
        // channel id.
        Role::Alfie => {
            channels
                .map(|ch| {
                    let conn = conn.clone();
                    async move {
                        let (mut send, recv) = conn.open_bi().await?;
                        send.write_u8(ch.id()).await?;
                        trace!(?ch, "opened bi stream");
                        Result::<_, anyhow::Error>::Ok((ch, Some((send, recv))))
                    }
                })
                .try_join()
                .await
        }
        // Betty accepts as many quick streams as there are logical channels, and reads a single
        // byte on each, which is expected to contain a channel id.
        Role::Betty => {
            channels
                .map(|_| async {
                    let (send, mut recv) = conn.accept_bi().await?;
                    trace!("accepted bi stream");
                    let channel_id = recv.read_u8().await?;
                    trace!("read channel id {channel_id}");
                    let channel = LogicalChannel::from_id(channel_id)?;
                    trace!("accepted bi stream for logical channel {channel:?}");
                    Result::<_, anyhow::Error>::Ok((channel, Some((send, recv))))
                })
                .try_join()
                .await
        }
    }?;

    let mut take_and_spawn_channel = |channel| {
        channels
            .iter_mut()
            .find_map(|(ch, streams)| (*ch == channel).then(|| streams.take()))
            .flatten()
            .ok_or(MissingChannel(channel))
            .map(|(send_stream, recv_stream)| {
                spawn_channel(
                    join_set,
                    Channel::Logical(channel),
                    cap,
                    cap,
                    Guarantees::Limited(0),
                    send_stream,
                    recv_stream,
                )
            })
    };

    let rec = take_and_spawn_channel(LogicalChannel::Reconciliation)?;
    let stt = take_and_spawn_channel(LogicalChannel::StaticToken)?;
    let aoi = take_and_spawn_channel(LogicalChannel::AreaOfInterest)?;
    let cap = take_and_spawn_channel(LogicalChannel::Capability)?;
    Ok((
        LogicalChannelSenders {
            reconciliation: rec.0,
            static_tokens: stt.0,
            aoi: aoi.0,
            capability: cap.0,
        },
        LogicalChannelReceivers {
            reconciliation_recv: rec.1.into(),
            static_tokens_recv: stt.1.into(),
            aoi_recv: aoi.1.into(),
            capability_recv: cap.1.into(),
        },
    ))
}

fn spawn_channel(
    join_set: &mut JoinSet<anyhow::Result<()>>,
    ch: Channel,
    send_cap: usize,
    recv_cap: usize,
    guarantees: Guarantees,
    send_stream: SendStream,
    recv_stream: RecvStream,
) -> (Sender<Message>, Receiver<Message>) {
    let (sender, outbound_reader) = outbound_channel(send_cap, guarantees);
    let (inbound_writer, recveiver) = inbound_channel(recv_cap);

    let recv_fut = recv_loop(recv_stream, inbound_writer)
        .map_err(move |e| e.context(format!("receive loop for {ch:?} failed")))
        .instrument(error_span!("recv", ch=%ch.fmt_short()));

    join_set.spawn(recv_fut);

    let send_fut = send_loop(send_stream, outbound_reader)
        .map_err(move |e| e.context(format!("send loop for {ch:?} failed")))
        .instrument(error_span!("send", ch=%ch.fmt_short()));

    join_set.spawn(send_fut);

    (sender, recveiver)
}

async fn recv_loop(mut recv_stream: RecvStream, mut channel_writer: Writer) -> anyhow::Result<()> {
    let max_buffer_size = channel_writer.max_buffer_size();
    while let Some(buf) = recv_stream.read_chunk(max_buffer_size, true).await? {
        channel_writer.write_all(&buf.bytes[..]).await?;
        trace!(len = buf.bytes.len(), "recv");
    }
    channel_writer.close();
    debug!("closed");
    Ok(())
}

async fn send_loop(mut send_stream: SendStream, channel_reader: Reader) -> anyhow::Result<()> {
    while let Some(data) = channel_reader.read_bytes().await {
        let len = data.len();
        send_stream.write_chunk(data).await?;
        trace!(len, "sent");
    }
    debug!("close");
    send_stream.finish().await?;
    debug!("closed");
    Ok(())
}

async fn exchange_commitments(
    send_stream: &mut SendStream,
    recv_stream: &mut RecvStream,
) -> anyhow::Result<InitialTransmission> {
    let our_nonce: AccessChallenge = rand::random();
    let challenge_hash = Hash::new(&our_nonce);
    send_stream.write_u8(MAX_PAYLOAD_SIZE_POWER).await?;
    send_stream.write_all(challenge_hash.as_bytes()).await?;

    let their_max_payload_size = {
        let power = recv_stream.read_u8().await?;
        ensure!(power <= 64, "max payload size too large");
        2u64.pow(power as u32)
    };

    let mut received_commitment = [0u8; CHALLENGE_HASH_LENGTH];
    recv_stream.read_exact(&mut received_commitment).await?;
    Ok(InitialTransmission {
        our_nonce,
        received_commitment,
        their_max_payload_size,
    })
}

#[derive(Debug)]
pub struct InitialTransmission {
    pub our_nonce: AccessChallenge,
    pub received_commitment: ChallengeHash,
    pub their_max_payload_size: u64,
}

async fn join_all(mut join_set: JoinSet<anyhow::Result<()>>) -> anyhow::Result<()> {
    let mut final_result = Ok(());
    let mut joined = 0;
    while let Some(res) = join_set.join_next().await {
        joined += 1;
        tracing::trace!("joined {joined} tasks, remaining {}", join_set.len());
        let res = match res {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(err),
            Err(err) => Err(err.into()),
        };
        if res.is_err() && final_result.is_ok() {
            final_result = res;
        } else if res.is_err() {
            warn!("join error after initial error: {res:?}");
        }
    }
    final_result
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, time::Instant};

    use futures_lite::StreamExt;
    use futures_util::FutureExt;
    use iroh_base::key::SecretKey;
    use iroh_blobs::store::Store as PayloadStore;
    use iroh_net::MagicEndpoint;
    use rand::SeedableRng;
    use rand_core::CryptoRngCore;
    use tracing::{debug, info};

    use crate::{
        actor::ActorHandle,
        net::run,
        proto::{
            grouping::{AreaOfInterest, ThreeDRange},
            keys::{NamespaceId, NamespaceKind, NamespaceSecretKey, UserPublicKey, UserSecretKey},
            meadowcap::{AccessMode, McCapability, OwnedCapability},
            sync::ReadCapability,
            willow::{Entry, InvalidPath, Path, WriteCapability},
        },
        session::{Role, SessionInit},
        store::{MemoryKeyStore, MemoryStore},
    };

    const ALPN: &[u8] = b"iroh-willow/0";

    #[tokio::test(flavor = "multi_thread")]
    async fn smoke() -> anyhow::Result<()> {
        iroh_test::logging::setup_multithreaded();
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(1);
        let n_betty: usize = std::env::var("N_BETTY")
            .as_deref()
            .unwrap_or("1000")
            .parse()
            .unwrap();
        let n_alfie: usize = std::env::var("N_ALFIE")
            .as_deref()
            .unwrap_or("1000")
            .parse()
            .unwrap();

        let ep_alfie = MagicEndpoint::builder()
            .secret_key(SecretKey::generate_with_rng(&mut rng))
            .alpns(vec![ALPN.to_vec()])
            .bind(0)
            .await?;
        let ep_betty = MagicEndpoint::builder()
            .secret_key(SecretKey::generate_with_rng(&mut rng))
            .alpns(vec![ALPN.to_vec()])
            .bind(0)
            .await?;

        let addr_betty = ep_betty.my_addr().await?;
        let node_id_betty = ep_betty.node_id();
        let node_id_alfie = ep_alfie.node_id();

        debug!("start connect");
        let (conn_alfie, conn_betty) = tokio::join!(
            async move { ep_alfie.connect(addr_betty, ALPN).await },
            async move {
                let connecting = ep_betty.accept().await.unwrap();
                connecting.await
            }
        );
        let conn_alfie = conn_alfie.unwrap();
        let conn_betty = conn_betty.unwrap();
        info!("connected! now start reconciliation");

        let namespace_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let namespace_id: NamespaceId = namespace_secret.public_key().into();

        let start = Instant::now();
        let mut expected_entries = BTreeSet::new();

        let store_alfie = MemoryStore::default();
        let keys_alfie = MemoryKeyStore::default();
        let payloads_alfie = iroh_blobs::store::mem::Store::default();
        let handle_alfie = ActorHandle::spawn(
            store_alfie,
            keys_alfie,
            payloads_alfie.clone(),
            node_id_alfie,
        );

        let store_betty = MemoryStore::default();
        let keys_betty = MemoryKeyStore::default();
        let payloads_betty = iroh_blobs::store::mem::Store::default();
        let handle_betty = ActorHandle::spawn(
            store_betty,
            keys_betty,
            payloads_betty.clone(),
            node_id_betty,
        );

        let init_alfie = setup_and_insert(
            &mut rng,
            &handle_alfie,
            &payloads_alfie,
            &namespace_secret,
            n_alfie,
            &mut expected_entries,
            |n| Path::new(&[b"alfie", n.to_string().as_bytes()]),
        )
        .await?;
        let init_betty = setup_and_insert(
            &mut rng,
            &handle_betty,
            &payloads_betty,
            &namespace_secret,
            n_betty,
            &mut expected_entries,
            |n| Path::new(&[b"betty", n.to_string().as_bytes()]),
        )
        .await?;

        debug!("init constructed");
        println!("init took {:?}", start.elapsed());
        let start = Instant::now();

        // tokio::task::spawn({
        //     let handle_alfie = handle_alfie.clone();
        //     let handle_betty = handle_betty.clone();
        //     async move {
        //         loop {
        //             info!(
        //                 "alfie count: {}",
        //                 handle_alfie
        //                     .get_entries(namespace_id, ThreeDRange::full())
        //                     .await
        //                     .unwrap()
        //                     .count()
        //                     .await
        //             );
        //             info!(
        //                 "betty count: {}",
        //                 handle_betty
        //                     .get_entries(namespace_id, ThreeDRange::full())
        //                     .await
        //                     .unwrap()
        //                     .count()
        //                     .await
        //             );
        //             tokio::time::sleep(Duration::from_secs(1)).await;
        //         }
        //     }
        // });

        let (res_alfie, res_betty) = tokio::join!(
            run(
                node_id_alfie,
                handle_alfie.clone(),
                conn_alfie,
                Role::Alfie,
                init_alfie
            )
            .inspect(|res| info!("alfie done: {res:?}")),
            run(
                node_id_betty,
                handle_betty.clone(),
                conn_betty,
                Role::Betty,
                init_betty
            )
            .inspect(|res| info!("betty done: {res:?}")),
        );
        info!(time=?start.elapsed(), "reconciliation finished");

        info!("alfie res {:?}", res_alfie);
        info!("betty res {:?}", res_betty);
        // info!(
        //     "alfie store {:?}",
        //     get_entries_debug(&handle_alfie, namespace_id).await?
        // );
        // info!(
        //     "betty store {:?}",
        //     get_entries_debug(&handle_betty, namespace_id).await?
        // );
        assert!(res_alfie.is_ok());
        assert!(res_betty.is_ok());
        let alfie_entries = get_entries(&handle_alfie, namespace_id).await?;
        let betty_entries = get_entries(&handle_betty, namespace_id).await?;
        info!("alfie has now {} entries", alfie_entries.len());
        info!("betty has now {} entries", betty_entries.len());
        // not using assert_eq because it would print a lot in case of failure
        assert!(alfie_entries == expected_entries, "alfie expected entries");
        assert!(betty_entries == expected_entries, "betty expected entries");

        Ok(())
    }
    async fn get_entries(
        store: &ActorHandle,
        namespace: NamespaceId,
    ) -> anyhow::Result<BTreeSet<Entry>> {
        let entries: BTreeSet<_> = store
            .get_entries(namespace, ThreeDRange::full())
            .await?
            .collect::<BTreeSet<_>>()
            .await;
        Ok(entries)
    }

    async fn setup_and_insert<P: PayloadStore>(
        rng: &mut impl CryptoRngCore,
        store: &ActorHandle,
        payload_store: &P,
        namespace_secret: &NamespaceSecretKey,
        count: usize,
        track_entries: &mut impl Extend<Entry>,
        path_fn: impl Fn(usize) -> Result<Path, InvalidPath>,
    ) -> anyhow::Result<SessionInit> {
        let user_secret = UserSecretKey::generate(rng);
        let user_id_short = user_secret.id().fmt_short();
        store.insert_secret(user_secret.clone()).await?;
        let (read_cap, write_cap) = create_capabilities(namespace_secret, user_secret.public_key());
        for i in 0..count {
            let payload = format!("hi, this is entry {i} for {user_id_short}")
                .as_bytes()
                .to_vec();
            let payload_len = payload.len() as u64;
            let temp_tag = payload_store
                .import_bytes(payload.into(), iroh_base::hash::BlobFormat::Raw)
                .await?;
            let payload_digest = *temp_tag.hash();
            let path = path_fn(i).expect("invalid path");
            let entry = Entry::new_current(
                namespace_secret.id(),
                user_secret.id(),
                path,
                payload_digest,
                payload_len,
            );
            track_entries.extend([entry.clone()]);
            let entry = entry.attach_authorisation(write_cap.clone(), &user_secret)?;
            store.ingest_entry(entry).await?;
        }
        let init = SessionInit::with_interest(read_cap, AreaOfInterest::full());
        Ok(init)
    }

    fn create_capabilities(
        namespace_secret: &NamespaceSecretKey,
        user_public_key: UserPublicKey,
    ) -> (ReadCapability, WriteCapability) {
        let read_capability = McCapability::Owned(OwnedCapability::new(
            &namespace_secret,
            user_public_key,
            AccessMode::Read,
        ));
        let write_capability = McCapability::Owned(OwnedCapability::new(
            &namespace_secret,
            user_public_key,
            AccessMode::Write,
        ));
        (read_capability, write_capability)
    }

    // async fn get_entries_debug(
    //     store: &StoreHandle,
    //     namespace: NamespaceId,
    // ) -> anyhow::Result<Vec<(SubspaceId, Path)>> {
    //     let entries = get_entries(store, namespace).await?;
    //     let mut entries: Vec<_> = entries
    //         .into_iter()
    //         .map(|e| (e.subspace_id, e.path))
    //         .collect();
    //     entries.sort();
    //     Ok(entries)
    // }
}
