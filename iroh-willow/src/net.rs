use anyhow::ensure;
use futures_concurrency::future::TryJoin;
use futures_util::future::TryFutureExt;
use iroh_base::{hash::Hash, key::NodeId};
use iroh_net::endpoint::{Connection, RecvStream, SendStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
};
use tracing::{debug, error_span, field::Empty, instrument, trace, warn, Instrument, Span};

use crate::{
    actor::{self, ActorHandle},
    proto::sync::{
        AccessChallenge, Channel, LogicalChannel, Message, CHALLENGE_HASH_LENGTH,
        MAX_PAYLOAD_SIZE_POWER,
    },
    session::{
        channels::{
            ChannelReceivers, ChannelSenders, Channels, LogicalChannelReceivers,
            LogicalChannelSenders,
        },
        InitialTransmission, Role, SessionInit,
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
) -> anyhow::Result<SessionHandle> {
    let peer = iroh_net::endpoint::get_remote_node_id(&conn)?;
    Span::current().record("peer", tracing::field::display(peer.fmt_short()));
    debug!(?our_role, "connected");

    let mut tasks = JoinSet::new();

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
        &mut tasks,
        Channel::Control,
        CHANNEL_CAP,
        CHANNEL_CAP,
        Guarantees::Unlimited,
        control_send_stream,
        control_recv_stream,
    );

    let (logical_send, logical_recv) = open_logical_channels(&mut tasks, conn, our_role).await?;
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

    Ok(SessionHandle { handle, tasks })
}

#[derive(Debug)]
pub struct SessionHandle {
    handle: actor::SessionHandle,
    tasks: JoinSet<anyhow::Result<()>>,
}

impl SessionHandle {
    /// Close the session gracefully.
    ///
    /// After calling this, no further protocol messages will be sent from this node.
    /// Previously queued messages will still be sent out. The session will only be closed
    /// once the other peer closes their senders as well.
    pub fn close(&self) {
        self.handle.close()
    }

    /// Wait for the session to finish.
    ///
    /// Returns an error if the session failed to complete.
    pub async fn join(&mut self) -> anyhow::Result<()> {
        let session_res = self.handle.on_finish().await;
        let net_tasks_res = join_all(&mut self.tasks).await;
        session_res.or(net_tasks_res)
    }
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
            .ok_or(MissingChannel(channel))
    };

    let rec = take_and_spawn_channel(LogicalChannel::Reconciliation)?;
    let stt = take_and_spawn_channel(LogicalChannel::StaticToken)?;
    let aoi = take_and_spawn_channel(LogicalChannel::AreaOfInterest)?;
    let cap = take_and_spawn_channel(LogicalChannel::Capability)?;
    let dat = take_and_spawn_channel(LogicalChannel::Data)?;

    Ok((
        LogicalChannelSenders {
            reconciliation: rec.0,
            static_tokens: stt.0,
            aoi: aoi.0,
            capability: cap.0,
            data: dat.0,
        },
        LogicalChannelReceivers {
            reconciliation_recv: rec.1.into(),
            static_tokens_recv: stt.1.into(),
            aoi_recv: aoi.1.into(),
            capability_recv: cap.1.into(),
            data_recv: dat.1.into(),
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
    let (inbound_writer, receiver) = inbound_channel(recv_cap);

    let recv_fut = recv_loop(recv_stream, inbound_writer)
        .map_err(move |e| e.context(format!("receive loop for {ch:?} failed")))
        .instrument(error_span!("recv", ch=%ch.fmt_short()));

    join_set.spawn(recv_fut);

    let send_fut = send_loop(send_stream, outbound_reader)
        .map_err(move |e| e.context(format!("send loop for {ch:?} failed")))
        .instrument(error_span!("send", ch=%ch.fmt_short()));

    join_set.spawn(send_fut);

    (sender, receiver)
}

async fn recv_loop(mut recv_stream: RecvStream, mut channel_writer: Writer) -> anyhow::Result<()> {
    let max_buffer_size = channel_writer.max_buffer_size();
    while let Some(buf) = recv_stream.read_chunk(max_buffer_size, true).await? {
        channel_writer.write_all(&buf.bytes[..]).await?;
        trace!(len = buf.bytes.len(), "recv");
    }
    channel_writer.close();
    trace!("close");
    Ok(())
}

async fn send_loop(mut send_stream: SendStream, channel_reader: Reader) -> anyhow::Result<()> {
    while let Some(data) = channel_reader.read_bytes().await {
        let len = data.len();
        send_stream.write_chunk(data).await?;
        trace!(len, "sent");
    }
    send_stream.finish().await?;
    trace!("close");
    Ok(())
}

async fn exchange_commitments(
    send_stream: &mut SendStream,
    recv_stream: &mut RecvStream,
) -> anyhow::Result<InitialTransmission> {
    let our_nonce: AccessChallenge = rand::random();
    let challenge_hash = Hash::new(our_nonce);
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

async fn join_all(join_set: &mut JoinSet<anyhow::Result<()>>) -> anyhow::Result<()> {
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
    use iroh_base::key::SecretKey;
    use iroh_blobs::store::Store as PayloadStore;
    use iroh_net::{Endpoint, NodeAddr, NodeId};
    use rand::SeedableRng;
    use rand_core::CryptoRngCore;
    use tracing::info;

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
        session::{Role, SessionInit, SessionMode},
        store::memory,
    };

    const ALPN: &[u8] = b"iroh-willow/0";

    #[tokio::test(flavor = "multi_thread")]
    async fn smoke() -> anyhow::Result<()> {
        iroh_test::logging::setup_multithreaded();
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(1);
        let n_betty = parse_env_var("N_BETTY", 100);
        let n_alfie = parse_env_var("N_ALFIE", 100);

        let (ep_alfie, node_id_alfie, _) = create_endpoint(&mut rng).await?;
        let (ep_betty, node_id_betty, addr_betty) = create_endpoint(&mut rng).await?;

        let namespace_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let namespace_id = namespace_secret.id();

        let start = Instant::now();
        let mut expected_entries = BTreeSet::new();

        let (handle_alfie, payloads_alfie) = create_willow(node_id_alfie);
        let (handle_betty, payloads_betty) = create_willow(node_id_betty);

        let (init_alfie, _) = setup_and_insert(
            SessionMode::ReconcileOnce,
            &mut rng,
            &handle_alfie,
            &payloads_alfie,
            &namespace_secret,
            n_alfie,
            &mut expected_entries,
            |n| Path::new(&[b"alfie", n.to_string().as_bytes()]),
        )
        .await?;
        let (init_betty, _) = setup_and_insert(
            SessionMode::ReconcileOnce,
            &mut rng,
            &handle_betty,
            &payloads_betty,
            &namespace_secret,
            n_betty,
            &mut expected_entries,
            |n| Path::new(&[b"betty", n.to_string().as_bytes()]),
        )
        .await?;
        info!("init took {:?}", start.elapsed());

        let start = Instant::now();
        let (conn_alfie, conn_betty) = tokio::join!(
            async move { ep_alfie.connect(addr_betty, ALPN).await.unwrap() },
            async move { ep_betty.accept().await.unwrap().await.unwrap() }
        );
        info!("connecting took {:?}", start.elapsed());

        let start = Instant::now();
        let (session_alfie, session_betty) = tokio::join!(
            run(
                node_id_alfie,
                handle_alfie.clone(),
                conn_alfie,
                Role::Alfie,
                init_alfie
            ),
            run(
                node_id_betty,
                handle_betty.clone(),
                conn_betty,
                Role::Betty,
                init_betty
            )
        );
        let mut session_alfie = session_alfie?;
        let mut session_betty = session_betty?;
        let (res_alfie, res_betty) = tokio::join!(session_alfie.join(), session_betty.join());
        info!(time=?start.elapsed(), "reconciliation finished");

        info!("alfie res {:?}", res_alfie);
        info!("betty res {:?}", res_betty);
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

    #[tokio::test(flavor = "multi_thread")]
    async fn live_data() -> anyhow::Result<()> {
        iroh_test::logging::setup_multithreaded();
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(1);

        let (ep_alfie, node_id_alfie, _) = create_endpoint(&mut rng).await?;
        let (ep_betty, node_id_betty, addr_betty) = create_endpoint(&mut rng).await?;

        let namespace_secret = NamespaceSecretKey::generate(&mut rng, NamespaceKind::Owned);
        let namespace_id = namespace_secret.id();

        let start = Instant::now();
        let mut expected_entries = BTreeSet::new();

        let (handle_alfie, payloads_alfie) = create_willow(node_id_alfie);
        let (handle_betty, payloads_betty) = create_willow(node_id_betty);

        let (init_alfie, cap_alfie) = setup_and_insert(
            SessionMode::Live,
            &mut rng,
            &handle_alfie,
            &payloads_alfie,
            &namespace_secret,
            2,
            &mut expected_entries,
            |n| Path::new(&[b"alfie", n.to_string().as_bytes()]),
        )
        .await?;
        let (init_betty, _cap_betty) = setup_and_insert(
            SessionMode::Live,
            &mut rng,
            &handle_betty,
            &payloads_betty,
            &namespace_secret,
            2,
            &mut expected_entries,
            |n| Path::new(&[b"betty", n.to_string().as_bytes()]),
        )
        .await?;

        info!("init took {:?}", start.elapsed());

        let start = Instant::now();
        let (conn_alfie, conn_betty) = tokio::join!(
            async move { ep_alfie.connect(addr_betty, ALPN).await.unwrap() },
            async move { ep_betty.accept().await.unwrap().await.unwrap() }
        );
        info!("connecting took {:?}", start.elapsed());

        let start = Instant::now();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();

        // alfie insert 3 enries after waiting a second
        let _insert_task_alfie = tokio::task::spawn({
            let store = handle_alfie.clone();
            let payload_store = payloads_alfie.clone();
            let count = 3;
            let content_fn = |i: usize| format!("alfie live insert {i} for alfie");
            let path_fn = |i: usize| Path::new(&[b"alfie-live", i.to_string().as_bytes()]);
            let mut track_entries = vec![];

            async move {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                insert(
                    &store,
                    &payload_store,
                    namespace_id,
                    cap_alfie,
                    count,
                    content_fn,
                    path_fn,
                    &mut track_entries,
                )
                .await
                .expect("failed to insert");
                done_tx.send(track_entries).unwrap();
            }
        });

        let (session_alfie, session_betty) = tokio::join!(
            run(
                node_id_alfie,
                handle_alfie.clone(),
                conn_alfie,
                Role::Alfie,
                init_alfie
            ),
            run(
                node_id_betty,
                handle_betty.clone(),
                conn_betty,
                Role::Betty,
                init_betty
            )
        );
        let mut session_alfie = session_alfie?;
        let mut session_betty = session_betty?;

        let live_entries = done_rx.await?;
        expected_entries.extend(live_entries);
        session_alfie.close();

        let (res_alfie, res_betty) = tokio::join!(session_alfie.join(), session_betty.join());
        info!(time=?start.elapsed(), "reconciliation finished");

        info!("alfie res {:?}", res_alfie);
        info!("betty res {:?}", res_betty);
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

    pub async fn create_endpoint(
        rng: &mut rand_chacha::ChaCha12Rng,
    ) -> anyhow::Result<(Endpoint, NodeId, NodeAddr)> {
        let ep = Endpoint::builder()
            .secret_key(SecretKey::generate_with_rng(rng))
            .alpns(vec![ALPN.to_vec()])
            .bind(0)
            .await?;
        let addr = ep.my_addr().await?;
        let node_id = ep.node_id();
        Ok((ep, node_id, addr))
    }

    pub fn create_willow(me: NodeId) -> (ActorHandle, iroh_blobs::store::mem::Store) {
        let payloads = iroh_blobs::store::mem::Store::default();
        let payloads_clone = payloads.clone();
        let handle = ActorHandle::spawn(move || memory::Store::new(payloads_clone), me);
        (handle, payloads)
    }

    async fn get_entries(
        store: &ActorHandle,
        namespace: NamespaceId,
    ) -> anyhow::Result<BTreeSet<Entry>> {
        let entries: anyhow::Result<BTreeSet<_>> = store
            .get_entries(namespace, ThreeDRange::full())
            .await?
            .try_collect()
            .await;
        entries
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert<P: PayloadStore>(
        actor: &ActorHandle,
        payload_store: &P,
        namespace_id: NamespaceId,
        write_cap: WriteCapability,
        count: usize,
        content_fn: impl Fn(usize) -> String,
        path_fn: impl Fn(usize) -> Result<Path, InvalidPath>,
        track_entries: &mut impl Extend<Entry>,
    ) -> anyhow::Result<()> {
        for i in 0..count {
            let payload = content_fn(i).as_bytes().to_vec();
            let payload_len = payload.len() as u64;
            let temp_tag = payload_store
                .import_bytes(payload.into(), iroh_base::hash::BlobFormat::Raw)
                .await?;
            let payload_digest = *temp_tag.hash();
            let path = path_fn(i).expect("invalid path");
            let entry = Entry::new_current(
                namespace_id,
                write_cap.receiver().id(),
                path,
                payload_digest,
                payload_len,
            );
            track_entries.extend([entry.clone()]);
            actor.insert_entry(entry, write_cap.clone()).await?;
            drop(temp_tag);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn setup_and_insert<P: PayloadStore>(
        mode: SessionMode,
        rng: &mut impl CryptoRngCore,
        store: &ActorHandle,
        payload_store: &P,
        namespace_secret: &NamespaceSecretKey,
        count: usize,
        track_entries: &mut impl Extend<Entry>,
        path_fn: impl Fn(usize) -> Result<Path, InvalidPath>,
    ) -> anyhow::Result<(SessionInit, WriteCapability)> {
        let (read_cap, write_cap) = setup_capabilities(rng, store, namespace_secret).await?;
        let content_fn = |i| {
            format!(
                "initial entry {i} for {}",
                write_cap.receiver().id().fmt_short()
            )
        };
        insert(
            store,
            payload_store,
            namespace_secret.id(),
            write_cap.clone(),
            count,
            content_fn,
            path_fn,
            track_entries,
        )
        .await?;
        let init = SessionInit::with_interest(mode, read_cap, AreaOfInterest::full());
        Ok((init, write_cap))
    }

    async fn setup_capabilities(
        rng: &mut impl CryptoRngCore,
        store: &ActorHandle,
        namespace_secret: &NamespaceSecretKey,
    ) -> anyhow::Result<(ReadCapability, WriteCapability)> {
        let user_secret = UserSecretKey::generate(rng);
        let user_public_key = user_secret.public_key();
        store.insert_secret(user_secret.clone()).await?;
        let (read_cap, write_cap) = create_capabilities(namespace_secret, user_public_key);
        Ok((read_cap, write_cap))
    }

    fn create_capabilities(
        namespace_secret: &NamespaceSecretKey,
        user_public_key: UserPublicKey,
    ) -> (ReadCapability, WriteCapability) {
        let read_capability = McCapability::Owned(OwnedCapability::new(
            namespace_secret,
            user_public_key,
            AccessMode::Read,
        ));
        let write_capability = McCapability::Owned(OwnedCapability::new(
            namespace_secret,
            user_public_key,
            AccessMode::Write,
        ));
        (read_capability, write_capability)
    }

    fn parse_env_var<T>(var: &str, default: T) -> T
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Debug,
    {
        match std::env::var(var).as_deref() {
            Ok(val) => val
                .parse()
                .unwrap_or_else(|_| panic!("failed to parse environment variable {var}")),
            Err(_) => default,
        }
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
    //
    //
    //
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
}
