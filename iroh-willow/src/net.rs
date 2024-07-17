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
        AccessChallenge, Channel, InitialTransmission, LogicalChannel, Message,
        CHALLENGE_HASH_LENGTH, MAX_PAYLOAD_SIZE_POWER,
    },
    session::{
        channels::{
            ChannelReceivers, ChannelSenders, Channels, LogicalChannelReceivers,
            LogicalChannelSenders,
        },
        intents::IntentData,
        Role, SessionInit,
    },
    util::channel::{
        inbound_channel, outbound_channel, Guarantees, Reader, Receiver, Sender, Writer,
    },
};

pub const CHANNEL_CAP: usize = 1024 * 64;
pub const ALPN: &[u8] = b"iroh-willow/0";

#[instrument(skip_all, name = "willow_net", fields(me=%me.fmt_short(), peer=Empty))]
pub async fn setup(
    conn: Connection,
    me: NodeId,
    our_role: Role,
) -> anyhow::Result<(InitialTransmission, Channels, JoinSet<anyhow::Result<()>>)> {
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
    Ok((initial_transmission, channels, tasks))
}

#[instrument(skip_all, name = "willow_net", fields(me=%me.fmt_short(), peer=Empty))]
pub async fn run(
    me: NodeId,
    actor: ActorHandle,
    conn: Connection,
    our_role: Role,
    intents: Vec<IntentData>,
    // init: SessionInit,
) -> anyhow::Result<SessionHandle> {
    let peer = iroh_net::endpoint::get_remote_node_id(&conn)?;
    let (initial_transmission, channels, tasks) = setup(conn, me, our_role).await?;
    let handle = actor
        .init_session(peer, our_role, initial_transmission, channels, intents)
        .await?;

    Ok(SessionHandle { handle, tasks })
}
//
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
        debug!("trigger user close");
        self.handle.close()
    }

    /// Wait for the session to finish.
    ///
    /// Returns an error if the session failed to complete.
    pub async fn join(&mut self) -> anyhow::Result<()> {
        let session_res = self.handle.on_finish().await;
        let net_tasks_res = join_all(&mut self.tasks).await;
        match session_res {
            Err(err) => Err(err.into()),
            Ok(()) => net_tasks_res,
        }
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

    let pai = take_and_spawn_channel(LogicalChannel::Intersection)?;
    let rec = take_and_spawn_channel(LogicalChannel::Reconciliation)?;
    let stt = take_and_spawn_channel(LogicalChannel::StaticToken)?;
    let aoi = take_and_spawn_channel(LogicalChannel::AreaOfInterest)?;
    let cap = take_and_spawn_channel(LogicalChannel::Capability)?;
    let dat = take_and_spawn_channel(LogicalChannel::Data)?;

    Ok((
        LogicalChannelSenders {
            intersection: pai.0,
            reconciliation: rec.0,
            static_tokens: stt.0,
            aoi: aoi.0,
            capability: cap.0,
            data: dat.0,
        },
        LogicalChannelReceivers {
            intersection_recv: pai.1.into(),
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
        // trace!(len = buf.bytes.len(), "recv");
    }
    channel_writer.close();
    trace!("close");
    Ok(())
}

async fn send_loop(mut send_stream: SendStream, channel_reader: Reader) -> anyhow::Result<()> {
    while let Some(data) = channel_reader.read_bytes().await {
        // let len = data.len();
        send_stream.write_chunk(data).await?;
        // trace!(len, "sent");
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

pub async fn join_all(join_set: &mut JoinSet<anyhow::Result<()>>) -> anyhow::Result<()> {
    let mut final_result = Ok(());
    let mut joined = 0;
    while let Some(res) = join_set.join_next().await {
        joined += 1;
        trace!("joined {joined} tasks, remaining {}", join_set.len());
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
    use std::{
        collections::BTreeSet,
        time::{Duration, Instant},
    };

    use futures_lite::StreamExt;
    use iroh_base::key::SecretKey;
    use iroh_net::{Endpoint, NodeAddr, NodeId};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use tracing::info;

    use crate::{
        actor::ActorHandle,
        auth::{CapSelector, DelegateTo},
        form::{AuthForm, EntryForm, PayloadForm, SubspaceForm, TimestampForm},
        net::run,
        proto::{
            grouping::ThreeDRange,
            keys::{NamespaceId, NamespaceKind, UserId},
            meadowcap::AccessMode,
            willow::{Entry, InvalidPath, Path},
        },
        session::{intents::IntentHandle, Interests, Role, SessionInit, SessionMode},
    };

    const ALPN: &[u8] = b"iroh-willow/0";

    fn create_rng(seed: &str) -> ChaCha12Rng {
        let seed = iroh_base::hash::Hash::new(seed);
        rand_chacha::ChaCha12Rng::from_seed(*(seed.as_bytes()))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn net_smoke() -> anyhow::Result<()> {
        iroh_test::logging::setup_multithreaded();
        let mut rng = create_rng("net_smoke");
        let n_betty = parse_env_var("N_BETTY", 100);
        let n_alfie = parse_env_var("N_ALFIE", 100);

        let (ep_alfie, node_id_alfie, _) = create_endpoint(&mut rng).await?;
        let (ep_betty, node_id_betty, addr_betty) = create_endpoint(&mut rng).await?;

        let start = Instant::now();
        let mut expected_entries = BTreeSet::new();

        let handle_alfie = ActorHandle::spawn_memory(Default::default(), node_id_alfie);
        let handle_betty = ActorHandle::spawn_memory(Default::default(), node_id_betty);

        let user_alfie = handle_alfie.create_user().await?;
        let user_betty = handle_betty.create_user().await?;

        let namespace_id = handle_alfie
            .create_namespace(NamespaceKind::Owned, user_alfie)
            .await?;

        let cap_for_betty = handle_alfie
            .delegate_caps(
                CapSelector::widest(namespace_id),
                AccessMode::Write,
                DelegateTo::new(user_betty, None),
            )
            .await?;

        handle_betty.import_caps(cap_for_betty).await?;

        insert(
            &handle_alfie,
            namespace_id,
            user_alfie,
            n_alfie,
            |n| Path::new(&[b"alfie", n.to_string().as_bytes()]),
            |n| format!("alfie{n}"),
            &mut expected_entries,
        )
        .await?;

        insert(
            &handle_betty,
            namespace_id,
            user_betty,
            n_betty,
            |n| Path::new(&[b"betty", n.to_string().as_bytes()]),
            |n| format!("betty{n}"),
            &mut expected_entries,
        )
        .await?;

        let init_alfie = SessionInit::new(Interests::All, SessionMode::ReconcileOnce);
        let init_betty = SessionInit::new(Interests::All, SessionMode::ReconcileOnce);
        let (mut intent_alfie, intent_alfie_data) = IntentHandle::new(init_alfie);
        let (mut intent_betty, intent_betty_data) = IntentHandle::new(init_betty);

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
                vec![intent_alfie_data]
            ),
            run(
                node_id_betty,
                handle_betty.clone(),
                conn_betty,
                Role::Betty,
                vec![intent_betty_data]
            )
        );
        let mut session_alfie = session_alfie?;
        let mut session_betty = session_betty?;

        let (res_alfie, res_betty) = tokio::join!(intent_alfie.complete(), intent_betty.complete());
        info!("alfie intent res {:?}", res_alfie);
        info!("betty intent res {:?}", res_betty);
        assert!(res_alfie.is_ok());
        assert!(res_betty.is_ok());

        let (res_alfie, res_betty) = tokio::join!(session_alfie.join(), session_betty.join());
        info!("alfie session res {:?}", res_alfie);
        info!("betty session res {:?}", res_betty);
        assert!(res_alfie.is_ok());
        assert!(res_betty.is_ok());

        info!(time=?start.elapsed(), "reconciliation finished");

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
    async fn net_live_data() -> anyhow::Result<()> {
        iroh_test::logging::setup_multithreaded();
        let mut rng = create_rng("net_live_data");

        let (ep_alfie, node_id_alfie, _) = create_endpoint(&mut rng).await?;
        let (ep_betty, node_id_betty, addr_betty) = create_endpoint(&mut rng).await?;

        let handle_alfie = ActorHandle::spawn_memory(Default::default(), node_id_alfie);
        let handle_betty = ActorHandle::spawn_memory(Default::default(), node_id_betty);

        let user_alfie = handle_alfie.create_user().await?;
        let user_betty = handle_betty.create_user().await?;

        let namespace_id = handle_alfie
            .create_namespace(NamespaceKind::Owned, user_alfie)
            .await?;

        let cap_for_betty = handle_alfie
            .delegate_caps(
                CapSelector::widest(namespace_id),
                AccessMode::Write,
                DelegateTo::new(user_betty, None),
            )
            .await?;

        handle_betty.import_caps(cap_for_betty).await?;

        let mut expected_entries = BTreeSet::new();
        let start = Instant::now();

        let n_init = 2;
        insert(
            &handle_alfie,
            namespace_id,
            user_alfie,
            n_init,
            |n| Path::new(&[b"alfie-init", n.to_string().as_bytes()]),
            |n| format!("alfie{n}"),
            &mut expected_entries,
        )
        .await?;

        insert(
            &handle_betty,
            namespace_id,
            user_betty,
            n_init,
            |n| Path::new(&[b"betty-init", n.to_string().as_bytes()]),
            |n| format!("betty{n}"),
            &mut expected_entries,
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
            let handle_alfie = handle_alfie.clone();
            let count = 3;
            let content_fn = |i: usize| format!("alfie live {i}");
            let path_fn = |i: usize| Path::new(&[b"alfie-live", i.to_string().as_bytes()]);
            let mut track_entries = vec![];

            async move {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                insert(
                    &handle_alfie,
                    namespace_id,
                    user_alfie,
                    count,
                    path_fn,
                    content_fn,
                    &mut track_entries,
                )
                .await
                .expect("failed to insert");
                done_tx.send(track_entries).unwrap();
            }
        });

        let init_alfie = SessionInit::new(Interests::All, SessionMode::Live);
        let init_betty = SessionInit::new(Interests::All, SessionMode::Live);

        let (mut intent_alfie, intent_alfie_data) = IntentHandle::new(init_alfie);
        let (mut intent_betty, intent_betty_data) = IntentHandle::new(init_betty);

        let (session_alfie, session_betty) = tokio::join!(
            run(
                node_id_alfie,
                handle_alfie.clone(),
                conn_alfie,
                Role::Alfie,
                vec![intent_alfie_data]
            ),
            run(
                node_id_betty,
                handle_betty.clone(),
                conn_betty,
                Role::Betty,
                vec![intent_betty_data]
            )
        );
        let mut session_alfie = session_alfie?;
        let mut session_betty = session_betty?;

        let live_entries = done_rx.await?;
        expected_entries.extend(live_entries);
        // TODO: replace with event
        tokio::time::sleep(Duration::from_secs(1)).await;
        session_alfie.close();

        let (res_alfie, res_betty) = tokio::join!(intent_alfie.complete(), intent_betty.complete());
        info!(time=?start.elapsed(), "reconciliation finished");
        info!("alfie intent res {:?}", res_alfie);
        info!("betty intent res {:?}", res_betty);
        assert!(res_alfie.is_ok());
        assert!(res_betty.is_ok());

        let (res_alfie, res_betty) = tokio::join!(session_alfie.join(), session_betty.join());

        info!("alfie session res {:?}", res_alfie);
        info!("betty session res {:?}", res_betty);
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
        let addr = ep.node_addr().await?;
        let node_id = ep.node_id();
        Ok((ep, node_id, addr))
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

    async fn insert(
        handle: &ActorHandle,
        namespace_id: NamespaceId,
        user_id: UserId,
        count: usize,
        path_fn: impl Fn(usize) -> Result<Path, InvalidPath>,
        content_fn: impl Fn(usize) -> String,
        track_entries: &mut impl Extend<Entry>,
    ) -> anyhow::Result<()> {
        for i in 0..count {
            let payload = content_fn(i).as_bytes().to_vec();
            let path = path_fn(i).expect("invalid path");
            let entry = EntryForm {
                namespace_id,
                subspace_id: SubspaceForm::User,
                path,
                timestamp: TimestampForm::Now,
                payload: PayloadForm::Bytes(payload.into()),
            };
            let (entry, inserted) = handle.insert(entry, AuthForm::Any(user_id)).await?;
            assert!(inserted);
            track_entries.extend([entry]);
        }
        Ok(())
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
