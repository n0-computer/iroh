use std::future::Future;

use anyhow::{anyhow, ensure, Context as _, Result};
use futures_concurrency::future::TryJoin;
use futures_util::future::TryFutureExt;
use iroh_base::key::NodeId;
use iroh_net::endpoint::{Connection, ConnectionError, RecvStream, SendStream, VarInt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, trace};

use crate::{
    proto::sync::{
        AccessChallenge, ChallengeHash, Channel, InitialTransmission, LogicalChannel, Message,
        CHALLENGE_HASH_LENGTH, MAX_PAYLOAD_SIZE_POWER,
    },
    session::{
        channels::{
            ChannelReceivers, ChannelSenders, Channels, LogicalChannelReceivers,
            LogicalChannelSenders,
        },
        Role,
    },
    util::channel::{
        inbound_channel, outbound_channel, Guarantees, Reader, Receiver, Sender, Writer,
    },
};

pub const CHANNEL_CAP: usize = 1024 * 64;

/// The ALPN protocol name for iroh-willow.
pub const ALPN: &[u8] = b"iroh-willow/0";

/// QUIC application error code for graceful connection termination.
pub const ERROR_CODE_OK: VarInt = VarInt::from_u32(1);

/// QUIC application error code for closing connections because another connection is preferred.
pub const ERROR_CODE_DUPLICATE_CONN: VarInt = VarInt::from_u32(2);

/// QUIC application error code when closing connection because our node is shutting down.
pub const ERROR_CODE_SHUTDOWN: VarInt = VarInt::from_u32(3);

/// The handle to an active peer connection.
///
/// This is passed into the session loop, where it is used to send and receive messages
/// on the control and logical channels. It also contains the data of the initial transmission.
#[derive(derive_more::Debug)]
pub(crate) struct ConnHandle {
    pub(crate) our_role: Role,
    pub(crate) peer: NodeId,
    #[debug("InitialTransmission")]
    pub(crate) initial_transmission: InitialTransmission,
    #[debug("Channels")]
    pub(crate) channels: Channels,
}

/// Establish the connection by running the initial transmission and
/// opening the streams for the control and logical channels.
///
/// The initial transmission is transferred over a pair of uni streams.
/// All channels for the actual WGPS are bi streams.
/// Returns the initial transmission and [`ChannelStreams], which is an
/// array of send and receive streams, one for each WGPS channel.
///
/// To start the networking loops that pipe the QUIC streams into our
/// internal channel streams use [`prepare_channels`].
pub(crate) async fn establish(
    conn: &Connection,
    our_role: Role,
    our_nonce: AccessChallenge,
) -> Result<(InitialTransmission, ChannelStreams)> {
    debug!(?our_role, "establishing connection");
    // Run the initial transmission (which works on uni streams) concurrently
    // with opening/accepting the bi streams for the channels.
    (
        initial_transmission(conn, our_nonce),
        open_channel_streams(conn, our_role),
    )
        .try_join()
        .await
}

async fn initial_transmission(
    conn: &Connection,
    our_nonce: AccessChallenge,
) -> Result<InitialTransmission> {
    let challenge_hash = our_nonce.hash();
    let mut send_stream = conn.open_uni().await?;
    send_stream.write_u8(MAX_PAYLOAD_SIZE_POWER).await?;
    send_stream.write_all(challenge_hash.as_bytes()).await?;

    let mut recv_stream = conn.accept_uni().await?;

    let their_max_payload_size = {
        let power = recv_stream.read_u8().await?;
        ensure!(power <= 64, "max payload size too large");
        2u64.pow(power as u32)
    };

    let mut received_commitment = [0u8; CHALLENGE_HASH_LENGTH];
    recv_stream.read_exact(&mut received_commitment).await?;
    debug!("initial transmission complete");
    Ok(InitialTransmission {
        our_nonce,
        received_commitment: ChallengeHash::from_bytes(received_commitment),
        their_max_payload_size,
    })
}

#[derive(Debug, thiserror::Error)]
#[error("missing channel: {0:?}")]
struct MissingChannel(Channel);

pub(crate) type ChannelStreams = [(Channel, SendStream, RecvStream); Channel::COUNT];

async fn open_channel_streams(conn: &Connection, our_role: Role) -> Result<ChannelStreams> {
    let channels = match our_role {
        // Alfie opens a quic stream for each logical channel, and sends a single byte with the
        // channel id.
        Role::Alfie => {
            Channel::all()
                .map(|ch| {
                    let conn = conn.clone();
                    async move {
                        let (mut send, recv) = conn.open_bi().await?;
                        send.write_u8(ch.id()).await?;
                        trace!(?ch, "opened bi stream");
                        Ok::<_, anyhow::Error>((ch, send, recv))
                    }
                })
                .try_join()
                .await
        }
        // Betty accepts as many quick streams as there are logical channels, and reads a single
        // byte on each, which is expected to contain a channel id.
        Role::Betty => {
            Channel::all()
                .map(|_| async {
                    let (send, mut recv) = conn.accept_bi().await?;
                    // trace!("accepted bi stream");
                    let channel_id = recv.read_u8().await?;
                    // trace!("read channel id {channel_id}");
                    let channel = Channel::from_id(channel_id)?;
                    trace!(?channel, "accepted bi stream for channel");
                    Result::Ok((channel, send, recv))
                })
                .try_join()
                .await
        }
    }?;
    Ok(channels)
}

/// Create a future for each WGPS channel that pipes between the QUIC channels and the
/// [`Sender`] and [`Receiver`] for each channel to be used in the session.
///
/// Returns [`Channels`], which contains all senders and receivers, and a future that drives
/// the send and receive loops for all channels combined.
pub(crate) fn prepare_channels(
    channels: ChannelStreams,
) -> Result<(Channels, impl Future<Output = Result<()>> + Send)> {
    let mut channels = channels.map(|(ch, send, recv)| (ch, Some(prepare_channel(ch, send, recv))));

    let mut find = |channel| {
        channels
            .iter_mut()
            .find_map(|(ch, streams)| (*ch == channel).then(|| streams.take()))
            .flatten()
            .ok_or(MissingChannel(channel))
    };

    let ctrl = find(Channel::Control)?;
    let pai = find(Channel::Logical(LogicalChannel::Intersection))?;
    let rec = find(Channel::Logical(LogicalChannel::Reconciliation))?;
    let stt = find(Channel::Logical(LogicalChannel::StaticToken))?;
    let aoi = find(Channel::Logical(LogicalChannel::AreaOfInterest))?;
    let cap = find(Channel::Logical(LogicalChannel::Capability))?;
    let dat = find(Channel::Logical(LogicalChannel::Data))?;

    let fut = (ctrl.2, pai.2, rec.2, stt.2, aoi.2, cap.2, dat.2)
        .try_join()
        .map_ok(|_| ());

    let logical_send = LogicalChannelSenders {
        intersection_send: pai.0,
        reconciliation_send: rec.0,
        static_tokens_send: stt.0,
        aoi_send: aoi.0,
        capability_send: cap.0,
        data_send: dat.0,
    };
    let logical_recv = LogicalChannelReceivers {
        intersection_recv: pai.1.into(),
        reconciliation_recv: rec.1.into(),
        static_tokens_recv: stt.1.into(),
        aoi_recv: aoi.1.into(),
        capability_recv: cap.1.into(),
        data_recv: dat.1.into(),
    };
    let channels = Channels {
        send: ChannelSenders {
            control_send: ctrl.0,
            logical_send,
        },
        recv: ChannelReceivers {
            control_recv: ctrl.1,
            logical_recv,
        },
    };
    Ok((channels, fut))
}

fn prepare_channel(
    ch: Channel,
    send_stream: SendStream,
    recv_stream: RecvStream,
) -> (
    Sender<Message>,
    Receiver<Message>,
    impl Future<Output = Result<()>> + Send,
) {
    let guarantees = match ch {
        Channel::Control => Guarantees::Unlimited,
        Channel::Logical(_) => Guarantees::Limited(0),
    };
    let cap = CHANNEL_CAP;
    let (sender, outbound_reader) = outbound_channel(cap, guarantees);
    let (inbound_writer, receiver) = inbound_channel(cap);

    let recv_fut = recv_loop(recv_stream, inbound_writer)
        .map_err(move |e| e.context(format!("receive loop for {ch:?} failed")));

    let send_fut = send_loop(send_stream, outbound_reader)
        .map_err(move |e| e.context(format!("send loop for {ch:?} failed")));

    let fut = (recv_fut, send_fut).try_join().map_ok(|_| ());

    (sender, receiver, fut)
}

async fn recv_loop(mut recv_stream: RecvStream, mut channel_writer: Writer) -> Result<()> {
    trace!("recv: start");
    let max_buffer_size = channel_writer.max_buffer_size();
    while let Some(buf) = recv_stream
        .read_chunk(max_buffer_size, true)
        .await
        .context("failed to read from quic stream")?
    {
        // trace!(len = buf.bytes.len(), "read");
        channel_writer.write_all(&buf.bytes[..]).await?;
        // trace!(len = buf.bytes.len(), "sent");
    }
    trace!("recv: stream close");
    channel_writer.close();
    trace!("recv: loop close");
    Ok(())
}

async fn send_loop(mut send_stream: SendStream, channel_reader: Reader) -> Result<()> {
    trace!("send: start");
    while let Some(data) = channel_reader.read_bytes().await {
        // let len = data.len();
        // trace!(len, "send");
        send_stream
            .write_chunk(data)
            .await
            .context("failed to write to quic stream")?;
        // trace!(len, "sent");
    }
    trace!("send: close writer");
    send_stream.finish().await?;
    trace!("send: done");
    Ok(())
}

/// Terminate a connection gracefully.
///
/// QUIC does not allow us to rely on stream terminations, because those only signal
/// reception in the peer's QUIC stack, not in the application. Closing a QUIC connection
/// triggers immediate termination, so to make sure that all data was actually processed
/// by our session, we exchange a single byte over a pair of uni streams. As this is the only
/// use of uni streams after the initial connection handshake, we do not have to identify the
/// streams specifically.
///
/// This function may only be called once the session processing has fully terminated and all
/// WGPS streams are closed (for send streams) and read to end (for recv streams) on our side.
///
/// `we_cancelled` is a boolean indicating whether we are terminating the connection after
/// we willfully terminated or completed our session. Pass `false` if the session terminated
/// because the other peer closed their WGPS streams.
///
/// If only one peer indicated that they initiated the termination by setting `we_cancelled`
/// to `true`, this peer will *not* close the connection, but instead wait for the other peer
/// to close the connection.
/// If both peers indicated that they initiated the termination, the peer with the higher node id
/// will close the connection first.
/// If none of the peers said they closed, which likely is a bug in the implementation, both peers
/// will close the connection.
///
/// A connection is considered to be closed gracefully if and only if this procedure is run to end
/// successfully, and if the connection is closed with the expected error code.
///
/// Returns an error if the termination flow was aborted prematurely.
/// Returns a  [`ConnectionError] if the termination flow was completed successfully, but the connection
/// was not closed with the expected error code.
pub(crate) async fn terminate_gracefully(
    conn: &Connection,
    me: NodeId,
    peer: NodeId,
    we_cancelled: bool,
) -> Result<Option<ConnectionError>> {
    trace!(?we_cancelled, "terminating connection");
    let send = async {
        let mut send_stream = conn.open_uni().await?;
        let data = if we_cancelled { 1u8 } else { 0u8 };
        send_stream.write_u8(data).await?;
        send_stream.finish().await?;
        Ok(())
    };

    let recv = async {
        let mut recv_stream = conn.accept_uni().await?;
        let data = recv_stream.read_u8().await?;
        recv_stream.read_to_end(0).await?;
        let they_cancelled = match data {
            0 => false,
            1 => true,
            _ => return Err(anyhow!("received unexpected closing byte from peer")),
        };
        Ok(they_cancelled)
    };

    let (_, they_cancelled) = (send, recv).try_join().await?;

    #[derive(Debug)]
    enum WhoCancelled {
        WeDid,
        TheyDid,
        BothDid,
        NoneDid,
    }

    let who_cancelled = match (we_cancelled, they_cancelled) {
        (true, false) => WhoCancelled::WeDid,
        (false, true) => WhoCancelled::TheyDid,
        (true, true) => WhoCancelled::BothDid,
        (false, false) => WhoCancelled::NoneDid,
    };

    let we_close_first = match who_cancelled {
        WhoCancelled::WeDid => false,
        WhoCancelled::TheyDid => true,
        WhoCancelled::BothDid => me > peer,
        WhoCancelled::NoneDid => true,
    };
    debug!(?who_cancelled, "connection complete");
    if we_close_first {
        conn.close(ERROR_CODE_OK, b"bye");
    }
    let reason = conn.closed().await;
    let is_graceful = match &reason {
        ConnectionError::LocallyClosed if we_close_first => true,
        ConnectionError::ApplicationClosed(frame) if frame.error_code == ERROR_CODE_OK => {
            !we_close_first || matches!(who_cancelled, WhoCancelled::NoneDid)
        }
        _ => false,
    };
    if !is_graceful {
        Ok(Some(reason))
    } else {
        Ok(None)
    }
}

/// This test module contains two integration tests for the net and session run module.
///
/// They were written before the peer_manager module existed, and thus are quite verbose.
/// Still going to keep them around for now as a safe guard.
#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        time::{Duration, Instant},
    };

    use anyhow::Result;
    use futures_lite::StreamExt;
    use iroh_base::key::SecretKey;
    use iroh_net::{endpoint::Connection, Endpoint, NodeAddr, NodeId};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use tracing::{info, Instrument};

    use crate::{
        auth::{CapSelector, DelegateTo, RestrictArea},
        engine::ActorHandle,
        form::{AuthForm, EntryForm, PayloadForm, SubspaceForm, TimestampForm},
        net::{terminate_gracefully, ConnHandle},
        proto::{
            grouping::ThreeDRange,
            keys::{NamespaceId, NamespaceKind, UserId},
            meadowcap::AccessMode,
            sync::AccessChallenge,
            willow::{Entry, InvalidPath, Path},
        },
        session::{intents::Intent, Interests, Role, SessionHandle, SessionInit, SessionMode},
    };

    use super::{establish, prepare_channels};

    const ALPN: &[u8] = b"iroh-willow/0";

    fn create_rng(seed: &str) -> ChaCha12Rng {
        let seed = iroh_base::hash::Hash::new(seed);
        rand_chacha::ChaCha12Rng::from_seed(*(seed.as_bytes()))
    }

    pub async fn run(
        me: NodeId,
        actor: ActorHandle,
        conn: Connection,
        our_role: Role,
        our_nonce: AccessChallenge,
        intents: Vec<Intent>,
    ) -> Result<(SessionHandle, tokio::task::JoinHandle<Result<()>>)> {
        let peer = iroh_net::endpoint::get_remote_node_id(&conn)?;
        let span = tracing::error_span!("conn", me=%me.fmt_short(), peer=%peer.fmt_short());
        let (initial_transmission, channel_streams) = establish(&conn, our_role, our_nonce)
            .instrument(span.clone())
            .await?;
        let (channels, fut) = prepare_channels(channel_streams)?;
        let net_task = tokio::task::spawn(fut.instrument(span));
        let willow_conn = ConnHandle {
            initial_transmission,
            our_role,
            peer,
            channels,
        };
        let handle = actor.init_session(willow_conn, intents).await?;
        Ok((handle, net_task))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn net_smoke() -> Result<()> {
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
                AccessMode::ReadWrite,
                DelegateTo::new(user_betty, RestrictArea::None),
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
        let (intent_alfie, mut intent_handle_alfie) = Intent::new(init_alfie);
        let (intent_betty, mut intent_handle_betty) = Intent::new(init_betty);

        info!("init took {:?}", start.elapsed());

        let start = Instant::now();
        let (conn_alfie, conn_betty) = tokio::join!(
            async move { ep_alfie.connect(addr_betty, ALPN).await.unwrap() },
            async move { ep_betty.accept().await.unwrap().await.unwrap() }
        );
        info!("connecting took {:?}", start.elapsed());

        let start = Instant::now();
        let nonce_alfie = AccessChallenge::generate_with_rng(&mut rng);
        let nonce_betty = AccessChallenge::generate_with_rng(&mut rng);
        let (session_alfie, session_betty) = tokio::join!(
            run(
                node_id_alfie,
                handle_alfie.clone(),
                conn_alfie.clone(),
                Role::Alfie,
                nonce_alfie,
                vec![intent_alfie]
            ),
            run(
                node_id_betty,
                handle_betty.clone(),
                conn_betty.clone(),
                Role::Betty,
                nonce_betty,
                vec![intent_betty]
            )
        );
        let (mut session_alfie, net_task_alfie) = session_alfie?;
        let (mut session_betty, net_task_betty) = session_betty?;

        let (res_alfie, res_betty) = tokio::join!(
            intent_handle_alfie.complete(),
            intent_handle_betty.complete()
        );
        info!("alfie intent res {:?}", res_alfie);
        info!("betty intent res {:?}", res_betty);
        assert!(res_alfie.is_ok());
        assert!(res_betty.is_ok());

        let (res_alfie, res_betty) =
            tokio::join!(session_alfie.complete(), session_betty.complete());
        info!("alfie session res {:?}", res_alfie);
        info!("betty session res {:?}", res_betty);

        info!(time=?start.elapsed(), "reconciliation finished");

        let (senders_alfie, alfie_cancelled) = res_alfie.unwrap();
        let (senders_betty, betty_cancelled) = res_betty.unwrap();
        senders_alfie.close_all();
        senders_betty.close_all();

        let (r1, r2) = tokio::try_join!(net_task_alfie, net_task_betty)
            .expect("failed to close connection loops");
        r1.unwrap();
        r2.unwrap();

        let (error_alfie, error_betty) = tokio::try_join!(
            terminate_gracefully(&conn_alfie, node_id_alfie, node_id_betty, alfie_cancelled),
            terminate_gracefully(&conn_betty, node_id_betty, node_id_alfie, betty_cancelled),
        )
        .expect("failed to close both connections gracefully");
        assert_eq!(error_alfie, None);
        assert_eq!(error_betty, None);

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
    async fn net_live_data() -> Result<()> {
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
                AccessMode::ReadWrite,
                DelegateTo::new(user_betty, RestrictArea::None),
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

        let (intent_alfie, mut intent_handle_alfie) = Intent::new(init_alfie);
        let (intent_betty, mut intent_handle_betty) = Intent::new(init_betty);

        let nonce_alfie = AccessChallenge::generate_with_rng(&mut rng);
        let nonce_betty = AccessChallenge::generate_with_rng(&mut rng);

        let (session_alfie, session_betty) = tokio::join!(
            run(
                node_id_alfie,
                handle_alfie.clone(),
                conn_alfie.clone(),
                Role::Alfie,
                nonce_alfie,
                vec![intent_alfie]
            ),
            run(
                node_id_betty,
                handle_betty.clone(),
                conn_betty.clone(),
                Role::Betty,
                nonce_betty,
                vec![intent_betty]
            )
        );
        let (mut session_alfie, net_task_alfie) = session_alfie?;
        let (mut session_betty, net_task_betty) = session_betty?;

        let live_entries = done_rx.await?;
        expected_entries.extend(live_entries);
        // TODO: replace with event
        tokio::time::sleep(Duration::from_secs(1)).await;

        session_alfie.close();
        let (senders_alfie, alfie_cancelled) = session_alfie
            .complete()
            .await
            .expect("failed to close alfie session");
        info!("close alfie session");
        senders_alfie.close_all();

        let (senders_betty, betty_cancelled) = session_betty
            .complete()
            .await
            .expect("failed to close alfie session");
        senders_betty.close_all();

        let (r1, r2) = tokio::try_join!(net_task_alfie, net_task_betty)
            .expect("failed to close connection loops");
        r1.unwrap();
        r2.unwrap();

        let (res_alfie, res_betty) = tokio::join!(
            intent_handle_alfie.complete(),
            intent_handle_betty.complete()
        );
        info!(time=?start.elapsed(), "reconciliation finished");
        info!("alfie intent res {:?}", res_alfie);
        info!("betty intent res {:?}", res_betty);
        assert!(res_alfie.is_ok());
        assert!(res_betty.is_ok());

        let (error_alfie, error_betty) = tokio::try_join!(
            terminate_gracefully(&conn_alfie, node_id_alfie, node_id_betty, alfie_cancelled),
            terminate_gracefully(&conn_betty, node_id_betty, node_id_alfie, betty_cancelled),
        )
        .expect("failed to close both connections gracefully");
        assert_eq!(error_alfie, None);
        assert_eq!(error_betty, None);

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
    ) -> Result<(Endpoint, NodeId, NodeAddr)> {
        let ep = Endpoint::builder()
            .secret_key(SecretKey::generate_with_rng(rng))
            .alpns(vec![ALPN.to_vec()])
            .bind(0)
            .await?;
        let addr = ep.node_addr().await?;
        let node_id = ep.node_id();
        Ok((ep, node_id, addr))
    }

    async fn get_entries(store: &ActorHandle, namespace: NamespaceId) -> Result<BTreeSet<Entry>> {
        let entries: Result<BTreeSet<_>> = store
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
    ) -> Result<()> {
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
}
