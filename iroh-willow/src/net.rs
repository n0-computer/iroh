//! Networking implementation for iroh-willow.

use std::{future::Future, io, time::Duration};

use anyhow::{anyhow, ensure, Context as _, Result};
use futures_concurrency::future::TryJoin;
use futures_util::future::TryFutureExt;
use iroh_base::key::NodeId;
use iroh_net::endpoint::{
    Connection, ConnectionError, ReadError, ReadExactError, RecvStream, SendStream, VarInt,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, trace};

use crate::{
    proto::wgps::{
        AccessChallenge, ChallengeHash, Channel, LogicalChannel, Message, CHALLENGE_HASH_LENGTH,
        MAX_PAYLOAD_SIZE_POWER,
    },
    session::{
        channels::{
            ChannelReceivers, ChannelSenders, Channels, LogicalChannelReceivers,
            LogicalChannelSenders,
        },
        InitialTransmission, Role,
    },
    util::channel::{
        inbound_channel, outbound_channel, Guarantees, Reader, Receiver, Sender, Writer,
    },
};

/// Default capacity for the in-memory pipes between networking and session.
const CHANNEL_CAP: usize = 1024 * 64;

/// The ALPN protocol name for iroh-willow.
pub const ALPN: &[u8] = b"iroh-willow/0";

/// QUIC application error code for closing with failure.
pub const ERROR_CODE_FAIL: VarInt = VarInt::from_u32(1);

/// QUIC application error code for graceful connection termination.
pub const ERROR_CODE_OK: VarInt = VarInt::from_u32(2);

/// QUIC application error code for closing connections because another connection is preferred.
pub const ERROR_CODE_DUPLICATE_CONN: VarInt = VarInt::from_u32(3);

/// QUIC application error code when closing connection because our node is shutting down.
pub const ERROR_CODE_SHUTDOWN: VarInt = VarInt::from_u32(4);

/// Timeout until we abort a connection attempt.
const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout until we abort a graceful termination attempt.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

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
    // Run the initial transmission (which uses uni streams) concurrently
    // with opening/accepting the bi streams for the channels.
    let fut = (
        initial_transmission(conn, our_nonce),
        open_channel_streams(conn, our_role),
    )
        .try_join();
    tokio::time::timeout(ESTABLISH_TIMEOUT, fut).await?
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
                .map(|channel| {
                    let conn = conn.clone();
                    async move {
                        let (mut send, recv) = conn.open_bi().await?;
                        send.write_u8(channel.id()).await?;
                        trace!(?channel, "opened bi stream");
                        Ok::<_, anyhow::Error>((channel, send, recv))
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
                    trace!(?channel, "accepted bi stream");
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

    let fut = async move {
        let result = (ctrl.2, pai.2, rec.2, stt.2, aoi.2, cap.2, dat.2)
            .try_join()
            .map_ok(|_| ())
            .await;
        if let Err(err) = &result {
            debug!("channels closed with error: {err:#}");
        } else {
            debug!("channels closed");
        }
        result
    };

    let channels = Channels {
        send: ChannelSenders {
            control_send: ctrl.0,
            logical_send: LogicalChannelSenders {
                intersection_send: pai.0,
                reconciliation_send: rec.0,
                static_tokens_send: stt.0,
                aoi_send: aoi.0,
                capability_send: cap.0,
                data_send: dat.0,
            },
        },
        recv: ChannelReceivers {
            control_recv: ctrl.1,
            logical_recv: LogicalChannelReceivers {
                intersection_recv: pai.1.into(),
                reconciliation_recv: rec.1.into(),
                static_tokens_recv: stt.1.into(),
                aoi_recv: aoi.1.into(),
                capability_recv: cap.1.into(),
                data_recv: dat.1.into(),
            },
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

    let recv_fut = recv_loop(ch, recv_stream, inbound_writer)
        .map_err(move |e| e.context(format!("receive loop for {ch:?} failed")));

    let send_fut = send_loop(ch, send_stream, outbound_reader)
        .map_err(move |e| e.context(format!("send loop for {ch:?} failed")));

    let fut = (recv_fut, send_fut).try_join().map_ok(|_| ());

    (sender, receiver, fut)
}

/// Error code when stopping receive streams because we closed our session.
///
/// This is currently for debugging purposes only - the other end will still see this as a connection error.
const ERROR_CODE_SESSION_CLOSED: VarInt = VarInt::from_u32(1);

async fn recv_loop(
    channel: Channel,
    mut recv_stream: RecvStream,
    mut channel_writer: Writer,
) -> Result<()> {
    trace!(?channel, "recv: start");
    let max_buffer_size = channel_writer.max_buffer_size();
    while let Some(buf) = recv_stream
        .read_chunk(max_buffer_size, true)
        .await
        .context("failed to read from quic stream")?
    {
        trace!(len = buf.bytes.len(), "read");
        match channel_writer.write_all(&buf.bytes[..]).await {
            Ok(()) => {
                trace!(len = buf.bytes.len(), "sent");
            }
            Err(err) if err.kind() == io::ErrorKind::BrokenPipe => {
                debug!("closing recv channel: session closed");
                recv_stream.stop(ERROR_CODE_SESSION_CLOSED)?;
                break;
            }
            Err(err) => return Err(err.into()),
        }
    }
    trace!(?channel, "recv: stream close");
    channel_writer.close();
    Ok(())
}

async fn send_loop(
    channel: Channel,
    mut send_stream: SendStream,
    channel_reader: Reader,
) -> Result<()> {
    trace!(?channel, "send: start");
    while let Some(data) = channel_reader.read_bytes().await {
        // let len = data.len();
        // trace!(len, "send");
        send_stream
            .write_chunk(data)
            .await
            .context("failed to write to quic stream")?;
        // trace!(len, "sent");
    }
    trace!(?channel, "send: close writer");
    send_stream.finish()?;
    send_stream.stopped().await?;
    // We don't await SendStream::stopped, because we rely on application level closing notifications,
    // and make sure that the connection is closed gracefully in any case.
    trace!(?channel, "send: done");
    Ok(())
}

/// Terminates a connection gracefully.
///
/// This function should be called after all bidirectional streams are terminated (`finish` called
/// for send streams and `read_to_end` awaited for recv stream) and no further streams will be
/// opened or accepted by the application.
///
/// It will send a goodbye byte over a newly opened uni channel, and wait for the other peer to
/// confirm either by sending a goodbye byte as well or closing the connection with
/// [`ERROR_CODE_OK`], signalling that our goodbye byte was received.
///
/// We will only close the connection after having received the goodbye byte, or after the other
/// peer closed the connection.
///
/// This flow guarantees that neither peer will close the connection too early.
///
/// A connection is considered to be closed gracefully if and only if this procedure is run to end
/// successfully, and if the connection is closed with the expected error code.
///
/// Returns an error if the termination flow was aborted prematurely or if the connection was not
/// closed with the expected error code.
pub(crate) async fn terminate_gracefully(conn: Connection) -> Result<()> {
    trace!("terminating connection");
    // Send a single byte on a newly opened uni stream.
    let mut send_stream = conn.open_uni().await?;
    send_stream.write_u8(1).await?;
    send_stream.finish()?;
    // Wait until we either receive the goodbye byte from the other peer, or for the other peer
    // to close the connection with the expected error code.
    match tokio::time::timeout(SHUTDOWN_TIMEOUT, wait_for_goodbye_or_graceful_close(&conn)).await {
        Ok(Ok(())) => {
            conn.close(ERROR_CODE_OK, b"bye");
            trace!("connection terminated gracefully");
            Ok(())
        }
        Ok(Err(err)) => {
            conn.close(ERROR_CODE_FAIL, b"failed-while-closing");
            trace!(?err, "connection failed while terminating");
            Err(err)
        }
        Err(err) => {
            conn.close(ERROR_CODE_FAIL, b"timeout-while-closing");
            trace!("connection timed out while terminating");
            Err(err.into())
        }
    }
}

/// Waits for a goodbye byte or connection close, and then closes the connection.
///
/// Accepts a single uni stream and reads a single byte on it.
///
/// Returns once we received the goodbye byte or if the peer closed the connection with the
/// graceful error code.
///
/// Returns an error if the connection was closed without the graceful error code or if reading the
/// goodbye byte failed.
async fn wait_for_goodbye_or_graceful_close(conn: &Connection) -> Result<()> {
    let mut recv_stream = match conn.accept_uni().await {
        // The other peer closed the connection with the expected error code: They received our
        // goodbye byte after having sent theirs. We're free to close the connection.
        Err(ConnectionError::ApplicationClosed(frame)) if frame.error_code == ERROR_CODE_OK => {
            return Ok(())
        }
        // The peer closed the connection with an unexpected error coe.
        Err(err) => return Err(err.into()),
        Ok(stream) => stream,
    };
    let mut buf = [0u8];
    match recv_stream.read_exact(&mut buf).await {
        // We received the goodbye byte: the other peer indicates to us that they are finished with
        // everything and we are free to close the connection.
        Ok(()) if buf == [1u8] => Ok(()),
        // The other peer closed the connection with the expected error code: They received our
        // goodbye byte, and reacted by closing the connection. We're free to close too.
        Err(ReadExactError::ReadError(ReadError::ConnectionLost(
            ConnectionError::ApplicationClosed(frame),
        ))) if frame.error_code == ERROR_CODE_OK => Ok(()),
        // The peer has sent invalid data on the goodbye stream.
        Ok(()) => Err(anyhow!("Received unexpected closing byte from peer.")),
        // The peer closed the connection with an unexpected error coe.
        Err(err) => Err(err.into()),
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
        sync::Arc,
        time::{Duration, Instant},
    };

    use anyhow::Result;
    use futures_lite::StreamExt;
    use iroh_base::key::SecretKey;
    use iroh_net::{endpoint::Connection, Endpoint, NodeAddr, NodeId};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use tracing::{info, Instrument};

    use super::{establish, prepare_channels};
    use crate::{
        engine::ActorHandle,
        form::{AuthForm, EntryForm, PayloadForm, SubspaceForm, TimestampForm},
        interest::{CapSelector, DelegateTo, Interests, RestrictArea},
        net::{terminate_gracefully, ConnHandle},
        proto::{
            data_model::{Entry, InvalidPathError2, Path, PathExt},
            grouping::Range3d,
            keys::{NamespaceId, NamespaceKind, UserId},
            meadowcap::AccessMode,
            wgps::AccessChallenge,
        },
        session::{intents::Intent, Role, SessionHandle, SessionInit, SessionMode},
    };

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
        let conn_handle = ConnHandle {
            initial_transmission,
            our_role,
            peer,
            channels,
        };
        let session_handle = actor.init_session(conn_handle, intents).await?;
        Ok((session_handle, net_task))
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
                CapSelector::any(namespace_id),
                AccessMode::Write,
                DelegateTo::new(user_betty, RestrictArea::None),
            )
            .await?;

        handle_betty.import_caps(cap_for_betty).await?;

        insert(
            &handle_alfie,
            namespace_id,
            user_alfie,
            n_alfie,
            |n| Path::from_bytes(&[b"alfie", n.to_string().as_bytes()]),
            |n| format!("alfie{n}"),
            &mut expected_entries,
        )
        .await?;

        insert(
            &handle_betty,
            namespace_id,
            user_betty,
            n_betty,
            |n| Path::from_bytes(&[b"betty", n.to_string().as_bytes()]),
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

        let (senders_alfie, _alfie_cancelled) = res_alfie.unwrap();
        let (senders_betty, _betty_cancelled) = res_betty.unwrap();
        senders_alfie.close_all();
        senders_betty.close_all();

        let (r1, r2) = tokio::try_join!(net_task_alfie, net_task_betty)
            .expect("failed to close connection loops");
        r1.unwrap();
        r2.unwrap();

        tokio::try_join!(
            terminate_gracefully(conn_alfie),
            terminate_gracefully(conn_betty),
        )
        .expect("failed to close both connections gracefully");

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
                CapSelector::any(namespace_id),
                AccessMode::Write,
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
            |n| Path::from_bytes(&[b"alfie-init", n.to_string().as_bytes()]),
            |n| format!("alfie{n}"),
            &mut expected_entries,
        )
        .await?;

        insert(
            &handle_betty,
            namespace_id,
            user_betty,
            n_init,
            |n| Path::from_bytes(&[b"betty-init", n.to_string().as_bytes()]),
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

        // alfie insert 3 entries after waiting a second
        let _insert_task_alfie = tokio::task::spawn({
            let handle_alfie = handle_alfie.clone();
            let count = 3;
            let content_fn = |i: usize| format!("alfie live {i}");
            let path_fn = |i: usize| Path::from_bytes(&[b"alfie-live", i.to_string().as_bytes()]);
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

        let init_alfie = SessionInit::new(Interests::All, SessionMode::Continuous);
        let init_betty = SessionInit::new(Interests::All, SessionMode::Continuous);

        let (intent_alfie, intent_handle_alfie) = Intent::new(init_alfie);
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

        // Drop the alfie intent, which closes the session.
        drop(intent_handle_alfie);

        let (senders_alfie, _alfie_cancelled) = session_alfie
            .complete()
            .await
            .expect("failed to close alfie session");
        info!("close alfie session");
        senders_alfie.close_all();

        let (senders_betty, _betty_cancelled) = session_betty
            .complete()
            .await
            .expect("failed to close alfie session");
        senders_betty.close_all();

        let (r1, r2) = tokio::try_join!(net_task_alfie, net_task_betty)
            .expect("failed to close connection loops");
        r1.unwrap();
        r2.unwrap();

        let res_betty = intent_handle_betty.complete().await;
        info!(time=?start.elapsed(), "finished");
        info!("betty intent res {:?}", res_betty);
        assert!(res_betty.is_err());
        assert_eq!(
            res_betty,
            Err(Arc::new(crate::session::Error::SessionClosedByPeer))
        );

        tokio::try_join!(
            terminate_gracefully(conn_alfie),
            terminate_gracefully(conn_betty),
        )
        .expect("failed to close both connections gracefully");

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
            .relay_mode(iroh_net::RelayMode::Disabled)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await?;
        let addr = ep.node_addr().await?;
        let node_id = ep.node_id();
        Ok((ep, node_id, addr))
    }

    async fn get_entries(store: &ActorHandle, namespace: NamespaceId) -> Result<BTreeSet<Entry>> {
        let entries: Result<BTreeSet<_>> = store
            .get_entries(namespace, Range3d::new_full())
            .await?
            .map(|entry| entry.map(|entry| entry.into_parts().0))
            .try_collect()
            .await;
        entries
    }

    async fn insert(
        handle: &ActorHandle,
        namespace_id: NamespaceId,
        user_id: UserId,
        count: usize,
        path_fn: impl Fn(usize) -> Result<Path, InvalidPathError2>,
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
            let (entry, inserted) = handle.insert_entry(entry, AuthForm::Any(user_id)).await?;
            assert!(inserted);
            track_entries.extend([entry.into_parts().0]);
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
