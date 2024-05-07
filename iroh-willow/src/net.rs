use std::{pin::Pin, sync::Arc, task::Poll};

use anyhow::{anyhow, ensure, Context};
use futures::{FutureExt, SinkExt, Stream, TryFutureExt};
use iroh_base::{hash::Hash, key::NodeId};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
};
// use tokio_stream::StreamExt;
// use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error_span, info, instrument, Instrument, Span};

use crate::{
    proto::wgps::{
        AccessChallenge, ChallengeHash, LogicalChannel, Message, CHALLENGE_HASH_LENGTH,
        MAX_PAYLOAD_SIZE_POWER,
    },
    session::{
        coroutine::{Channels, Yield},
        Role, Session, SessionInit,
    },
    store::actor::{Interest, Notifier, StoreHandle, ToActor},
    util::{
        channel::{channel, Receiver, Sender},
        Decoder, Encoder,
    },
};

use self::codec::WillowCodec;

pub mod codec;

// /// Read the next frame from a [`FramedRead`] but only if it is available without waiting on IO.
// async fn next_if_ready<T: tokio::io::AsyncRead + Unpin, D: Decoder>(
//     mut reader: &mut FramedRead<T, D>,
// ) -> Option<Result<D::Item, D::Error>> {
//     futures::future::poll_fn(|cx| match Pin::new(&mut reader).poll_next(cx) {
//         Poll::Ready(r) => Poll::Ready(r),
//         Poll::Pending => Poll::Ready(None),
//     })
//     .await
// }

// #[instrument(skip_all, fields(me=%me.fmt_short(), role=?our_role, peer=%peer.fmt_short()))]
#[instrument(skip_all, fields(me=%me.fmt_short(), role=?our_role))]
pub async fn run(
    me: NodeId,
    store: StoreHandle,
    conn: quinn::Connection,
    peer: NodeId,
    our_role: Role,
    init: SessionInit,
) -> anyhow::Result<()> {
    let (mut control_send_stream, mut control_recv_stream) = match our_role {
        Role::Alfie => conn.open_bi().await?,
        Role::Betty => conn.accept_bi().await?,
    };
    control_send_stream.set_priority(i32::MAX)?;

    let our_nonce: AccessChallenge = rand::random();
    debug!("start");
    let (received_commitment, max_payload_size) = exchange_commitments(
        &mut control_send_stream,
        &mut control_recv_stream,
        &our_nonce,
    )
    .await?;
    debug!("exchanged comittments");

    let (mut reconciliation_send_stream, mut reconciliation_recv_stream) = match our_role {
        Role::Alfie => conn.open_bi().await?,
        Role::Betty => conn.accept_bi().await?,
    };
    reconciliation_send_stream.write_u8(0u8).await?;
    reconciliation_recv_stream.read_u8().await?;
    debug!("reconcile channel open");

    let mut join_set = JoinSet::new();
    let (control_send, control_recv) = spawn_channel(
        &mut join_set,
        &store,
        peer,
        LogicalChannel::Control,
        1024,
        control_send_stream,
        control_recv_stream,
    );
    let (reconciliation_send, reconciliation_recv) = spawn_channel(
        &mut join_set,
        &store,
        peer,
        LogicalChannel::Reconciliation,
        1024,
        reconciliation_send_stream,
        reconciliation_recv_stream,
    );

    let channels = Channels {
        control_send,
        control_recv,
        reconciliation_send,
        reconciliation_recv,
    };

    let mut session = Session::new(
        peer,
        our_role,
        our_nonce,
        max_payload_size,
        received_commitment,
        init,
        channels.clone(),
        store.clone(),
    );

    let on_complete = session.notify_complete();
    let session_fut = async move { session.run_control().await };

    let notified_fut = async move {
        on_complete.notified().await;
        tracing::info!("reconciliation complete");
        channels.close_send();
        Ok(())
    };
    join_set.spawn(session_fut.map_err(anyhow::Error::from));
    join_set.spawn(notified_fut);
    while let Some(res) = join_set.join_next().await {
        res??;
    }
    Ok(())
}

fn spawn_channel(
    join_set: &mut JoinSet<anyhow::Result<()>>,
    store: &StoreHandle,
    peer: NodeId,
    ch: LogicalChannel,
    cap: usize,
    send_stream: quinn::SendStream,
    recv_stream: quinn::RecvStream,
) -> (Sender<Message>, Receiver<Message>) {
    let (send_tx, send_rx) = channel(cap);
    let (recv_tx, recv_rx) = channel(cap);

    let recv_fut = recv_loop(
        recv_stream,
        recv_tx,
        store.notifier(peer, Yield::ChannelPending(ch, Interest::Recv)),
    )
    .instrument(error_span!("recv", peer=%peer.fmt_short(), ch=%ch.fmt_short()));

    join_set.spawn(recv_fut);

    let send_fut = send_loop(
        send_stream,
        send_rx,
        store.notifier(peer, Yield::ChannelPending(ch, Interest::Send)),
    )
    .instrument(error_span!("send", peer=%peer.fmt_short(), ch=%ch.fmt_short()));

    join_set.spawn(send_fut);

    (send_tx, recv_rx)
}

// #[instrument(skip_all, fields(ch=%notifier.channel().fmt_short()))]
async fn recv_loop<T: Encoder>(
    mut recv_stream: quinn::RecvStream,
    channel_sender: Sender<T>,
    notifier: Notifier,
) -> anyhow::Result<()> {
    loop {
        let buf = recv_stream.read_chunk(1024 * 16, true).await?;
        if let Some(buf) = buf {
            channel_sender.write_slice_async(&buf.bytes[..]).await;
            debug!(len = buf.bytes.len(), "recv");
            if channel_sender.is_receivable_notify_set() {
                debug!("notify");
                notifier.notify().await?;
            }
        } else {
            break;
        }
    }
    channel_sender.close();
    debug!("recv_loop close");
    Ok(())
}

// #[instrument(skip_all, fields(ch=%notifier.channel().fmt_short()))]
async fn send_loop<T: Decoder>(
    mut send_stream: quinn::SendStream,
    channel_receiver: Receiver<T>,
    notifier: Notifier,
) -> anyhow::Result<()> {
    while let Some(data) = channel_receiver.read_bytes_async().await {
        let len = data.len();
        send_stream.write_chunk(data).await?;
        debug!(len, "sent");
        if channel_receiver.is_sendable_notify_set() {
            debug!("notify");
            notifier.notify().await?;
        }
    }
    send_stream.finish().await?;
    debug!("send_loop close");
    Ok(())
}

async fn exchange_commitments(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    our_nonce: &AccessChallenge,
) -> anyhow::Result<(ChallengeHash, usize)> {
    let challenge_hash = Hash::new(&our_nonce);
    send.write_u8(MAX_PAYLOAD_SIZE_POWER).await?;
    send.write_all(challenge_hash.as_bytes()).await?;

    let their_max_payload_size = {
        let power = recv.read_u8().await?;
        ensure!(power <= 64, "max payload size too large");
        2usize.pow(power as u32)
    };

    let mut received_commitment = [0u8; CHALLENGE_HASH_LENGTH];
    recv.read_exact(&mut received_commitment).await?;
    Ok((received_commitment, their_max_payload_size))
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, time::Instant};

    use futures::StreamExt;
    use iroh_base::{hash::Hash, key::SecretKey};
    use iroh_net::MagicEndpoint;
    use rand::SeedableRng;
    use tracing::{debug, info};

    use crate::{
        net::run,
        proto::{
            grouping::{AreaOfInterest, ThreeDRange},
            keys::{NamespaceId, NamespaceKind, NamespaceSecretKey, UserSecretKey},
            meadowcap::{AccessMode, McCapability, OwnedCapability},
            willow::{Entry, Path, SubspaceId},
        },
        session::{Role, SessionInit},
        store::{
            actor::{StoreHandle, ToActor},
            MemoryStore, Store,
        },
    };

    const ALPN: &[u8] = b"iroh-willow/0";

    #[tokio::test]
    async fn smoke() -> anyhow::Result<()> {
        iroh_test::logging::setup_multithreaded();
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(1);
        let n_betty = 1;
        let n_alfie = 2;

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
        let mut expected_entries = HashSet::new();
        let mut store_alfie = MemoryStore::default();
        let init_alfie = {
            let secret_key = UserSecretKey::generate(&mut rng);
            let public_key = secret_key.public_key();
            let read_capability = McCapability::Owned(OwnedCapability::new(
                &namespace_secret,
                public_key,
                AccessMode::Read,
            ));
            let write_capability = McCapability::Owned(OwnedCapability::new(
                &namespace_secret,
                public_key,
                AccessMode::Write,
            ));
            for i in 0..n_alfie {
                let p = format!("alfie{i}");
                let entry = Entry {
                    namespace_id,
                    subspace_id: public_key.into(),
                    path: Path::new(&[p.as_bytes()])?,
                    timestamp: 10,
                    payload_length: 2,
                    payload_digest: Hash::new("cool things"),
                };
                expected_entries.insert(entry.clone());
                let entry = entry.attach_authorisation(write_capability.clone(), &secret_key)?;
                store_alfie.ingest_entry(&entry)?;
            }
            let area_of_interest = AreaOfInterest::full();
            SessionInit {
                user_secret_key: secret_key,
                capability: read_capability,
                area_of_interest,
            }
        };

        let mut store_betty = MemoryStore::default();
        let init_betty = {
            let secret_key = UserSecretKey::generate(&mut rng);
            let public_key = secret_key.public_key();
            let read_capability = McCapability::Owned(OwnedCapability::new(
                &namespace_secret,
                public_key,
                AccessMode::Read,
            ));
            let write_capability = McCapability::Owned(OwnedCapability::new(
                &namespace_secret,
                public_key,
                AccessMode::Write,
            ));
            for i in 0..n_betty {
                let p = format!("betty{i}");
                let entry = Entry {
                    namespace_id,
                    subspace_id: public_key.into(),
                    path: Path::new(&[p.as_bytes()])?,
                    timestamp: 10,
                    payload_length: 2,
                    payload_digest: Hash::new("cool things"),
                };
                expected_entries.insert(entry.clone());
                let entry = entry.attach_authorisation(write_capability.clone(), &secret_key)?;
                store_betty.ingest_entry(&entry)?;
            }
            let area_of_interest = AreaOfInterest::full();
            SessionInit {
                user_secret_key: secret_key,
                capability: read_capability,
                area_of_interest,
            }
        };

        debug!("init constructed");

        let handle_alfie = StoreHandle::spawn(store_alfie, node_id_alfie);
        let handle_betty = StoreHandle::spawn(store_betty, node_id_betty);
        let (res_alfie, res_betty) = tokio::join!(
            run(
                node_id_alfie,
                handle_alfie.clone(),
                conn_alfie,
                node_id_betty,
                Role::Alfie,
                init_alfie
            ),
            run(
                node_id_betty,
                handle_betty.clone(),
                conn_betty,
                node_id_alfie,
                Role::Betty,
                init_betty
            ),
        );
        info!(time=?start.elapsed(), "reconciliation finished!");

        info!("alfie res {:?}", res_alfie);
        info!("betty res {:?}", res_betty);
        info!(
            "alfie store {:?}",
            get_entries_debug(&handle_alfie, namespace_id).await?
        );
        info!(
            "betty store {:?}",
            get_entries_debug(&handle_betty, namespace_id).await?
        );

        assert!(res_alfie.is_ok());
        assert!(res_betty.is_ok());
        assert_eq!(
            get_entries(&handle_alfie, namespace_id).await?,
            expected_entries
        );
        assert_eq!(
            get_entries(&handle_betty, namespace_id).await?,
            expected_entries
        );

        Ok(())
    }
    async fn get_entries(
        store: &StoreHandle,
        namespace: NamespaceId,
    ) -> anyhow::Result<HashSet<Entry>> {
        let (tx, rx) = flume::bounded(1024);
        store
            .send(ToActor::GetEntries {
                namespace,
                reply: tx,
            })
            .await?;
        let entries: HashSet<_> = rx.into_stream().collect::<HashSet<_>>().await;
        Ok(entries)
    }

    async fn get_entries_debug(
        store: &StoreHandle,
        namespace: NamespaceId,
    ) -> anyhow::Result<Vec<(SubspaceId, Path)>> {
        let entries = get_entries(store, namespace).await?;
        let mut entries: Vec<_> = entries
            .into_iter()
            .map(|e| (e.subspace_id, e.path))
            .collect();
        entries.sort();
        Ok(entries)
    }
}

// let mut join_set = JoinSet::new();
// join_set.spawn(
//     session_fut
//         .map(|r| ("session", r.map_err(|e| anyhow::Error::from(e))))
//         .instrument(Span::current()),
// );
// join_set.spawn(
//     control_recv_fut
//         .map(|r| ("control_recv", r))
//         .instrument(Span::current()),
// );
// join_set.spawn(
//     reconciliation_recv_fut
//         .map(|r| ("reconciliation_recv", r))
//         .instrument(Span::current()),
// );
// join_set.spawn(
//     control_send_fut
//         .map(|r| ("control_send", r))
//         .instrument(Span::current()),
// );
// join_set.spawn(
//     reconciliation_send_fut
//         .map(|r| ("reconciliation_send", r))
//         .instrument(Span::current()),
// );
//
// let finish_tasks_fut = async {
//     let mut failed: Option<anyhow::Error> = None;
//     while let Some(res) = join_set.join_next().await {
//         match res {
//             Ok((label, Err(err))) => {
//                 debug!(?err, "task {label} failed");
//                 if failed.is_none() {
//                     failed = Some(err);
//                     join_set.abort_all();
//                 }
//             }
//             Ok((label, Ok(()))) => {
//                 debug!("task {label} finished");
//             }
//             Err(err) if err.is_cancelled() => {
//                 debug!("task cancelled");
//             }
//             Err(err) => {
//                 debug!(?err, "task failed");
//                 if failed.is_none() {
//                     failed = Some(err.into());
//                     join_set.abort_all();
//                 }
//             }
//         }
//     }
//     match failed {
//         None => Ok(()),
//         Some(err) => Err(err),
//     }
// };
//         tracing::info!("COMPLETE");
//         channels.close_send();
//         completed = true;
//     }

// let channel_futs = [control_send_fut, reconciliation_send_fut, control_recv_fut, reconciliation_recv_fut];
// let channel_futs = tokio::join!(control_send_ft);
//
// let channel_fut = async move {
//     tokio::join!(
//         session_fut,
//         control_send_fut,
//         reconciliation_send_fut,
//         control_recv_fut,
//         reconciliation_recv_fut
//     )
// };
// tokio::pin!(channel_fut);
// let channel_fut = async move {
//     let
//     // res = &mut session_fut => res.context("session")?,
//     // res = &mut control_recv_fut => res.context("control_recv")?,
//     // res = &mut control_send_fut => res.context("control_send")?,
//     // res = &mut reconciliation_recv_fut => res.context("reconciliation_recv")?,
//     // res = &mut reconciliation_send_fut => res.context("reconciliation_send")?,
// }
// tokio::pin!(channel_fut);
// let mut completed = false;
// tokio::select! {
//     biased;
//     _ = on_complete.notified() => {
//         tracing::info!("COMPLETE");
//         channels.close_send();
//         completed = true;
//     }
//     // res = &mut channel_fut => {
//     //     res.0?;
//     //     res.1?;
//     //     res.2?;
//     //     res.3?;
//     //     res.4?;
//     // }
//     res = &mut session_fut => res.context("session")?,
//     res = &mut control_recv_fut => res.context("control_recv")?,
//     res = &mut control_send_fut => res.context("control_send")?,
//     res = &mut reconciliation_recv_fut => res.context("reconciliation_recv")?,
//     res = &mut reconciliation_send_fut => res.context("reconciliation_send")?,
// }
// tracing::info!(?completed, "!CLOSED!");
// if completed {
//     let res = tokio::join!(
//         session_fut,
//         control_send_fut,
//         reconciliation_send_fut,
//         control_recv_fut,
//         reconciliation_recv_fut
//     );
//     // let res = channel_fut.await;
//     res.0?;
//     res.1?;
//     res.2?;
//     res.3?;
//     res.4?;
//
//     // control_send_fut.await?;
//     // info!("control_send down");
//     // reconciliation_send_fut.await?;
//     // info!("reconciliation_send down");
//     //
//     // session_fut.await?;
//     // info!("session down");
//     //
//     // control_recv_fut.await?;
//     // info!("control_recv down");
//     // reconciliation_recv_fut.await?;
//     // info!("reconciliation_recv down");
//     // control_send.finish().await?;
//     Ok(())
// } else {
//     Err(anyhow!(
//         "All tasks finished but reconciliation did not complete"
//     ))
// }
// tokio::pin!(finish_tasks_fut);
// let res = tokio::select! {
//     res = &mut finish_tasks_fut => {
//         match res {
//             // we completed before on_complete was triggered: no success
//             Ok(()) => Err(anyhow!("all tasks finished but reconciliation was not completed")),
//             Err(err) => Err(err),
//         }
//     }
//     _ = on_complete.notified()=> {
//             // finish_tasks_fut.abort();
//             // join_set.abort_all();
//             Ok(())
//     }
// };
// res
// tokio::pin!(session_fut);
// tokio::pin!(control_send_fut);
// tokio::pin!(reconciliation_send_fut);
// tokio::pin!(control_recv_fut);
// tokio::pin!(reconciliation_recv_fut);
// tokio::pin!(notified_fut);
// let res = tokio::join!(
//     session_fut,
//     control_send_fut,
//     reconciliation_send_fut,
//     control_recv_fut,
//     reconciliation_recv_fut,
//     notified_fut
// );
// tracing::warn!("RES {res:?}");
// Ok(())
