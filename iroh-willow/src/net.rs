use std::{pin::Pin, sync::Arc, task::Poll};

use anyhow::{anyhow, ensure, Context};
use futures::{FutureExt, SinkExt, Stream};
use iroh_base::{hash::Hash, key::NodeId};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
};
// use tokio_stream::StreamExt;
// use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, instrument, Instrument, Span};

use crate::{
    proto::wgps::{
        AccessChallenge, ChallengeHash, LogicalChannel, CHALLENGE_HASH_LENGTH,
        MAX_PAYLOAD_SIZE_POWER,
    },
    session::{coroutine::Channels, Role, Session, SessionInit},
    store::actor::{
        Interest, Notifier, StoreHandle,
        ToActor::{self, ResumeRecv},
    },
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
    let (mut control_send, mut control_recv) = match our_role {
        Role::Alfie => conn.open_bi().await?,
        Role::Betty => conn.accept_bi().await?,
    };

    let our_nonce: AccessChallenge = rand::random();
    debug!("start");
    let (received_commitment, max_payload_size) =
        exchange_commitments(&mut control_send, &mut control_recv, &our_nonce).await?;
    debug!("exchanged comittments");

    let (mut reconciliation_send, mut reconciliation_recv) = match our_role {
        Role::Alfie => conn.open_bi().await?,
        Role::Betty => conn.accept_bi().await?,
    };
    reconciliation_send.write_u8(0u8).await?;
    reconciliation_recv.read_u8().await?;
    debug!("reconcile channel open");

    let (reconciliation_send_tx, reconciliation_send_rx) = channel(1024);
    let (reconciliation_recv_tx, reconciliation_recv_rx) = channel(1024);
    let (control_send_tx, control_send_rx) = channel(1024);
    let (control_recv_tx, control_recv_rx) = channel(1024);
    let channels = Channels {
        control_send: control_send_tx,
        control_recv: control_recv_rx,
        reconciliation_send: reconciliation_send_tx,
        reconciliation_recv: reconciliation_recv_rx,
    };

    let session = Session::new(
        peer,
        our_role,
        our_nonce,
        max_payload_size,
        received_commitment,
        init,
        channels.clone(),
        store.clone(),
    );

    let res = {
        let on_complete = session.notify_complete();

        let session_fut = session.run_control();

        let control_recv_fut = recv_loop(
            &mut control_recv,
            control_recv_tx,
            store.notifier(LogicalChannel::Control, Interest::Recv, peer),
        );
        let reconciliation_recv_fut = recv_loop(
            &mut reconciliation_recv,
            reconciliation_recv_tx,
            store.notifier(LogicalChannel::Reconciliation, Interest::Recv, peer),
        );
        let control_send_fut = send_loop(
            &mut control_send,
            control_send_rx,
            store.notifier(LogicalChannel::Control, Interest::Send, peer),
        );
        let reconciliation_send_fut = send_loop(
            &mut reconciliation_send,
            reconciliation_send_rx,
            store.notifier(LogicalChannel::Reconciliation, Interest::Send, peer),
        );
        tokio::pin!(session_fut);
        tokio::pin!(control_send_fut);
        tokio::pin!(reconciliation_send_fut);
        tokio::pin!(control_recv_fut);
        tokio::pin!(reconciliation_recv_fut);

        // let finish_tasks_fut = async {
        //     Result::<_, anyhow::Error>::Ok(())
        // };
        //
        // finish_tasks_fut.await?;
        // Ok(())
        let mut completed = false;
        tokio::select! {
            biased;
            _ = on_complete.notified() => {
                tracing::warn!("COMPLETE");
                channels.close_send();
                completed = true;
            }
            res = &mut session_fut => res.context("session")?,
            res = &mut control_recv_fut => res.context("control_recv")?,
            res = &mut control_send_fut => res.context("control_send")?,
            res = &mut reconciliation_recv_fut => res.context("reconciliation_recv")?,
            res = &mut reconciliation_send_fut => res.context("reconciliation_send")?,
        }
        tracing::warn!("CLOSED");
        if completed {
            // control_send.finish().await?;
            Ok(())
        } else {
            Err(anyhow!(
                "All tasks finished but reconciliation did not complete"
            ))
        }
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
    };
    control_send.finish().await?;
    reconciliation_send.finish().await?;
    res
}

#[instrument(skip_all, fields(ch=%notifier.channel().fmt_short()))]
async fn recv_loop<T: Encoder>(
    recv_stream: &mut quinn::RecvStream,
    channel_sender: Sender<T>,
    notifier: Notifier,
) -> anyhow::Result<()> {
    loop {
        // debug!("wait");
        let buf = recv_stream.read_chunk(1024 * 16, true).await?;
        if let Some(buf) = buf {
            channel_sender.write_slice_async(&buf.bytes[..]).await;
            debug!(len = buf.bytes.len(), "recv");
            if channel_sender.is_receivable_notify_set() {
                debug!("notify ResumeRecv");
                notifier.notify().await?;
                // store_handle
                //     .send(ToActor::ResumeRecv { peer, channel })
                //     .await?;
            }
        } else {
            debug!("EOF");
            break;
        }
    }
    // recv_stream.stop()
    Ok(())
}

#[instrument(skip_all, fields(ch=%notifier.channel().fmt_short()))]
async fn send_loop<T: Decoder>(
    send_stream: &mut quinn::SendStream,
    channel_receiver: Receiver<T>,
    notifier: Notifier,
) -> anyhow::Result<()> {
    while let Some(data) = channel_receiver.read_bytes_async().await {
        let len = data.len();
        send_stream.write_chunk(data).await?;
        debug!(len, "sent");
        if channel_receiver.is_sendable_notify_set() {
            debug!("notify ResumeSend");
            notifier.notify().await?;
        }
    }
    send_stream.finish().await?;
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
        // use tracing_chrome::ChromeLayerBuilder;
        // use tracing_subscriber::{prelude::*, registry::Registry};
        // let (chrome_layer, _guard) = ChromeLayerBuilder::new().build();
        // tracing_subscriber::registry().with(chrome_layer).init();

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
