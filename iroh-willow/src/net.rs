use anyhow::ensure;
use futures::TryFutureExt;
use iroh_base::{hash::Hash, key::NodeId};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
    task::JoinSet,
};
use tracing::{debug, error_span, instrument, trace, warn, Instrument};

use crate::{
    proto::wgps::{
        AccessChallenge, ChallengeHash, LogicalChannel, Message, CHALLENGE_HASH_LENGTH,
        MAX_PAYLOAD_SIZE_POWER,
    },
    session::{coroutine::Channels, Role, SessionInit, SessionState},
    store::actor::{StoreHandle, ToActor},
    util::{
        channel::{channel, Receiver, Sender},
        Decoder, Encoder,
    },
};

const CHANNEL_CAP: usize = 1024 * 64;

const ERROR_CODE_CLOSE_GRACEFUL: u16 = 1;

#[instrument(skip_all, fields(me=%me.fmt_short(), role=?our_role))]
pub async fn run(
    me: NodeId,
    store: StoreHandle,
    conn: quinn::Connection,
    peer: NodeId,
    our_role: Role,
    init: SessionInit,
) -> anyhow::Result<()> {
    let mut join_set = JoinSet::new();
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

    let (control_send, control_recv) = spawn_channel(
        &mut join_set,
        peer,
        LogicalChannel::Control,
        CHANNEL_CAP,
        control_send_stream,
        control_recv_stream,
    );

    let (mut reconciliation_send_stream, mut reconciliation_recv_stream) = match our_role {
        Role::Alfie => conn.open_bi().await?,
        Role::Betty => conn.accept_bi().await?,
    };
    reconciliation_send_stream.write_u8(0u8).await?;
    reconciliation_recv_stream.read_u8().await?;
    let (reconciliation_send, reconciliation_recv) = spawn_channel(
        &mut join_set,
        peer,
        LogicalChannel::Reconciliation,
        CHANNEL_CAP,
        reconciliation_send_stream,
        reconciliation_recv_stream,
    );
    debug!("reconcile channel open");

    let channels = Channels {
        control_send,
        control_recv,
        reconciliation_send,
        reconciliation_recv,
    };
    let state = SessionState::new(our_role, our_nonce, received_commitment, max_payload_size);

    let (reply, reply_rx) = oneshot::channel();
    store
        .send(ToActor::InitSession {
            peer,
            state,
            channels,
            init,
            reply,
        })
        .await?;

    join_set.spawn(async move {
        reply_rx.await??;
        Ok(())
    });

    join_all(join_set).await
}

async fn join_all(mut join_set: JoinSet<anyhow::Result<()>>) -> anyhow::Result<()> {
    let mut final_result = Ok(());
    while let Some(res) = join_set.join_next().await {
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

fn spawn_channel(
    join_set: &mut JoinSet<anyhow::Result<()>>,
    peer: NodeId,
    ch: LogicalChannel,
    cap: usize,
    send_stream: quinn::SendStream,
    recv_stream: quinn::RecvStream,
) -> (Sender<Message>, Receiver<Message>) {
    let (send_tx, send_rx) = channel(cap);
    let (recv_tx, recv_rx) = channel(cap);

    let recv_fut = recv_loop(recv_stream, recv_tx)
        .map_err(move |e| e.context(format!("receive loop for {ch:?} failed")))
        .instrument(error_span!("recv", peer=%peer.fmt_short(), ch=%ch.fmt_short()));

    join_set.spawn(recv_fut);

    let send_fut = send_loop(send_stream, send_rx)
        .map_err(move |e| e.context(format!("send loop for {ch:?} failed")))
        .instrument(error_span!("send", peer=%peer.fmt_short(), ch=%ch.fmt_short()));

    join_set.spawn(send_fut);

    (send_tx, recv_rx)
}

async fn recv_loop<T: Encoder>(
    mut recv_stream: quinn::RecvStream,
    channel_tx: Sender<T>,
) -> anyhow::Result<()> {
    while let Some(buf) = recv_stream.read_chunk(CHANNEL_CAP, true).await? {
        channel_tx.write_slice_async(&buf.bytes[..]).await?;
        trace!(len = buf.bytes.len(), "recv");
    }
    recv_stream.stop(ERROR_CODE_CLOSE_GRACEFUL.into()).ok();
    channel_tx.close();
    Ok(())
}

async fn send_loop<T: Decoder>(
    mut send_stream: quinn::SendStream,
    channel_rx: Receiver<T>,
) -> anyhow::Result<()> {
    while let Some(data) = channel_rx.read_bytes_async().await {
        let len = data.len();
        send_stream.write_chunk(data).await?;
        trace!(len, "sent");
    }
    match send_stream.finish().await {
        Ok(()) => {}
        // If the other side closed gracefully, we are good.
        Err(quinn::WriteError::Stopped(code))
            if code.into_inner() == ERROR_CODE_CLOSE_GRACEFUL as u64 => {}
        Err(err) => return Err(err.into()),
    }
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
    use rand_core::CryptoRngCore;
    use tracing::{debug, info};

    use crate::{
        net::run,
        proto::{
            grouping::AreaOfInterest,
            keys::{NamespaceId, NamespaceKind, NamespaceSecretKey, UserPublicKey, UserSecretKey},
            meadowcap::{AccessMode, McCapability, OwnedCapability},
            wgps::ReadCapability,
            willow::{Entry, InvalidPath, Path, WriteCapability},
        },
        session::{Role, SessionInit},
        store::{
            actor::{StoreHandle, ToActor},
            MemoryStore,
        },
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
        let mut expected_entries = HashSet::new();

        let store_alfie = MemoryStore::default();
        let handle_alfie = StoreHandle::spawn(store_alfie, node_id_alfie);

        let store_betty = MemoryStore::default();
        let handle_betty = StoreHandle::spawn(store_betty, node_id_betty);

        let init_alfie = setup_and_insert(
            &mut rng,
            &handle_alfie,
            &namespace_secret,
            n_alfie,
            &mut expected_entries,
            |n| Path::new(&[b"alfie", n.to_string().as_bytes()]),
        )
        .await?;
        let init_betty = setup_and_insert(
            &mut rng,
            &handle_betty,
            &namespace_secret,
            n_betty,
            &mut expected_entries,
            |n| Path::new(&[b"betty", n.to_string().as_bytes()]),
        )
        .await?;

        debug!("init constructed");
        println!("init took {:?}", start.elapsed());
        let start = Instant::now();

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
        println!("reconciliation took {:?}", start.elapsed());

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
        assert_eq!(
            get_entries(&handle_alfie, namespace_id).await?,
            expected_entries,
            "alfie expected entries"
        );
        assert_eq!(
            get_entries(&handle_betty, namespace_id).await?,
            expected_entries,
            "bettyexpected entries"
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

    async fn setup_and_insert(
        rng: &mut impl CryptoRngCore,
        store: &StoreHandle,
        namespace_secret: &NamespaceSecretKey,
        count: usize,
        track_entries: &mut impl Extend<Entry>,
        path_fn: impl Fn(usize) -> Result<Path, InvalidPath>,
    ) -> anyhow::Result<SessionInit> {
        let user_secret = UserSecretKey::generate(rng);
        let (read_cap, write_cap) = create_capabilities(namespace_secret, user_secret.public_key());
        let subspace_id = user_secret.id();
        let namespace_id = namespace_secret.id();
        for i in 0..count {
            let path = path_fn(i);
            let entry = Entry {
                namespace_id,
                subspace_id,
                path: path.expect("invalid path"),
                timestamp: 10,
                payload_length: 2,
                payload_digest: Hash::new("cool things"),
            };
            track_entries.extend([entry.clone()]);
            let entry = entry.attach_authorisation(write_cap.clone(), &user_secret)?;
            info!("INGEST {entry:?}");
            store.ingest_entry(entry).await?;
        }
        let init = SessionInit::with_interest(user_secret, read_cap, AreaOfInterest::full());
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
        // let init = SessionInit::with_interest(secret_key, read_capability, AreaOfInterest::full())
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
