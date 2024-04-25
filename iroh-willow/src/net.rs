use std::{pin::Pin, task::Poll};

use anyhow::{ensure, Context};
use futures::{SinkExt, Stream};
use iroh_base::hash::Hash;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::StreamExt;
use tokio_util::codec::{Decoder, FramedRead, FramedWrite};
use tracing::{debug, instrument};

use crate::{
    proto::wgps::{AccessChallenge, ChallengeHash, CHALLENGE_HASH_LENGTH, MAX_PAYLOAD_SIZE_POWER},
    session::{Role, Session, SessionInit},
    store::Store,
};

use self::codec::WillowCodec;

pub mod codec;

/// Read the next frame from a [`FramedRead`] but only if it is available without waiting on IO.
async fn next_if_ready<T: tokio::io::AsyncRead + Unpin, D: Decoder>(
    mut reader: &mut FramedRead<T, D>,
) -> Option<Result<D::Item, D::Error>> {
    futures::future::poll_fn(|cx| match Pin::new(&mut reader).poll_next(cx) {
        Poll::Ready(r) => Poll::Ready(r),
        Poll::Pending => Poll::Ready(None),
    })
    .await
}

#[instrument(skip_all, fields(role=?role))]
pub async fn run<S: Store>(
    store: &mut S,
    conn: quinn::Connection,
    role: Role,
    init: SessionInit,
) -> anyhow::Result<()> {
    let (mut send, mut recv) = match role {
        Role::Alfie => conn.open_bi().await?,
        Role::Betty => conn.accept_bi().await?,
    };

    let our_nonce: AccessChallenge = rand::random();
    debug!(?role, "start");
    let (received_commitment, max_payload_size) =
        exchange_commitments(&mut send, &mut recv, &our_nonce).await?;
    debug!(?role, "exchanged comittments");

    let mut session = Session::new(role, our_nonce, max_payload_size, received_commitment, init);

    let mut reader = FramedRead::new(recv, WillowCodec);
    let mut writer = FramedWrite::new(send, WillowCodec);

    // TODO: blocking!
    session.process(store)?;

    // send out initial messages
    for message in session.drain_outbox() {
        debug!(role=?role, ?message, "send");
        writer.send(message).await?;
    }

    while let Some(message) = reader.next().await {
        let message = message.context("error from reader")?;
        debug!(%message,awaited=true, "recv");
        session.recv(message.into());

        // keep pushing already buffered messages
        while let Some(message) = next_if_ready(&mut reader).await {
            let message = message.context("error from reader")?;
            debug!(%message,awaited=false, "recv");
            // TODO: stop when session is full
            session.recv(message.into());
        }

        // TODO: blocking!
        let done = session.process(store)?;
        debug!(?done, "process done");

        for message in session.drain_outbox() {
            debug!(%message, "send");
            writer.send(message).await?;
        }

        if done {
            debug!("close");
            writer.close().await?;
        }
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

    use iroh_base::hash::Hash;
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
        store::{MemoryStore, Store},
    };

    const ALPN: &[u8] = b"iroh-willow/0";

    #[tokio::test]
    async fn smoke() -> anyhow::Result<()> {
        iroh_test::logging::setup_multithreaded();
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(1);
        let n_betty = 10;
        let n_alfie = 20;

        let ep_alfie = MagicEndpoint::builder()
            .alpns(vec![ALPN.to_vec()])
            .bind(0)
            .await?;
        let ep_betty = MagicEndpoint::builder()
            .alpns(vec![ALPN.to_vec()])
            .bind(0)
            .await?;

        let addr_betty = ep_betty.my_addr().await?;

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

        let (res_alfie, res_betty) = tokio::join!(
            run(&mut store_alfie, conn_alfie, Role::Alfie, init_alfie),
            run(&mut store_betty, conn_betty, Role::Betty, init_betty),
        );
        info!(time=?start.elapsed(), "reconciliation finished!");

        info!("alfie res {:?}", res_alfie);
        info!("betty res {:?}", res_betty);
        info!(
            "alfie store {:?}",
            get_entries_debug(&mut store_alfie, namespace_id)
        );
        info!(
            "betty store {:?}",
            get_entries_debug(&mut store_betty, namespace_id)
        );

        assert!(res_alfie.is_ok());
        assert!(res_betty.is_ok());
        assert_eq!(
            get_entries(&mut store_alfie, namespace_id),
            expected_entries
        );
        assert_eq!(
            get_entries(&mut store_betty, namespace_id),
            expected_entries
        );

        Ok(())
    }
    fn get_entries<S: Store>(store: &mut S, namespace: NamespaceId) -> HashSet<Entry> {
        store
            .get_entries(namespace, &ThreeDRange::full())
            .filter_map(Result::ok)
            .collect()
    }

    fn get_entries_debug<S: Store>(
        store: &mut S,
        namespace: NamespaceId,
    ) -> Vec<(SubspaceId, Path)> {
        let mut entries: Vec<_> = store
            .get_entries(namespace, &ThreeDRange::full())
            .filter_map(|r| r.ok())
            .map(|e| (e.subspace_id, e.path))
            .collect();
        entries.sort();
        entries
    }
}
