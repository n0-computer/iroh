use anyhow::ensure;
use futures::{FutureExt, SinkExt, TryFutureExt};
use iroh_base::hash::Hash;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::debug;

use crate::{
    proto::wgps::{
        AccessChallenge, ChallengeHash, CHALLENGE_HASH_LENGTH, CHALLENGE_LENGTH,
        MAXIMUM_PAYLOAD_SIZE_POWER,
    },
    session::{Role, Session, SessionInit},
    store::{MemoryStore, Store},
};

use self::codec::WillowCodec;

pub mod codec;

async fn run<S: Store>(
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
    let (received_commitment, maximum_payload_size) =
        exchange_commitments(&mut send, &mut recv, &our_nonce).await?;
    debug!(?role, "exchanged comittments");

    let mut session = Session::new(
        role,
        our_nonce,
        maximum_payload_size,
        received_commitment,
        init,
    );

    let mut reader = FramedRead::new(recv, WillowCodec);
    let mut writer = FramedWrite::new(send, WillowCodec);

    // move to store thread for this!
    session.process(store)?;

    // back in network land: send out everything
    // should be in parallel with reading
    for message in session.drain_outbox() {
        debug!(role=?role, ?message, "send");
        writer.send(message).await?;
    }

    while let Some(message) = reader.try_next().await? {
        debug!(?role, ?message, "recv");
        // TODO: buffer more than a single message here before handing off to store thread
        // what we should do here:
        // * notify store thread that we want to process
        // * keep reading and pushing into session, until session is full
        // * once store thread is ready for us: be notified of that, and hand over session to store
        //   thread
        session.recv(message.into());

        // move to store thread for this!
        let done = session.process(store)?;

        // back in network land: send out everything
        // should be in parallel with reading
        for message in session.drain_outbox() {
            debug!(role=?role, ?message, "send");
            writer.send(message).await?;
        }

        if done {
            break;
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
    send.write_u8(MAXIMUM_PAYLOAD_SIZE_POWER).await?;
    send.write_all(challenge_hash.as_bytes()).await?;

    let their_maximum_payload_size_power = recv.read_u8().await?;
    ensure!(
        their_maximum_payload_size_power <= 64,
        "maximum payload size too large"
    );
    let their_maximum_payload_size = 2usize.pow(their_maximum_payload_size_power as u32);

    let mut received_commitment = [0u8; CHALLENGE_HASH_LENGTH];
    recv.read_exact(&mut received_commitment).await?;
    Ok((received_commitment, their_maximum_payload_size))
}

#[cfg(test)]
mod tests {
    use iroh_base::hash::Hash;
    use iroh_net::MagicEndpoint;
    use rand::SeedableRng;
    use tracing::debug;

    use crate::{
        net::run,
        proto::{
            keys::{NamespaceId, NamespaceSecretKey, NamespaceType, UserSecretKey},
            meadowcap::{AccessMode, McCapability, OwnedCapability},
            wgps::{AreaOfInterest, ReadCapability},
            willow::{Entry, Path},
        },
        session::{Role, SessionInit},
        store::{MemoryStore, Store},
    };

    const ALPN: &[u8] = b"iroh-willow/0";

    #[tokio::test]
    async fn smoke() -> anyhow::Result<()> {
        iroh_test::logging::setup_multithreaded();
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(1);

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
        debug!("connected");

        let namespace_secret = NamespaceSecretKey::generate(&mut rng, NamespaceType::Owned);
        let namespace_id: NamespaceId = namespace_secret.public_key().into();

        let mut store_alfie = MemoryStore::default();
        let init_alfie = {
            let secret_key = UserSecretKey::generate(&mut rng);
            let public_key = secret_key.public_key();
            let read_capability = ReadCapability::Owned(OwnedCapability::new(
                &namespace_secret,
                public_key,
                AccessMode::Read,
            ));
            let area_of_interest = AreaOfInterest::full();
            let write_capability = McCapability::Owned(OwnedCapability::new(
                &namespace_secret,
                public_key,
                AccessMode::Write,
            ));
            for i in 0..3 {
                let p = format!("alfie{i}");
                let entry = Entry {
                    namespace_id,
                    subspace_id: public_key.into(),
                    path: Path::new(&[p.as_bytes()])?,
                    timestamp: 10,
                    payload_length: 2,
                    payload_digest: Hash::new("cool things"),
                };
                let entry = entry.attach_authorisation(write_capability.clone(), &secret_key)?;
                store_alfie.ingest_entry(&entry)?;
            }
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
            let area_of_interest = AreaOfInterest::full();
            let write_capability = McCapability::Owned(OwnedCapability::new(
                &namespace_secret,
                public_key,
                AccessMode::Write,
            ));
            for i in 0..3 {
                let p = format!("betty{i}");
                let entry = Entry {
                    namespace_id,
                    subspace_id: public_key.into(),
                    path: Path::new(&[p.as_bytes()])?,
                    timestamp: 10,
                    payload_length: 2,
                    payload_digest: Hash::new("cool things"),
                };
                let entry = entry.attach_authorisation(write_capability.clone(), &secret_key)?;
                store_betty.ingest_entry(&entry)?;
            }
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
        res_alfie.unwrap();
        res_betty.unwrap();
        println!("alfie {:?}", store_alfie);
        println!("betty {:?}", store_betty);

        Ok(())
    }
}
