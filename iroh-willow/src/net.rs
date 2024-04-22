use anyhow::ensure;
use futures::SinkExt;
use iroh_base::hash::Hash;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::{
    proto::wgps::{
        AccessChallenge, ChallengeHash, CHALLENGE_HASH_LENGTH, CHALLENGE_LENGTH,
        MAXIMUM_PAYLOAD_SIZE_POWER,
    },
    session::{Role, Session, SessionInit},
    store::MemoryStore,
};

use self::codec::WillowCodec;

pub mod codec;

async fn run(conn: quinn::Connection, our_role: Role, init: SessionInit) -> anyhow::Result<()> {
    let (mut send, mut recv) = match our_role {
        Role::Alfie => conn.open_bi().await?,
        Role::Betty => conn.accept_bi().await?,
    };

    let our_nonce: AccessChallenge = rand::random();
    let (received_commitment, maximum_payload_size) =
        exchange_commitments(&mut send, &mut recv, &our_nonce).await?;

    let mut session = Session::new(
        our_role,
        our_nonce,
        maximum_payload_size,
        received_commitment,
        init,
    );

    let mut reader = FramedRead::new(recv, WillowCodec);
    let mut writer = FramedWrite::new(send, WillowCodec);

    let mut store = MemoryStore::default();

    while let Some(message) = reader.try_next().await? {
        // TODO: buffer more than a single message here before handing off to store thread
        // what we should do here:
        // * notify store thread that we want to process
        // * keep reading and pushing into session, until session is full
        // * once store thread is ready for us: be notified of that, and hand over session to store
        //   thread
        session.recv(message.into());

        // move to store thread for this!
        session.process(&mut store)?;

        // back in network land: send out everything
        // should be in parallel with reading
        for message in session.drain_outbox() {
            writer.send(message).await?;
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
