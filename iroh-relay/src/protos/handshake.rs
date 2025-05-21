//! TODO(matheus23) docs

use anyhow::Result;
use bytes::{BufMut, Bytes, BytesMut};
use iroh_base::{PublicKey, SecretKey, Signature};
use n0_future::{time, Sink, SinkExt, Stream, TryStreamExt};
use quinn_proto::{coding::Codec, VarInt};
use rand::{CryptoRng, RngCore};

/// TODO(matheus23) docs
pub const PROTOCOL_VERSION: &[u8] = b"1";

/// A challenge for the client to sign with their secret key for NodeId authentication.
#[derive(derive_more::Debug, serde::Deserialize)]
#[cfg_attr(feature = "server", derive(serde::Serialize))]
pub struct ServerChallenge {
    /// The challenge to sign.
    /// Must be randomly generated with an RNG that is safe to use for crypto.
    pub challenge: [u8; 16],
}

const SERVER_CHALLENGE_TAG: VarInt = VarInt::from_u32(1);

/// Info about the client. Also serves as authentication.
#[derive(derive_more::Debug, serde::Serialize)]
#[cfg_attr(feature = "server", derive(serde::Deserialize))]
pub struct ClientInfo {
    /// The client's public key, a.k.a. the `NodeId`
    pub public_key: PublicKey,
    /// A signature of the server challenge, serves as authentication.
    pub signature: Signature,
    /// Part of the extracted key material, if that's what was signed.
    pub key_material_suffix: Option<[u8; 16]>,
    /// Supported versions/protocol features for version negotiation
    /// with other connected relay clients
    pub versions: Vec<Vec<u8>>,
}

const CLIENT_INFO_TAG: VarInt = VarInt::from_u32(2);

/// TODO(matheus23) docs
pub trait BytesStreamSink:
    Stream<Item = Result<Bytes>> + Sink<Bytes, Error = anyhow::Error> + Unpin
{
}

impl<T: Stream<Item = Result<Bytes>> + Sink<Bytes, Error = anyhow::Error> + Unpin> BytesStreamSink
    for T
{
}

/// TODO(matheus23) docs
pub async fn clientside(io: &mut impl BytesStreamSink, secret_key: &SecretKey) -> Result<()> {
    let challenge: ServerChallenge =
        read_postcard_frame(io, SERVER_CHALLENGE_TAG, time::Duration::from_secs(30)).await?;

    let client_info = ClientInfo {
        public_key: secret_key.public(),
        signature: secret_key.sign(&challenge.challenge), // TODO(matheus23) add some context to the signature, so we're not signing arbitrary stuff
        key_material_suffix: None,
        versions: vec![PROTOCOL_VERSION.to_vec()],
    };
    write_postcard_frame(io, CLIENT_INFO_TAG, client_info).await?;

    Ok(())
}

/// TODO(matheus23) docs
#[cfg(feature = "server")]
pub async fn serverside(
    io: &mut impl BytesStreamSink,
    mut rng: impl RngCore + CryptoRng,
) -> Result<ClientInfo> {
    let mut challenge = [0u8; 16];
    rng.fill_bytes(&mut challenge);

    write_postcard_frame(io, SERVER_CHALLENGE_TAG, ServerChallenge { challenge }).await?;

    let client_info: ClientInfo =
        read_postcard_frame(io, CLIENT_INFO_TAG, time::Duration::from_secs(10)).await?;

    // TODO(matheus23): Add context bytes to this verification check
    client_info
        .public_key
        .verify(&challenge, &client_info.signature)?;

    Ok(client_info)
}

async fn write_postcard_frame(
    io: &mut impl BytesStreamSink,
    tag: VarInt,
    frame: impl serde::Serialize,
) -> Result<()> {
    let mut bytes = BytesMut::new();
    tag.encode(&mut bytes);
    let bytes = postcard::to_io(&frame, bytes.writer())?
        .into_inner()
        .freeze();
    io.send(bytes).await?;
    io.flush().await?;
    Ok(())
}

async fn read_postcard_frame<F: serde::de::DeserializeOwned>(
    io: &mut impl BytesStreamSink,
    expected_tag: VarInt,
    timeout: time::Duration,
) -> Result<F> {
    let recv = time::timeout(timeout, io.try_next())
        .await??
        .ok_or_else(|| anyhow::anyhow!("disconnected"))?;
    let mut cursor = std::io::Cursor::new(recv);
    let tag = VarInt::decode(&mut cursor)?;
    anyhow::ensure!(tag == expected_tag);
    let start = cursor.position() as usize;
    let frame: F = postcard::from_bytes(
        &cursor
            .into_inner()
            .get(start..)
            .expect("cursor confirmed position"),
    )?;

    Ok(frame)
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use iroh_base::SecretKey;
    use n0_future::{SinkExt, TryStreamExt};
    use testresult::TestResult;
    use tokio_util::codec::{Framed, LengthDelimitedCodec};

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn simulate_handshake() -> TestResult {
        let (client, server) = tokio::io::duplex(1024);
        let secret_key = SecretKey::generate(rand::rngs::OsRng);

        let mut client_io = Framed::new(client, LengthDelimitedCodec::new())
            .map_ok(BytesMut::freeze)
            .map_err(anyhow::Error::from)
            .sink_err_into();
        let mut server_io = Framed::new(server, LengthDelimitedCodec::new())
            .map_ok(BytesMut::freeze)
            .map_err(anyhow::Error::from)
            .sink_err_into();

        let (_, client_info) = n0_future::future::try_zip(
            super::clientside(&mut client_io, &secret_key),
            super::serverside(&mut server_io, rand::rngs::OsRng),
        )
        .await?;

        println!("{client_info:#?}");

        Ok(())
    }
}
