//! TODO(matheus23) docs

use anyhow::Result;
use bytes::{BufMut, Bytes, BytesMut};
use iroh_base::{PublicKey, SecretKey, Signature};
use n0_future::{time, Sink, SinkExt, Stream, TryStreamExt};
use quinn_proto::{coding::Codec, VarInt};
use rand::{CryptoRng, RngCore};

use crate::ExportKeyingMaterial;

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

/// Confirmation of successful connection.
#[derive(derive_more::Debug, serde::Deserialize)]
#[cfg_attr(feature = "server", derive(serde::Serialize))]
pub struct ServerConfirmsConnected;

const SERVER_CONFIRMS_CONNECTED_TAG: VarInt = VarInt::from_u32(3);

/// Denial of connection. The client couldn't be verified as authentic.
#[derive(derive_more::Debug, serde::Deserialize)]
#[cfg_attr(feature = "server", derive(serde::Serialize))]
pub struct ServerDeniesConnection;

const SERVER_DENIES_CONNECTION_TAG: VarInt = VarInt::from_u32(4);

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
pub(crate) async fn clientside(
    io: &mut (impl BytesStreamSink + ExportKeyingMaterial),
    secret_key: &SecretKey,
) -> Result<ServerConfirmsConnected> {
    let public_key = secret_key.public();
    let versions = vec![PROTOCOL_VERSION.to_vec()];

    let key_material = io.export_keying_material(
        [0u8; 32],
        b"iroh-relay handshake v1",
        Some(secret_key.public().as_bytes()),
    );

    if let Some(key_material) = key_material {
        write_frame(
            io,
            CLIENT_INFO_TAG,
            ClientInfo {
                public_key,
                signature: secret_key.sign(&blake3::derive_key(
                    "iroh-relay handshake v1 key material signature",
                    &key_material[..16],
                )),
                key_material_suffix: Some(key_material[16..].try_into().expect("split right")),
                versions: versions.clone(),
            },
        )
        .await?;
    }

    let (tag, frame) = read_frame(
        io,
        &[
            SERVER_CHALLENGE_TAG,
            SERVER_CONFIRMS_CONNECTED_TAG,
            SERVER_DENIES_CONNECTION_TAG,
        ],
        time::Duration::from_secs(30),
    )
    .await?;

    let (tag, frame) = if tag == SERVER_CHALLENGE_TAG {
        let challenge: ServerChallenge = postcard::from_bytes(&frame)?;

        let client_info = ClientInfo {
            public_key,
            signature: secret_key.sign(&blake3::derive_key(
                "iroh-relay handshake v1 challenge signature",
                &challenge.challenge,
            )),
            key_material_suffix: None,
            versions,
        };
        write_frame(io, CLIENT_INFO_TAG, client_info).await?;

        read_frame(
            io,
            &[SERVER_CONFIRMS_CONNECTED_TAG, SERVER_DENIES_CONNECTION_TAG],
            time::Duration::from_secs(30),
        )
        .await?
    } else {
        (tag, frame)
    };

    match tag {
        SERVER_CONFIRMS_CONNECTED_TAG => {
            let confirmation: ServerConfirmsConnected = postcard::from_bytes(&frame)?;
            Ok(confirmation)
        }
        SERVER_DENIES_CONNECTION_TAG => {
            let denial: ServerDeniesConnection = postcard::from_bytes(&frame)?;
            anyhow::bail!("server denied connection: {denial:?}");
        }
        _ => unreachable!(),
    }
}

/// TODO(matheus23) docs
#[cfg(feature = "server")]
pub(crate) async fn serverside(
    io: &mut (impl BytesStreamSink + ExportKeyingMaterial),
    mut rng: impl RngCore + CryptoRng,
) -> Result<ClientInfo> {
    let mut challenge = [0u8; 16];
    rng.fill_bytes(&mut challenge);

    write_frame(io, SERVER_CHALLENGE_TAG, ServerChallenge { challenge }).await?;

    let (_, frame) = read_frame(io, &[CLIENT_INFO_TAG], time::Duration::from_secs(10)).await?;
    let client_info: ClientInfo = postcard::from_bytes(&frame)?;

    let result = client_info.public_key.verify(
        &blake3::derive_key("iroh-relay handshake v1 challenge signature", &challenge),
        &client_info.signature,
    );

    if result.is_ok() {
        write_frame(io, SERVER_CONFIRMS_CONNECTED_TAG, ServerConfirmsConnected).await?;
    } else {
        write_frame(io, SERVER_DENIES_CONNECTION_TAG, ServerDeniesConnection).await?;
    }

    Ok(client_info)
}

async fn write_frame(
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

async fn read_frame(
    io: &mut impl BytesStreamSink,
    expected_tags: &[VarInt],
    timeout: time::Duration,
) -> Result<(VarInt, Bytes)> {
    let recv = time::timeout(timeout, io.try_next())
        .await??
        .ok_or_else(|| anyhow::anyhow!("disconnected"))?;

    let mut cursor = std::io::Cursor::new(recv);
    let tag = VarInt::decode(&mut cursor)?;
    anyhow::ensure!(
        expected_tags.contains(&tag),
        "Unexpected tag {tag}, expected one of {expected_tags:?}"
    );

    let start = cursor.position() as usize;
    let payload = cursor.into_inner().slice(start..);

    Ok((tag, payload))
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use iroh_base::SecretKey;
    use n0_future::{Sink, SinkExt, Stream, TryStreamExt};
    use testresult::TestResult;
    use tokio_util::codec::{Framed, LengthDelimitedCodec};

    use crate::ExportKeyingMaterial;

    struct TestKeyingMaterial<IO> {
        shared_secret: Option<u64>,
        inner: IO,
    }

    trait WithTlsSharedSecret: Sized {
        fn with_shared_secret(self, shared_secret: Option<u64>) -> TestKeyingMaterial<Self>;
    }

    impl<T: Sized> WithTlsSharedSecret for T {
        fn with_shared_secret(self, shared_secret: Option<u64>) -> TestKeyingMaterial<Self> {
            TestKeyingMaterial {
                shared_secret,
                inner: self,
            }
        }
    }

    impl<IO> ExportKeyingMaterial for TestKeyingMaterial<IO> {
        fn export_keying_material<T: AsMut<[u8]>>(
            &self,
            mut output: T,
            label: &[u8],
            context: Option<&[u8]>,
        ) -> Option<T> {
            // we simulate something like exporting keying material using blake3

            let label_key = blake3::hash(label);
            let context_key = blake3::keyed_hash(label_key.as_bytes(), context.unwrap_or(&[]));
            let mut hasher = blake3::Hasher::new_keyed(context_key.as_bytes());
            hasher.update(&self.shared_secret?.to_le_bytes());
            hasher.finalize_xof().fill(output.as_mut());

            Some(output)
        }
    }

    impl<V, IO: Stream<Item = V> + Unpin> Stream for TestKeyingMaterial<IO> {
        type Item = V;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::pin::Pin::new(&mut self.inner).poll_next(cx)
        }
    }

    impl<V, E, IO: Sink<V, Error = E> + Unpin> Sink<V> for TestKeyingMaterial<IO> {
        type Error = E;

        fn poll_ready(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::pin::Pin::new(&mut self.inner).poll_ready(cx)
        }

        fn start_send(mut self: std::pin::Pin<&mut Self>, item: V) -> Result<(), Self::Error> {
            std::pin::Pin::new(&mut self.inner).start_send(item)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_close(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::pin::Pin::new(&mut self.inner).poll_close(cx)
        }
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn simulate_handshake() -> TestResult {
        use anyhow::Context;

        let (client, server) = tokio::io::duplex(1024);
        let secret_key = SecretKey::generate(rand::rngs::OsRng);

        let mut client_io = Framed::new(client, LengthDelimitedCodec::new())
            .map_ok(BytesMut::freeze)
            .map_err(anyhow::Error::from)
            .sink_err_into()
            .with_shared_secret(Some(42));
        let mut server_io = Framed::new(server, LengthDelimitedCodec::new())
            .map_ok(BytesMut::freeze)
            .map_err(anyhow::Error::from)
            .sink_err_into()
            .with_shared_secret(Some(42));

        let (_, client_info) = n0_future::future::try_zip(
            async {
                super::clientside(&mut client_io, &secret_key)
                    .await
                    .context("clientside")
            },
            async {
                super::serverside(&mut server_io, rand::rngs::OsRng)
                    .await
                    .context("serverside")
            },
        )
        .await?;

        println!("{client_info:#?}");

        Ok(())
    }
}
