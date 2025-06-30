//! TODO(matheus23) docs

use bytes::{BufMut, Bytes, BytesMut};
#[cfg(feature = "server")]
use iroh_base::Signature;
use iroh_base::{PublicKey, SecretKey};
use n0_future::{
    time::{self, Elapsed},
    SinkExt, TryStreamExt,
};
use nested_enum_utils::common_fields;
#[cfg(feature = "server")]
use rand::{CryptoRng, RngCore};
use snafu::{Backtrace, OptionExt, ResultExt, Snafu};

use super::{relay::FrameType, send_recv::SendError, streams::BytesStreamSink};
use crate::ExportKeyingMaterial;

/// Message that tells the server the client needs a challenge to authenticate.
#[derive(derive_more::Debug, serde::Serialize)]
#[cfg_attr(feature = "server", derive(serde::Deserialize))]
pub(crate) struct ClientRequestChallenge;

/// A challenge for the client to sign with their secret key for NodeId authentication.
#[derive(derive_more::Debug, serde::Deserialize)]
#[cfg_attr(feature = "server", derive(serde::Serialize))]
pub(crate) struct ServerChallenge {
    /// The challenge to sign.
    /// Must be randomly generated with an RNG that is safe to use for crypto.
    pub(crate) challenge: [u8; 16],
}

/// Authentication message from the client.
///
/// Also serves to inform the server about the client's send message version,
/// which will be passed on to other connecting clients.
#[derive(derive_more::Debug, serde::Serialize)]
#[cfg_attr(feature = "server", derive(serde::Deserialize))]
pub(crate) struct ClientAuth {
    /// The client's public key, a.k.a. the `NodeId`
    pub(crate) public_key: PublicKey,
    /// A signature of the server challenge, serves as authentication.
    #[serde(with = "serde_bytes")]
    pub(crate) signature: [u8; 64],
    /// Part of the extracted key material, if that's what was signed.
    pub(crate) key_material_suffix: Option<[u8; 16]>,
}

/// Confirmation of successful connection.
#[derive(derive_more::Debug, serde::Deserialize)]
#[cfg_attr(feature = "server", derive(serde::Serialize))]
pub(crate) struct ServerConfirmsAuth;

/// Denial of connection. The client couldn't be verified as authentic.
#[derive(derive_more::Debug, serde::Deserialize)]
#[cfg_attr(feature = "server", derive(serde::Serialize))]
pub(crate) struct ServerDeniesAuth;

/// Trait for getting the frame type tag for a frame.
///
/// Used only in the handshake, as the frame we expect next
/// is fairly stateful.
/// Not used in the send/recv protocol, as any frame is
/// allowed to happen at any time there.
trait Frame {
    /// The frame type this frame is identified by and prefixed with
    const TAG: FrameType;
}

impl<T: Frame> Frame for &T {
    const TAG: FrameType = T::TAG;
}

impl Frame for ClientRequestChallenge {
    const TAG: FrameType = FrameType::ClientRequestChallenge;
}

impl Frame for ServerChallenge {
    const TAG: FrameType = FrameType::ServerChallenge;
}

impl Frame for ClientAuth {
    const TAG: FrameType = FrameType::ClientAuth;
}

impl Frame for ServerConfirmsAuth {
    const TAG: FrameType = FrameType::ServerConfirmsAuth;
}

impl Frame for ServerDeniesAuth {
    const TAG: FrameType = FrameType::ServerDeniesAuth;
}

#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum Error {
    #[snafu(transparent)]
    Websocket {
        #[cfg(not(wasm_browser))]
        source: tokio_websockets::Error,
        #[cfg(wasm_browser)]
        source: ws_stream_wasm::WsErr,
    },
    #[snafu(transparent)]
    Legacy { source: SendError },
    #[snafu(display("Handshake timeout reached"))]
    Timeout { source: Elapsed },
    #[snafu(display("Handshake stream ended prematurely"))]
    UnexpectedEnd {},
    #[snafu(display("The relay denied our authentication"))]
    ServerDeniedAuth {},
    #[snafu(display("Unexpected tag, got {frame_type}, but expected one of {expected_types:?}"))]
    UnexpectedFrameType {
        frame_type: FrameType,
        expected_types: Vec<FrameType>,
    },
    #[snafu(display("Handshake failed while deserializing {frame_type} frame"))]
    DeserializationError {
        frame_type: FrameType,
        source: postcard::Error,
    },
}

impl ServerChallenge {
    /// TODO(matheus23): docs
    #[cfg(feature = "server")]
    pub(crate) fn new(mut rng: impl RngCore + CryptoRng) -> Self {
        let mut challenge = [0u8; 16];
        rng.fill_bytes(&mut challenge);
        Self { challenge }
    }

    fn message_to_sign(&self) -> [u8; 32] {
        blake3::derive_key(
            "iroh-relay handshake v1 challenge signature",
            &self.challenge,
        )
    }
}

impl ClientAuth {
    /// TODO(matheus23): docs
    pub(crate) fn new_from_challenge(secret_key: &SecretKey, challenge: &ServerChallenge) -> Self {
        Self {
            public_key: secret_key.public(),
            key_material_suffix: None,
            signature: secret_key.sign(&challenge.message_to_sign()).to_bytes(),
        }
    }

    /// TODO(matheus23): docs
    #[cfg(feature = "server")]
    pub(crate) fn verify_from_challenge(&self, challenge: &ServerChallenge) -> bool {
        self.public_key
            .verify(
                &challenge.message_to_sign(),
                &Signature::from_bytes(&self.signature),
            )
            .is_ok()
    }

    pub(crate) fn new_from_key_export(
        secret_key: &SecretKey,
        io: &mut impl ExportKeyingMaterial,
    ) -> Option<Self> {
        let public_key = secret_key.public();
        let key_material = io.export_keying_material(
            [0u8; 32],
            b"iroh-relay handshake v1",
            Some(secret_key.public().as_bytes()),
        )?;

        let message = blake3::derive_key(
            "iroh-relay handshake v1 key material signature",
            &key_material[..16],
        );
        Some(ClientAuth {
            public_key,
            signature: secret_key.sign(&message).to_bytes(),
            key_material_suffix: Some(key_material[16..].try_into().expect("split right")),
        })
    }

    #[cfg(feature = "server")]
    pub(crate) fn verify_from_key_export(&self, io: &mut impl ExportKeyingMaterial) -> bool {
        let Some(key_material) = io.export_keying_material(
            [0u8; 32],
            b"iroh-relay handshake v1",
            Some(self.public_key.as_bytes()),
        ) else {
            return false;
        };

        let message = blake3::derive_key(
            "iroh-relay handshake v1 key material signature",
            &key_material[..16],
        );
        self.public_key
            .verify(&message, &Signature::from_bytes(&self.signature))
            .is_ok()
    }
}

/// TODO(matheus23) docs
pub(crate) async fn clientside(
    io: &mut (impl BytesStreamSink + ExportKeyingMaterial),
    secret_key: &SecretKey,
) -> Result<ServerConfirmsAuth, Error> {
    if let Some(client_auth) = ClientAuth::new_from_key_export(secret_key, io) {
        write_frame(io, client_auth).await?;
    } else {
        // we can't use key exporting, so request a challenge.
        write_frame(io, ClientRequestChallenge).await?;
    }

    let (tag, frame) = read_frame(
        io,
        &[
            ServerChallenge::TAG,
            ServerConfirmsAuth::TAG,
            ServerDeniesAuth::TAG,
        ],
        time::Duration::from_secs(30),
    )
    .await?;

    let (tag, frame) = if tag == ServerChallenge::TAG {
        let challenge: ServerChallenge = deserialize_frame(frame)?;

        let client_info = ClientAuth::new_from_challenge(secret_key, &challenge);
        write_frame(io, client_info).await?;

        read_frame(
            io,
            &[ServerConfirmsAuth::TAG, ServerDeniesAuth::TAG],
            time::Duration::from_secs(30),
        )
        .await?
    } else {
        (tag, frame)
    };

    match tag {
        FrameType::ServerConfirmsAuth => {
            let confirmation: ServerConfirmsAuth = deserialize_frame(frame)?;
            Ok(confirmation)
        }
        FrameType::ServerDeniesAuth => {
            let _denial: ServerDeniesAuth = deserialize_frame(frame)?;
            return Err(ServerDeniedAuthSnafu.build());
        }
        _ => unreachable!(),
    }
}

/// TODO(matheus23) docs
#[cfg(feature = "server")]
pub(crate) async fn serverside(
    io: &mut (impl BytesStreamSink + ExportKeyingMaterial),
    rng: impl RngCore + CryptoRng,
) -> Result<ClientAuth, Error> {
    let (tag, frame) = read_frame(
        io,
        &[ClientRequestChallenge::TAG, ClientAuth::TAG],
        time::Duration::from_secs(10),
    )
    .await?;

    // it might be fast-path authentication using TLS exported key material
    if tag == ClientAuth::TAG {
        let client_auth: ClientAuth = deserialize_frame(frame)?;
        if client_auth.verify_from_key_export(io) {
            write_frame(io, ServerConfirmsAuth).await?;
            return Ok(client_auth);
        }
    } else {
        let _frame: ClientRequestChallenge = deserialize_frame(frame)?;
    }

    let challenge = ServerChallenge::new(rng);
    write_frame(io, &challenge).await?;

    let (_, frame) = read_frame(io, &[ClientAuth::TAG], time::Duration::from_secs(10)).await?;
    let client_auth: ClientAuth = deserialize_frame(frame)?;

    if client_auth.verify_from_challenge(&challenge) {
        write_frame(io, ServerConfirmsAuth).await?;
    } else {
        write_frame(io, ServerDeniesAuth).await?;
    }

    Ok(client_auth)
}

async fn write_frame<F: serde::Serialize + Frame>(
    io: &mut impl BytesStreamSink,
    frame: F,
) -> Result<(), Error> {
    let mut bytes = BytesMut::new();
    F::TAG.write_to(&mut bytes);
    let bytes = postcard::to_io(&frame, bytes.writer())
        .expect("serialization failed") // buffer can't become "full" without being a critical failure, datastructures shouldn't ever fail serialization
        .into_inner()
        .freeze();
    io.send(bytes).await?;
    io.flush().await?;
    Ok(())
}

async fn read_frame(
    io: &mut impl BytesStreamSink,
    expected_types: &[FrameType],
    timeout: time::Duration,
) -> Result<(FrameType, Bytes), Error> {
    let recv = time::timeout(timeout, io.try_next())
        .await
        .context(TimeoutSnafu)??
        .ok_or_else(|| UnexpectedEndSnafu.build())?;

    let (frame_type, payload) = FrameType::from_bytes(recv).context(UnexpectedEndSnafu)?;
    snafu::ensure!(
        expected_types.contains(&frame_type),
        UnexpectedFrameTypeSnafu {
            frame_type,
            expected_types: expected_types.into_iter().cloned().collect::<Vec<_>>()
        }
    );

    Ok((frame_type, payload))
}

fn deserialize_frame<F: Frame + serde::de::DeserializeOwned>(frame: Bytes) -> Result<F, Error> {
    postcard::from_bytes(&frame).context(DeserializationSnafu { frame_type: F::TAG })
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use bytes::BytesMut;
    use iroh_base::SecretKey;
    use n0_future::{Sink, SinkExt, Stream, TryStreamExt};
    use n0_snafu::{Result, ResultExt};
    use tokio_util::codec::{Framed, LengthDelimitedCodec};

    use super::{ClientAuth, ServerChallenge};
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

    async fn simulate_handshake(
        secret_key: &SecretKey,
        client_shared_secret: Option<u64>,
        server_shared_secret: Option<u64>,
    ) -> Result<ClientAuth> {
        let (client, server) = tokio::io::duplex(1024);

        let mut client_io = Framed::new(client, LengthDelimitedCodec::new())
            .map_ok(BytesMut::freeze)
            .map_err(|e| tokio_websockets::Error::Io(e).into())
            .sink_map_err(|e| tokio_websockets::Error::Io(e).into())
            .with_shared_secret(client_shared_secret);
        let mut server_io = Framed::new(server, LengthDelimitedCodec::new())
            .map_ok(BytesMut::freeze)
            .map_err(|e| tokio_websockets::Error::Io(e).into())
            .sink_map_err(|e| tokio_websockets::Error::Io(e).into())
            .with_shared_secret(server_shared_secret);

        let (_, client_auth) = n0_future::future::try_zip(
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

        Ok(client_auth)
    }

    #[tokio::test]
    async fn test_handshake_via_shared_secrets() -> Result {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        let auth = simulate_handshake(&secret_key, Some(42), Some(42)).await?;
        assert_eq!(auth.public_key, secret_key.public());
        assert!(auth.key_material_suffix.is_some()); // it got verified via shared key material
        Ok(())
    }

    #[tokio::test]
    async fn test_handshake_via_challenge() -> Result {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        let auth = simulate_handshake(&secret_key, None, None).await?;
        assert_eq!(auth.public_key, secret_key.public());
        assert!(auth.key_material_suffix.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_handshake_mismatching_shared_secrets() -> Result {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        // mismatching shared secrets *might* happen with HTTPS proxies that don't also middle-man the shared secret
        let auth = simulate_handshake(&secret_key, Some(10), Some(99)).await?;
        assert_eq!(auth.public_key, secret_key.public());
        assert!(auth.key_material_suffix.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn test_handshake_challenge_fallback() -> Result {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        // clients might not have access to shared secrets
        let auth = simulate_handshake(&secret_key, None, Some(99)).await?;
        assert_eq!(auth.public_key, secret_key.public());
        assert!(auth.key_material_suffix.is_none());
        Ok(())
    }

    #[test]
    fn test_client_auth_roundtrip() -> Result {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        let challenge = ServerChallenge::new(rand::rngs::OsRng);
        let client_auth = ClientAuth::new_from_challenge(&secret_key, &challenge);

        let bytes = postcard::to_allocvec(&client_auth).e()?;
        let decoded: ClientAuth = postcard::from_bytes(&bytes).e()?;

        assert_eq!(client_auth.public_key, decoded.public_key);
        assert_eq!(client_auth.key_material_suffix, decoded.key_material_suffix);
        assert_eq!(client_auth.signature, decoded.signature);

        Ok(())
    }

    #[test]
    fn test_challenge_verification() -> Result {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        let challenge = ServerChallenge::new(rand::rngs::OsRng);
        let client_auth = ClientAuth::new_from_challenge(&secret_key, &challenge);
        assert!(client_auth.verify_from_challenge(&challenge));

        Ok(())
    }
}
