//! Implements the handshake protocol that iroh's relays and iroh clients that connect to it go through.
//!
//! The purpose of the handshake is to
//! 1. Inform the relay of the client's NodeId
//! 2. Check that the connecting client owns the secret key for its NodeId ("is authentic"/"authentication")
//! 3. Possibly check that the client has access to this relay, if the relay requires authorization.
//!
//! Additional complexity comes from the fact that there's two ways that clients can authenticate with
//! relays.
//!
//! One way is via an explicitly sent challenge:
//!
//! 1. Once a websocket connection is opened, a client receives a challenge (the [`ServerChallenge`] frame)
//! 2. The client sends back what is essentially a signature of that challenge with their secret key
//!    that matches the NodeId they have, as well as the NodeId (the [`ClientAuth`] frame)
//!
//! The second way is very similar to the [Concealed HTTP Auth RFC], and involves send a header that
//! contains a signature of some shared keying material extracted from TLS ([RFC 5705]).
//!
//! The second way can save a full round trip, because the challenge doesn't have to be sent to the client
//! first, however, it won't always work, as it relies on the keying material extraction feature of TLS,
//! which is not available in browsers (but might be in the future?) and might break when there's an
//! HTTPS proxy that doesn't properly deal with this TLS feature.
//!
//! [Concealed HTTP Auth RFC]: https://datatracker.ietf.org/doc/rfc9729/
//! [RFC 5705]: https://datatracker.ietf.org/doc/html/rfc5705
use bytes::{BufMut, Bytes, BytesMut};
use http::HeaderValue;
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
use snafu::{Backtrace, ResultExt, Snafu};
use tracing::trace;

use super::{
    common::{FrameType, FrameTypeError},
    streams::BytesStreamSink,
};
use crate::ExportKeyingMaterial;

/// Authentication message from the client.
#[derive(derive_more::Debug, serde::Serialize)]
#[cfg_attr(feature = "server", derive(serde::Deserialize))]
#[cfg_attr(wasm_browser, allow(unused))]
pub(crate) struct KeyMaterialClientAuth {
    /// The client's public key
    pub(crate) public_key: PublicKey,
    /// A signature of (a hash of) extracted key material.
    #[serde(with = "serde_bytes")]
    pub(crate) signature: [u8; 64],
    /// Part of the extracted key material.
    ///
    /// Allows making sure we have the same underlying key material.
    pub(crate) key_material_suffix: [u8; 16],
}

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
/// Used when authentication via [`KeyMaterialClientAuth`] didn't work.
#[derive(derive_more::Debug, serde::Serialize)]
#[cfg_attr(feature = "server", derive(serde::Deserialize))]
pub(crate) struct ClientAuth {
    /// The client's public key, a.k.a. the `NodeId`
    pub(crate) public_key: PublicKey,
    /// A signature of (a hash of) the [`ServerChallenge`].
    ///
    /// This is what provides the authentication.
    #[serde(with = "serde_bytes")]
    pub(crate) signature: [u8; 64],
}

/// Confirmation of successful connection.
#[derive(derive_more::Debug, serde::Deserialize)]
#[cfg_attr(feature = "server", derive(serde::Serialize))]
pub(crate) struct ServerConfirmsAuth;

/// Denial of connection. The client couldn't be verified as authentic.
#[derive(derive_more::Debug, Clone, serde::Deserialize)]
#[cfg_attr(feature = "server", derive(serde::Serialize))]
pub(crate) struct ServerDeniesAuth {
    reason: String,
}

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
    #[snafu(display("Handshake timeout reached"))]
    Timeout { source: Elapsed },
    #[snafu(display("Handshake stream ended prematurely"))]
    UnexpectedEnd {},
    #[snafu(transparent)]
    FrameTypeError { source: FrameTypeError },
    #[snafu(display("The relay denied our authentication ({reason})"))]
    ServerDeniedAuth { reason: String },
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
    #[cfg(feature = "server")]
    /// Failed to deserialize client auth header
    ClientAuthHeaderInvalid { value: HeaderValue },
}

impl ServerChallenge {
    /// Generates a new challenge.
    #[cfg(feature = "server")]
    pub(crate) fn new(mut rng: impl RngCore + CryptoRng) -> Self {
        let mut challenge = [0u8; 16];
        rng.fill_bytes(&mut challenge);
        Self { challenge }
    }

    /// The actual message bytes to sign (and verify against) for this challenge.
    fn message_to_sign(&self) -> [u8; 32] {
        blake3::derive_key(
            "iroh-relay handshake v1 challenge signature",
            &self.challenge,
        )
    }
}

impl ClientAuth {
    /// Generates a signature for given challenge from the server.
    pub(crate) fn new(secret_key: &SecretKey, challenge: &ServerChallenge) -> Self {
        Self {
            public_key: secret_key.public(),
            signature: secret_key.sign(&challenge.message_to_sign()).to_bytes(),
        }
    }

    /// Verifies this client's authentication given the challenge this was sent in response to.
    #[cfg(feature = "server")]
    pub(crate) fn verify(&self, challenge: &ServerChallenge) -> bool {
        self.public_key
            .verify(
                &challenge.message_to_sign(),
                &Signature::from_bytes(&self.signature),
            )
            .is_ok()
    }
}

#[cfg_attr(wasm_browser, allow(unused))]
impl KeyMaterialClientAuth {
    /// Generates a client's authentication, similar to [`ClientAuth`], but by using TLS keying material
    /// instead of a received challenge.
    pub(crate) fn new(secret_key: &SecretKey, io: &impl ExportKeyingMaterial) -> Option<Self> {
        let public_key = secret_key.public();
        let key_material = io.export_keying_material(
            [0u8; 32],
            b"iroh-relay handshake v1",
            Some(secret_key.public().as_bytes()),
        )?;
        Some(Self {
            public_key,
            signature: secret_key.sign(&key_material[..16]).to_bytes(),
            key_material_suffix: key_material[16..].try_into().expect("split right"),
        })
    }

    /// Generate the base64url-nopad-encoded header value.
    pub(crate) fn into_header_value(self) -> HeaderValue {
        HeaderValue::from_str(
            &data_encoding::BASE64URL_NOPAD
                .encode(&postcard::to_allocvec(&self).expect("encoding never fails")),
        )
        .expect("BASE64URL_NOPAD encoding contained invisible ascii characters")
    }

    /// Verifies this client auth on the server side using the same key material.
    ///
    /// This might return false for a couple of reasons:
    /// 1. The exported keying material might not be the same between both ends of the TLS session
    ///    (e.g. there's an HTTPS proxy in between that doesn't think/care about the TLS keying material exporter).
    ///    This situation is detected when the key material suffix mismatches.
    /// 2. The signature itself doesn't verify.
    #[cfg(feature = "server")]
    pub(crate) fn verify(&self, io: &impl ExportKeyingMaterial) -> bool {
        let Some(key_material) = io.export_keying_material(
            [0u8; 32],
            b"iroh-relay handshake v1",
            Some(self.public_key.as_bytes()),
        ) else {
            return false;
        };

        key_material[16..] == self.key_material_suffix
            && self
                .public_key
                .verify(&key_material[..16], &Signature::from_bytes(&self.signature))
                .is_ok()
    }
}

/// Runs the client side of the handshake protocol.
///
/// See the module docs for details on the protocol.
/// This is already after having potentially transferred a [`KeyMaterialClientAuth`],
/// but before having received a response for whether that worked or not.
///
/// This requires access to the client's secret key to sign a challenge.
pub(crate) async fn clientside(
    io: &mut (impl BytesStreamSink + ExportKeyingMaterial),
    secret_key: &SecretKey,
) -> Result<ServerConfirmsAuth, Error> {
    let (tag, frame) = read_frame(
        io,
        &[ServerChallenge::TAG, ServerConfirmsAuth::TAG],
        time::Duration::from_secs(30),
    )
    .await?;

    let (tag, frame) = if tag == ServerChallenge::TAG {
        let challenge: ServerChallenge = deserialize_frame(frame)?;

        let client_info = ClientAuth::new(secret_key, &challenge);
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
            let denial: ServerDeniesAuth = deserialize_frame(frame)?;
            Err(ServerDeniedAuthSnafu {
                reason: denial.reason,
            }
            .build())
        }
        _ => unreachable!(),
    }
}

/// This represents successful authentication for the client with the `client_key` public key
/// via the authentication [`Mechanism`] `mechanism`.
///
/// You must call [`SuccessfulAuthentication::authorize`] to finish the protocol.
#[cfg(feature = "server")]
#[derive(Debug)]
#[must_use = "the protocol is not finished unless `authorize` is called"]
pub(crate) struct SuccessfulAuthentication {
    pub(crate) client_key: PublicKey,
    pub(crate) mechanism: Mechanism,
}

/// The mechanism that was used for authentication.
#[cfg(feature = "server")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mechanism {
    /// Authentication was performed by verifying a signature of a challenge we sent
    SignedChallenge,
    /// Authentication was performed by verifying a signature of shared extracted TLS keying material
    SignedKeyMaterial,
}

/// Runs the server side of the handshaking protocol.
///
/// See the module documentation for an overview of the handshaking protocol.
///
/// This takes `rng` to generate cryptographic randomness for the authentication challenge.
///
/// This also takes the `client_auth_header`, if present, to perform authentication without
/// requiring sending a challenge, saving a round-trip, if possible.
///
/// If this fails, the protocol falls back to doing a normal extra round trip with a challenge.
///
/// The return value [`SuccessfulAuthentication`] still needs to be resolved by calling
/// [`SuccessfulAuthentication::authorize`] to finish the whole authorization protocol
/// (otherwise the client won't be notified about auth success or failure).
#[cfg(feature = "server")]
pub(crate) async fn serverside(
    io: &mut (impl BytesStreamSink + ExportKeyingMaterial),
    client_auth_header: Option<HeaderValue>,
    rng: impl RngCore + CryptoRng,
) -> Result<SuccessfulAuthentication, Error> {
    if let Some(client_auth_header) = client_auth_header {
        let client_auth_bytes = data_encoding::BASE64URL_NOPAD
            .decode(client_auth_header.as_ref())
            .map_err(|_| {
                ClientAuthHeaderInvalidSnafu {
                    value: client_auth_header.clone(),
                }
                .build()
            })?;

        let client_auth: KeyMaterialClientAuth =
            postcard::from_bytes(&client_auth_bytes).map_err(|_| {
                ClientAuthHeaderInvalidSnafu {
                    value: client_auth_header.clone(),
                }
                .build()
            })?;

        if client_auth.verify(io) {
            trace!(?client_auth.public_key, "authentication succeeded via keying material");
            return Ok(SuccessfulAuthentication {
                client_key: client_auth.public_key,
                mechanism: Mechanism::SignedKeyMaterial,
            });
        }
    }

    let challenge = ServerChallenge::new(rng);
    write_frame(io, &challenge).await?;

    let (_, frame) = read_frame(io, &[ClientAuth::TAG], time::Duration::from_secs(10)).await?;
    let client_auth: ClientAuth = deserialize_frame(frame)?;

    if client_auth.verify(&challenge) {
        trace!(?client_auth.public_key, "authentication succeeded via challenge");
        Ok(SuccessfulAuthentication {
            client_key: client_auth.public_key,
            mechanism: Mechanism::SignedChallenge,
        })
    } else {
        trace!(?client_auth.public_key, "authentication failed");
        let denial = ServerDeniesAuth {
            reason: "signature invalid".into(),
        };
        write_frame(io, denial.clone()).await?;
        Err(ServerDeniedAuthSnafu {
            reason: denial.reason,
        }
        .build())
    }
}

#[cfg(feature = "server")]
impl SuccessfulAuthentication {
    pub async fn authorize_if(
        self,
        is_authorized: bool,
        io: &mut (impl BytesStreamSink + ExportKeyingMaterial),
    ) -> Result<PublicKey, Error> {
        if is_authorized {
            trace!("authorizing client");
            write_frame(io, ServerConfirmsAuth).await?;
            Ok(self.client_key)
        } else {
            trace!("denying client auth");
            let denial = ServerDeniesAuth {
                reason: "not authorized".into(),
            };
            write_frame(io, denial.clone()).await?;
            Err(ServerDeniedAuthSnafu {
                reason: denial.reason,
            }
            .build())
        }
    }
}

async fn write_frame<F: serde::Serialize + Frame>(
    io: &mut impl BytesStreamSink,
    frame: F,
) -> Result<(), Error> {
    let mut bytes = BytesMut::new();
    trace!(frame_type = %F::TAG, "Writing frame");
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
    let mut payload = time::timeout(timeout, io.try_next())
        .await
        .context(TimeoutSnafu)??
        .ok_or_else(|| UnexpectedEndSnafu.build())?;

    let frame_type = FrameType::from_bytes(&mut payload)?;
    trace!(%frame_type, "Reading frame");
    snafu::ensure!(
        expected_types.contains(&frame_type),
        UnexpectedFrameTypeSnafu {
            frame_type,
            expected_types: expected_types.to_vec()
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
    use iroh_base::{PublicKey, SecretKey};
    use n0_future::{Sink, SinkExt, Stream, TryStreamExt};
    use n0_snafu::{Result, ResultExt};
    use tokio_util::codec::{Framed, LengthDelimitedCodec};
    use tracing::{info_span, Instrument};
    use tracing_test::traced_test;

    use super::{
        ClientAuth, KeyMaterialClientAuth, Mechanism, ServerChallenge, ServerConfirmsAuth,
    };
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
        restricted_to: Option<PublicKey>,
    ) -> (Result<ServerConfirmsAuth>, Result<(PublicKey, Mechanism)>) {
        let (client, server) = tokio::io::duplex(1024);

        let mut client_io = Framed::new(client, LengthDelimitedCodec::new())
            .map_ok(BytesMut::freeze)
            .map_err(tokio_websockets::Error::Io)
            .sink_map_err(tokio_websockets::Error::Io)
            .with_shared_secret(client_shared_secret);
        let mut server_io = Framed::new(server, LengthDelimitedCodec::new())
            .map_ok(BytesMut::freeze)
            .map_err(tokio_websockets::Error::Io)
            .sink_map_err(tokio_websockets::Error::Io)
            .with_shared_secret(server_shared_secret);

        let client_auth_header = KeyMaterialClientAuth::new(secret_key, &client_io)
            .map(KeyMaterialClientAuth::into_header_value);

        n0_future::future::zip(
            async {
                super::clientside(&mut client_io, secret_key)
                    .await
                    .context("clientside")
            }
            .instrument(info_span!("clientside")),
            async {
                let auth_n =
                    super::serverside(&mut server_io, client_auth_header, rand::rngs::OsRng)
                        .await
                        .context("serverside")?;
                let mechanism = auth_n.mechanism;
                let is_authorized = restricted_to.is_none_or(|key| key == auth_n.client_key);
                let key = auth_n.authorize_if(is_authorized, &mut server_io).await?;
                Ok((key, mechanism))
            }
            .instrument(info_span!("serverside")),
        )
        .await
    }

    #[tokio::test]
    #[traced_test]
    async fn test_handshake_via_shared_secrets() -> Result {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        let (client, server) = simulate_handshake(&secret_key, Some(42), Some(42), None).await;
        client?;
        let (public_key, auth) = server?;
        assert_eq!(public_key, secret_key.public());
        assert_eq!(auth, Mechanism::SignedKeyMaterial); // it got verified via shared key material
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_handshake_via_challenge() -> Result {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        let (client, server) = simulate_handshake(&secret_key, None, None, None).await;
        client?;
        let (public_key, auth) = server?;
        assert_eq!(public_key, secret_key.public());
        assert_eq!(auth, Mechanism::SignedChallenge);
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_handshake_mismatching_shared_secrets() -> Result {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        // mismatching shared secrets *might* happen with HTTPS proxies that don't also middle-man the shared secret
        let (client, server) = simulate_handshake(&secret_key, Some(10), Some(99), None).await;
        client?;
        let (public_key, auth) = server?;
        assert_eq!(public_key, secret_key.public());
        assert_eq!(auth, Mechanism::SignedChallenge);
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_handshake_challenge_fallback() -> Result {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        // clients might not have access to shared secrets
        let (client, server) = simulate_handshake(&secret_key, None, Some(99), None).await;
        client?;
        let (public_key, auth) = server?;
        assert_eq!(public_key, secret_key.public());
        assert_eq!(auth, Mechanism::SignedChallenge);
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_handshake_with_auth_positive() -> Result {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        let public_key = secret_key.public();
        let (client, server) = simulate_handshake(&secret_key, None, None, Some(public_key)).await;
        client?;
        let (public_key, _) = server?;
        assert_eq!(public_key, secret_key.public());
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_handshake_with_auth_negative() -> Result {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        let public_key = secret_key.public();
        let wrong_secret_key = SecretKey::generate(rand::rngs::OsRng);
        let (client, server) =
            simulate_handshake(&wrong_secret_key, None, None, Some(public_key)).await;
        assert!(client.is_err());
        assert!(server.is_err());
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_handshake_via_shared_secret_with_auth_negative() -> Result {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        let public_key = secret_key.public();
        let wrong_secret_key = SecretKey::generate(rand::rngs::OsRng);
        let (client, server) =
            simulate_handshake(&wrong_secret_key, Some(42), Some(42), Some(public_key)).await;
        assert!(client.is_err());
        assert!(server.is_err());
        Ok(())
    }

    #[test]
    fn test_client_auth_roundtrip() -> Result {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        let challenge = ServerChallenge::new(rand::rngs::OsRng);
        let client_auth = ClientAuth::new(&secret_key, &challenge);

        let bytes = postcard::to_allocvec(&client_auth).e()?;
        let decoded: ClientAuth = postcard::from_bytes(&bytes).e()?;

        assert_eq!(client_auth.public_key, decoded.public_key);
        assert_eq!(client_auth.signature, decoded.signature);

        Ok(())
    }

    #[test]
    fn test_km_client_auth_roundtrip() -> Result {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        let client_auth = KeyMaterialClientAuth::new(
            &secret_key,
            &TestKeyingMaterial {
                inner: (),
                shared_secret: Some(42),
            },
        )
        .e()?;

        let bytes = postcard::to_allocvec(&client_auth).e()?;
        let decoded: KeyMaterialClientAuth = postcard::from_bytes(&bytes).e()?;

        assert_eq!(client_auth.public_key, decoded.public_key);
        assert_eq!(client_auth.signature, decoded.signature);

        Ok(())
    }

    #[test]
    fn test_challenge_verification() -> Result {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        let challenge = ServerChallenge::new(rand::rngs::OsRng);
        let client_auth = ClientAuth::new(&secret_key, &challenge);
        assert!(client_auth.verify(&challenge));

        Ok(())
    }

    #[test]
    fn test_key_material_verification() -> Result {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        let io = TestKeyingMaterial {
            inner: (),
            shared_secret: Some(42),
        };
        let client_auth = KeyMaterialClientAuth::new(&secret_key, &io).e()?;
        assert!(client_auth.verify(&io));

        Ok(())
    }
}
