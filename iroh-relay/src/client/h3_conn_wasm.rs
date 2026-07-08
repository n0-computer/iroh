//! Browser WebTransport client connection for the relay protocol.
//!
//! The browser counterpart to [`h3_conn`](super::h3_conn). The browser's native
//! WebTransport stack performs the QUIC and HTTP/3 handshake and the WebTransport
//! `CONNECT`, so all we do is open the session and run the relay handshake over
//! it. The browser cannot export TLS keying material, so authentication uses the
//! challenge-response path (see [`handshake`]).

use iroh_base::SecretKey;
use n0_error::{AnyError, anyerr, e, stack_error};
use url::Url;
use web_transport_wasm::ClientBuilder;

use crate::{
    http::{RELAY_PATH, RELAY_WT_MODE_QUERY_PARAM},
    protos::{h3_streams_wasm::WtBytesFramed, handshake},
    relay_map::WtTransferMode,
};

/// Errors establishing a browser WebTransport relay connection.
#[stack_error(derive, add_meta)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum H3ConnectError {
    /// The WebTransport session could not be opened. The concrete type is
    /// `web_transport_wasm::Error`; recover it via [`AnyError::downcast_ref`].
    #[error("WebTransport connect failed")]
    Connect { source: AnyError },
    #[error(transparent)]
    Handshake {
        #[error(from, std_err)]
        source: handshake::Error,
    },
}

/// Establish a relay connection over the browser's WebTransport.
///
/// `server_cert_hashes` supplies SHA-256 hashes of the relay's certificate for
/// connecting to a self-signed relay (as used in tests); when `None` the browser
/// validates against the system roots.
pub(crate) async fn connect_h3(
    url: &Url,
    server_cert_hashes: Option<Vec<Vec<u8>>>,
    secret_key: &SecretKey,
    transfer_mode: WtTransferMode,
) -> Result<WtBytesFramed, H3ConnectError> {
    let mut wt_url = url.clone();
    wt_url.set_path(RELAY_PATH);
    // Select the framing mode via a URL query parameter: a browser's WebTransport
    // CONNECT cannot carry custom headers, so the URL is the only channel to
    // negotiate it.
    wt_url
        .query_pairs_mut()
        .append_pair(RELAY_WT_MODE_QUERY_PARAM, transfer_mode.query_value());

    let client = match server_cert_hashes {
        Some(hashes) => ClientBuilder::new().with_server_certificate_hashes(hashes),
        None => ClientBuilder::new().with_system_roots(),
    };
    let session = client
        .connect(wt_url)
        .await
        .map_err(|err| e!(H3ConnectError::Connect, anyerr!("{err}")))?;

    // Run the relay handshake over per-message uni streams: the browser drops
    // datagrams the server sends before the session is fully established, so the
    // server's challenge would be lost. Switch to the negotiated framing for the
    // data phase.
    let mut io = WtBytesFramed::new(session, WtTransferMode::UniPerPacket);
    handshake::clientside(&mut io, secret_key).await?;
    io.set_transfer_mode(transfer_mode);
    Ok(io)
}
