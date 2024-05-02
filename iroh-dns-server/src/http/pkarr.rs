use anyhow::Result;
use axum::extract::Path;
use axum::{extract::State, response::IntoResponse};
use bytes::Bytes;

use http::{header, StatusCode};

use tracing::info;

use crate::util::PublicKeyBytes;
use crate::{state::AppState, store::PacketSource};

use super::error::AppError;

pub async fn put(
    State(state): State<AppState>,
    Path(key): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    let key = pkarr::PublicKey::try_from(key.as_str())
        .map_err(|e| AppError::new(StatusCode::BAD_REQUEST, Some(format!("invalid key: {e}"))))?;
    let label = &key.to_z32()[..10];
    let signed_packet = pkarr::SignedPacket::from_relay_response(key, body).map_err(|e| {
        AppError::new(
            StatusCode::BAD_REQUEST,
            Some(format!("invalid body payload: {e}")),
        )
    })?;

    let updated = state
        .store
        .insert(signed_packet, PacketSource::PkarrPublish)
        .await?;
    info!(key = %label, ?updated, "pkarr upsert");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get(
    State(state): State<AppState>,
    Path(pubkey): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let pubkey = PublicKeyBytes::from_z32(&pubkey)
        .map_err(|e| AppError::new(StatusCode::BAD_REQUEST, Some(format!("invalid key: {e}"))))?;
    let signed_packet = state
        .store
        .get_signed_packet(&pubkey)
        .await?
        .ok_or_else(|| AppError::with_status(StatusCode::NOT_FOUND))?;
    let body = signed_packet.as_relay_request();
    let headers = [(header::CONTENT_TYPE, "application/x-pkarr-signed-packet")];
    Ok((headers, body))
}
