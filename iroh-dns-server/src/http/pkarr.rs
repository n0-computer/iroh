use anyhow::Result;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use bytes::Bytes;
use http::{header, StatusCode};
use tracing::info;

use super::error::AppError;
use crate::{state::AppState, store::PacketSource, util::PublicKeyBytes};

pub async fn put(
    State(state): State<AppState>,
    Path(key): Path<String>,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!("pkarr put");
    let key = pkarr::PublicKey::try_from(key.as_str())
        .map_err(|e| AppError::new(StatusCode::BAD_REQUEST, Some(format!("invalid key: {e}"))))?;
    tracing::debug!("pkarr put 1");
    let label = &key.to_z32()[..10];
    tracing::debug!("pkarr put 2");
    // let empty = Bytes::new();
    tracing::debug!("Received key: {:?}", key);
    let y = &body;
    println!("Reference body: {:?}", y);
    tracing::debug!("pkarr put 2.5");
    // let signed_packet_r = pkarr::SignedPacket::from_relay_payload(&key, &empty); // this works
    let signed_packet_r = pkarr::SignedPacket::from_relay_payload(key, &body); // this segfaults

    tracing::debug!("pkarr put 3");
    let signed_packet = signed_packet_r.map_err(|e| {
        AppError::new(
            StatusCode::BAD_REQUEST,
            Some(format!("invalid body payload: {e}")),
        )
    })?;
    tracing::debug!("pkarr put 4");

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
    let body = signed_packet.to_relay_payload();
    let headers = [(header::CONTENT_TYPE, "application/x-pkarr-signed-packet")];
    Ok((headers, body))
}
