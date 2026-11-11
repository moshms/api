use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use mc_db::repos::annotations::{self, ItemType};
use mc_db::repos::catalog::{self, AlbumSummary, ArtistSummary, TrackSummary};
use serde::Serialize;
use uuid::Uuid;

use crate::auth;
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct FavoritesResponse {
    pub tracks: Vec<TrackSummary>,
    pub albums: Vec<AlbumSummary>,
    pub artists: Vec<ArtistSummary>,
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<FavoritesResponse>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;

    Ok(Json(FavoritesResponse {
        tracks: catalog::starred_tracks(&state.pool, user.id).await?,
        albums: catalog::starred_albums(&state.pool, user.id).await?,
        artists: catalog::starred_artists(&state.pool, user.id).await?,
    }))
}

pub async fn star_track(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    star(&state, &headers, ItemType::Track, id).await
}

pub async fn unstar_track(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    unstar(&state, &headers, ItemType::Track, id).await
}

pub async fn star_album(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    star(&state, &headers, ItemType::Album, id).await
}

pub async fn unstar_album(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    unstar(&state, &headers, ItemType::Album, id).await
}

pub async fn star_artist(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    star(&state, &headers, ItemType::Artist, id).await
}

pub async fn unstar_artist(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    unstar(&state, &headers, ItemType::Artist, id).await
}

async fn star(
    state: &AppState,
    headers: &HeaderMap,
    item_type: ItemType,
    item_id: Uuid,
) -> Result<StatusCode, ApiError> {
    let user = auth::authenticate(state, headers).await?;

    let exists = match item_type {
        ItemType::Track => catalog::get_track(&state.pool, item_id).await?.is_some(),
        ItemType::Album => catalog::get_album(&state.pool, item_id).await?.is_some(),
        ItemType::Artist => catalog::get_artist(&state.pool, item_id).await?.is_some(),
    };

    if !exists {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "item not found"));
    }

    annotations::star(&state.pool, user.id, item_type, item_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn unstar(
    state: &AppState,
    headers: &HeaderMap,
    item_type: ItemType,
    item_id: Uuid,
) -> Result<StatusCode, ApiError> {
    let user = auth::authenticate(state, headers).await?;
    annotations::unstar(&state.pool, user.id, item_type, item_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
