use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use mc_db::repos::catalog;
use mc_db::repos::playlists::{self, PlaylistDetail, PlaylistRecord};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth;
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CreatePlaylistRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePlaylistRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub is_public: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct AddTrackRequest {
    pub track_id: Uuid,
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PlaylistRecord>>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    Ok(Json(playlists::list(&state.pool, user.id).await?))
}

pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<PlaylistDetail>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    load_detail(&state, user.id, id).await.map(Json)
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreatePlaylistRequest>,
) -> Result<(StatusCode, Json<PlaylistDetail>), ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let name = validate_name(&request.name)?;
    let id = playlists::create(&state.pool, user.id, name, &[]).await?;
    let detail = load_detail(&state, user.id, id).await?;

    Ok((StatusCode::CREATED, Json(detail)))
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdatePlaylistRequest>,
) -> Result<Json<PlaylistDetail>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let name = request.name.as_deref().map(validate_name).transpose()?;

    let updated =
        playlists::update(&state.pool, user.id, id, name, request.is_public, &[], &[]).await?;

    if !updated {
        return Err(playlist_not_found());
    }

    load_detail(&state, user.id, id).await.map(Json)
}

pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;

    if playlists::delete(&state.pool, user.id, id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(playlist_not_found())
    }
}

pub async fn add_track(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<AddTrackRequest>,
) -> Result<Json<PlaylistDetail>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;

    if catalog::get_track(&state.pool, request.track_id)
        .await?
        .is_none()
    {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "track not found"));
    }

    let updated = playlists::update(
        &state.pool,
        user.id,
        id,
        None,
        None,
        &[request.track_id],
        &[],
    )
    .await?;

    if !updated {
        return Err(playlist_not_found());
    }

    load_detail(&state, user.id, id).await.map(Json)
}

pub async fn remove_track(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, position)): Path<(Uuid, usize)>,
) -> Result<Json<PlaylistDetail>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let updated = playlists::update(&state.pool, user.id, id, None, None, &[], &[position]).await?;

    if !updated {
        return Err(playlist_not_found());
    }

    load_detail(&state, user.id, id).await.map(Json)
}

async fn load_detail(
    state: &AppState,
    user_id: Uuid,
    playlist_id: Uuid,
) -> Result<PlaylistDetail, ApiError> {
    playlists::get(&state.pool, user_id, playlist_id)
        .await?
        .ok_or_else(playlist_not_found)
}

fn validate_name(value: &str) -> Result<&str, ApiError> {
    let value = value.trim();

    if value.is_empty() || value.chars().count() > 100 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "playlist name must be between 1 and 100 characters",
        ));
    }

    Ok(value)
}

fn playlist_not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "playlist not found")
}
