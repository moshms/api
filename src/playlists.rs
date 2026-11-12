use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use mc_authz::Permissions;
use mc_db::repos::catalog;
use mc_db::repos::permissions;
use mc_db::repos::playlists::{self, PlaylistRecord};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::{self, AuthUser};
use crate::authz;
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct PlaylistDetailDto {
    pub playlist: PlaylistRecord,
    pub tracks: Vec<mc_db::repos::catalog::TrackSummary>,
    pub hidden_count: i64,
    pub permissions: u64,
}

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
    let visible = user.visible_library_ids();
    let all = playlists::list_with_counts(&state.pool, &visible).await?;
    let overwrites = authz::playlist_overwrites(&state.pool, &user.authz).await?;
    let mut result = Vec::new();

    for playlist in all {
        let records = overwrites.get(&playlist.id).map_or(&[][..], Vec::as_slice);
        let permissions = authz::resolve_playlist(&user.authz, &playlist, records);
        if permissions.can_view_playlist() {
            result.push(playlist);
        }
    }

    Ok(Json(result))
}

pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<PlaylistDetailDto>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    load_detail(&state, &user, id).await.map(Json)
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreatePlaylistRequest>,
) -> Result<(StatusCode, Json<PlaylistDetailDto>), ApiError> {
    let user = auth::require_permission(&state, &headers, Permissions::PLAYLIST_CREATE).await?;
    let name = validate_name(&request.name)?;
    let id = playlists::create(&state.pool, user.id, name, &[]).await?;
    let detail = load_detail(&state, &user, id).await?;

    Ok((StatusCode::CREATED, Json(detail)))
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdatePlaylistRequest>,
) -> Result<Json<PlaylistDetailDto>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let playlist = load_record(&state, &user, id).await?;
    let access = playlist_permissions(&state, &user, &playlist).await?;

    if !access.contains(Permissions::PLAYLIST_MANAGE) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "permission denied"));
    }

    let name = request.name.as_deref().map(validate_name).transpose()?;
    let updated = playlists::update(&state.pool, id, name, request.is_public, &[], &[]).await?;

    if !updated {
        return Err(playlist_not_found());
    }

    if let Some(is_public) = request.is_public {
        if is_public {
            permissions::upsert(
                &state.pool,
                "playlist",
                id,
                "role",
                user.authz.everyone_role_id,
                i64::try_from(Permissions::PLAYLIST_VIEW.bits()).unwrap_or(i64::MAX),
                0,
            )
            .await?;
        } else {
            permissions::delete(
                &state.pool,
                "playlist",
                id,
                "role",
                user.authz.everyone_role_id,
            )
            .await?;
        }
    }

    mc_db::repos::audit::log(
        &state.pool,
        Some(user.id),
        "playlist.update",
        "playlist",
        Some(id),
        json!({ "name": name, "is_public": request.is_public }),
    )
    .await?;

    load_detail(&state, &user, id).await.map(Json)
}

pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let playlist = load_record(&state, &user, id).await?;
    let access = playlist_permissions(&state, &user, &playlist).await?;

    if !access.contains(Permissions::PLAYLIST_MANAGE) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "permission denied"));
    }

    if !playlists::delete(&state.pool, id).await? {
        return Err(playlist_not_found());
    }

    mc_db::repos::audit::log(
        &state.pool,
        Some(user.id),
        "playlist.delete",
        "playlist",
        Some(id),
        json!({ "name": playlist.name }),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_track(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<AddTrackRequest>,
) -> Result<Json<PlaylistDetailDto>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let playlist = load_record(&state, &user, id).await?;
    let access = playlist_permissions(&state, &user, &playlist).await?;

    if !access.contains(Permissions::PLAYLIST_EDIT) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "permission denied"));
    }

    let visible = user.visible_library_ids();
    if catalog::get_track(&state.pool, request.track_id, &visible)
        .await?
        .is_none()
    {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "track not found"));
    }

    let updated = playlists::update(&state.pool, id, None, None, &[request.track_id], &[]).await?;

    if !updated {
        return Err(playlist_not_found());
    }

    load_detail(&state, &user, id).await.map(Json)
}

pub async fn remove_track(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, position)): Path<(Uuid, usize)>,
) -> Result<Json<PlaylistDetailDto>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let playlist = load_record(&state, &user, id).await?;
    let access = playlist_permissions(&state, &user, &playlist).await?;

    if !access.contains(Permissions::PLAYLIST_EDIT) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "permission denied"));
    }

    let updated = playlists::update(&state.pool, id, None, None, &[], &[position]).await?;

    if !updated {
        return Err(playlist_not_found());
    }

    load_detail(&state, &user, id).await.map(Json)
}

async fn load_detail(
    state: &AppState,
    user: &AuthUser,
    playlist_id: Uuid,
) -> Result<PlaylistDetailDto, ApiError> {
    let visible = user.visible_library_ids();
    let detail = playlists::get(&state.pool, playlist_id, &visible)
        .await?
        .ok_or_else(playlist_not_found)?;
    let access = playlist_permissions(state, user, &detail.playlist).await?;

    if !access.can_view_playlist() {
        return Err(playlist_not_found());
    }

    Ok(PlaylistDetailDto {
        playlist: detail.playlist,
        tracks: detail.tracks,
        hidden_count: detail.hidden_count,
        permissions: access.bits(),
    })
}

async fn load_record(
    state: &AppState,
    user: &AuthUser,
    playlist_id: Uuid,
) -> Result<PlaylistRecord, ApiError> {
    let visible = user.visible_library_ids();
    playlists::get(&state.pool, playlist_id, &visible)
        .await?
        .map(|detail| detail.playlist)
        .ok_or_else(playlist_not_found)
}

async fn playlist_permissions(
    state: &AppState,
    user: &AuthUser,
    playlist: &PlaylistRecord,
) -> Result<Permissions, ApiError> {
    let overwrites = authz::playlist_overwrites(&state.pool, &user.authz).await?;
    let records = overwrites.get(&playlist.id).map_or(&[][..], Vec::as_slice);
    Ok(authz::resolve_playlist(&user.authz, playlist, records))
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
