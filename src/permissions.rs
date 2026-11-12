use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use mc_authz::Permissions;
use mc_db::repos::playlists::PlaylistRecord;
use mc_db::repos::roles;
use mc_db::repos::users;
use mc_db::repos::{audit, permissions};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::{self, AuthUser};
use crate::authz;
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Clone, Debug, Serialize)]
pub struct OverwriteDto {
    pub resource_type: String,
    pub resource_id: Uuid,
    pub target_type: String,
    pub target_id: Uuid,
    pub allow: u64,
    pub deny: u64,
}

impl From<&permissions::OverwriteRecord> for OverwriteDto {
    fn from(record: &permissions::OverwriteRecord) -> Self {
        Self {
            resource_type: record.resource_type.clone(),
            resource_id: record.resource_id,
            target_type: record.target_type.clone(),
            target_id: record.target_id,
            allow: u64::try_from(record.allow.max(0)).unwrap_or(0),
            deny: u64::try_from(record.deny.max(0)).unwrap_or(0),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SetOverwriteRequest {
    #[serde(default)]
    pub allow: u64,
    #[serde(default)]
    pub deny: u64,
}

pub async fn library_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<OverwriteDto>>, ApiError> {
    auth::require_permission(&state, &headers, Permissions::MANAGE_LIBRARIES).await?;
    ensure_library(&state, id).await?;

    let records = permissions::list_for_resource(&state.pool, "library", id).await?;
    Ok(Json(records.iter().map(OverwriteDto::from).collect()))
}

pub async fn library_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, target_type, target_id)): Path<(Uuid, String, Uuid)>,
    Json(request): Json<SetOverwriteRequest>,
) -> Result<Json<OverwriteDto>, ApiError> {
    let actor = auth::require_permission(&state, &headers, Permissions::MANAGE_LIBRARIES).await?;
    ensure_library(&state, id).await?;
    validate_target(&state, &target_type, target_id).await?;
    let (allow, deny) = validate_bits(
        &actor,
        Permissions::LIBRARY_BITS,
        request.allow,
        request.deny,
    )?;

    let record = permissions::upsert(
        &state.pool,
        "library",
        id,
        &target_type,
        target_id,
        allow,
        deny,
    )
    .await?;

    audit::log(
        &state.pool,
        Some(actor.id),
        "permissions.library.set",
        "library",
        Some(id),
        json!({ "target_type": target_type, "target_id": target_id, "allow": allow, "deny": deny }),
    )
    .await?;

    Ok(Json(OverwriteDto::from(&record)))
}

pub async fn library_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, target_type, target_id)): Path<(Uuid, String, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let actor = auth::require_permission(&state, &headers, Permissions::MANAGE_LIBRARIES).await?;
    ensure_library(&state, id).await?;
    validate_target(&state, &target_type, target_id).await?;

    if !permissions::delete(&state.pool, "library", id, &target_type, target_id).await? {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "permission overwrite not found",
        ));
    }

    audit::log(
        &state.pool,
        Some(actor.id),
        "permissions.library.delete",
        "library",
        Some(id),
        json!({ "target_type": target_type, "target_id": target_id }),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn playlist_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<OverwriteDto>>, ApiError> {
    let actor = auth::authenticate(&state, &headers).await?;
    let playlist = load_playlist(&state, &actor, id).await?;
    require_playlist_manage(&state, &actor, &playlist).await?;

    let records = permissions::list_for_resource(&state.pool, "playlist", id).await?;
    Ok(Json(records.iter().map(OverwriteDto::from).collect()))
}

pub async fn playlist_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, target_type, target_id)): Path<(Uuid, String, Uuid)>,
    Json(request): Json<SetOverwriteRequest>,
) -> Result<Json<OverwriteDto>, ApiError> {
    let actor = auth::authenticate(&state, &headers).await?;
    let playlist = load_playlist(&state, &actor, id).await?;
    require_playlist_manage(&state, &actor, &playlist).await?;
    validate_target(&state, &target_type, target_id).await?;
    let (allow, deny) = validate_bits(
        &actor,
        Permissions::PLAYLIST_BITS,
        request.allow,
        request.deny,
    )?;

    let record = permissions::upsert(
        &state.pool,
        "playlist",
        id,
        &target_type,
        target_id,
        allow,
        deny,
    )
    .await?;

    audit::log(
        &state.pool,
        Some(actor.id),
        "permissions.playlist.set",
        "playlist",
        Some(id),
        json!({ "target_type": target_type, "target_id": target_id, "allow": allow, "deny": deny }),
    )
    .await?;

    Ok(Json(OverwriteDto::from(&record)))
}

pub async fn playlist_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, target_type, target_id)): Path<(Uuid, String, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let actor = auth::authenticate(&state, &headers).await?;
    let playlist = load_playlist(&state, &actor, id).await?;
    require_playlist_manage(&state, &actor, &playlist).await?;
    validate_target(&state, &target_type, target_id).await?;

    if !permissions::delete(&state.pool, "playlist", id, &target_type, target_id).await? {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "permission overwrite not found",
        ));
    }

    audit::log(
        &state.pool,
        Some(actor.id),
        "permissions.playlist.delete",
        "playlist",
        Some(id),
        json!({ "target_type": target_type, "target_id": target_id }),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn ensure_library(state: &AppState, id: Uuid) -> Result<(), ApiError> {
    if mc_db::repos::libraries::get(&state.pool, id)
        .await?
        .is_none()
    {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "library not found"));
    }
    Ok(())
}

async fn validate_target(
    state: &AppState,
    target_type: &str,
    target_id: Uuid,
) -> Result<(), ApiError> {
    match target_type {
        "role" => {
            if roles::get(&state.pool, target_id).await?.is_none() {
                return Err(ApiError::new(StatusCode::NOT_FOUND, "role not found"));
            }
        }
        "user" => {
            if users::get(&state.pool, target_id).await?.is_none() {
                return Err(ApiError::new(StatusCode::NOT_FOUND, "user not found"));
            }
        }
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "target_type must be role or user",
            ))
        }
    }

    Ok(())
}

fn validate_bits(
    actor: &AuthUser,
    allowed_bits: Permissions,
    allow: u64,
    deny: u64,
) -> Result<(i64, i64), ApiError> {
    let allow = Permissions::from_bits(allow);
    let deny = Permissions::from_bits(deny);

    if allow.bits() != 0 && allow.difference(allowed_bits).bits() != 0 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "allow contains bits outside this resource",
        ));
    }
    if deny.bits() != 0 && deny.difference(allowed_bits).bits() != 0 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "deny contains bits outside this resource",
        ));
    }
    if allow.intersects(deny) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "allow and deny must not overlap",
        ));
    }

    if !actor.is_admin() {
        let actor_bits = actor
            .authz
            .libraries
            .iter()
            .fold(actor.authz.server, |current, library| {
                current.union(library.permissions)
            });
        if !allow.difference(actor_bits).is_empty() {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "cannot grant permissions you do not have",
            ));
        }
    }

    Ok((
        i64::try_from(allow.bits()).unwrap_or(i64::MAX),
        i64::try_from(deny.bits()).unwrap_or(i64::MAX),
    ))
}

async fn load_playlist(
    state: &AppState,
    actor: &AuthUser,
    id: Uuid,
) -> Result<PlaylistRecord, ApiError> {
    let visible = actor.visible_library_ids();
    let detail = mc_db::repos::playlists::get(&state.pool, id, &visible)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "playlist not found"))?;
    Ok(detail.playlist)
}

async fn require_playlist_manage(
    state: &AppState,
    actor: &AuthUser,
    playlist: &PlaylistRecord,
) -> Result<(), ApiError> {
    let overwrites = authz::playlist_overwrites(&state.pool, &actor.authz).await?;
    let records = overwrites.get(&playlist.id).map_or(&[][..], Vec::as_slice);
    let permissions = authz::resolve_playlist(&actor.authz, playlist, records);

    if permissions.contains(Permissions::PLAYLIST_MANAGE) {
        Ok(())
    } else {
        Err(ApiError::new(StatusCode::FORBIDDEN, "permission denied"))
    }
}
