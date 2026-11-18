use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::Engine;
use mc_authz::Permissions;
use mc_db::repos::catalog;
use mc_db::repos::tag_edits::{self, TagEditRecord};
use mc_media::TagChanges;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth;
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateTagEditRequest {
    pub track_ids: Vec<Uuid>,
    pub changes: TagChanges,
    #[serde(default)]
    pub artwork_base64: Option<String>,
    #[serde(default)]
    pub artwork_mime: Option<String>,
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateTagEditRequest>,
) -> Result<(StatusCode, Json<TagEditRecord>), ApiError> {
    let user = auth::authenticate(&state, &headers).await?;

    if !mc_jobs::is_worker_online(&state.pool, 30).await? {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "worker is offline",
        ));
    }

    if request.track_ids.is_empty() || request.track_ids.len() > 100 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "track_ids must contain between 1 and 100 tracks",
        ));
    }

    let artwork = match (
        request.artwork_base64.as_deref(),
        request.artwork_mime.as_deref(),
    ) {
        (Some(encoded), Some(mime)) => {
            if !mime.starts_with("image/") {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "artwork_mime must be an image type",
                ));
            }

            let data = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid artwork_base64"))?;

            if data.len() > 10 * 1024 * 1024 {
                return Err(ApiError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "artwork must be smaller than 10 MiB",
                ));
            }

            Some((mime.to_owned(), data))
        }
        (None, None) => None,
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "artwork_base64 and artwork_mime must be provided together",
            ))
        }
    };

    if let Some(year) = request.changes.year {
        if year != 0 && !(1000..=2100).contains(&year) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "year must be between 1000 and 2100",
            ));
        }
    }

    if request.changes.is_empty() && artwork.is_none() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "at least one tag change or artwork is required",
        ));
    }

    let visible = user.visible_library_ids();
    for track_id in &request.track_ids {
        let track = catalog::get_track(&state.pool, *track_id, &visible)
            .await?
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "track not found"))?;
        let can_edit = user.can_library(track.library_id, Permissions::LIBRARY_EDIT_TAGS);
        let own_upload = user.can_library(track.library_id, Permissions::LIBRARY_UPLOAD)
            && track.uploaded_by == Some(user.id);

        if !can_edit && !own_upload {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "permission denied"));
        }
    }

    let changes = serde_json::to_value(&request.changes)
        .map_err(|error| ApiError::new(StatusCode::BAD_REQUEST, error.to_string()))?;
    let edit = tag_edits::create(
        &state.pool,
        user.id,
        &request.track_ids,
        &changes,
        artwork.as_ref().map(|(mime, _)| mime.as_str()),
        artwork.as_ref().map(|(_, data)| data.as_slice()),
    )
    .await?;

    mc_jobs::enqueue(
        &state.pool,
        "writeback",
        serde_json::json!({ "tag_edit_id": edit.id }),
    )
    .await?;

    Ok((StatusCode::CREATED, Json(edit)))
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<TagEditRecord>>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let edits = if user.is_admin() {
        tag_edits::list(&state.pool, 100).await?
    } else {
        tag_edits::list_for_user(&state.pool, user.id, 100).await?
    };

    Ok(Json(edits))
}

pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<TagEditRecord>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let edit = tag_edits::get(&state.pool, id)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "tag edit not found"))?;

    if edit.user_id != user.id && !user.is_admin() {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "tag edit not found"));
    }

    Ok(Json(edit))
}
