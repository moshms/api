use std::path::Path as FsPath;

use axum::extract::{Path, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use mc_authz::Permissions;
use mc_db::repos::catalog;
use mc_db::repos::libraries::{self, LibraryRecord};
use mc_storage::{Delivery, Key};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{self, AuthUser};
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct AlbumsQuery {
    pub artist_id: Option<Uuid>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: String,
}

pub async fn libraries(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<LibraryRecord>>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let visible = user.visible_library_ids();
    let libraries = libraries::list(&state.pool)
        .await?
        .into_iter()
        .filter(|library| visible.contains(&library.id))
        .collect::<Vec<_>>();

    Ok(Json(libraries))
}

pub async fn artists(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<catalog::ArtistSummary>>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let visible = user.visible_library_ids();
    Ok(Json(catalog::list_artists(&state.pool, &visible).await?))
}

pub async fn albums(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AlbumsQuery>,
) -> Result<Json<Vec<catalog::AlbumSummary>>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let visible = user.visible_library_ids();
    Ok(Json(
        catalog::list_albums(&state.pool, query.artist_id, &visible).await?,
    ))
}

pub async fn album(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<catalog::AlbumDetail>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let visible = user.visible_library_ids();

    catalog::get_album(&state.pool, id, &visible)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "album not found"))
}

pub async fn track(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<catalog::TrackDetail>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let visible = user.visible_library_ids();

    catalog::get_track(&state.pool, id, &visible)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "track not found"))
}

pub async fn search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> Result<Json<catalog::SearchResults>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let visible = user.visible_library_ids();
    let query = query.q.trim();

    if query.is_empty() {
        return Ok(Json(catalog::SearchResults {
            artists: Vec::new(),
            albums: Vec::new(),
            tracks: Vec::new(),
        }));
    }

    Ok(Json(
        catalog::search(&state.pool, query, 20, &visible).await?,
    ))
}

pub async fn stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    file_response(&state, &user, id, false).await
}

pub async fn download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    file_response(&state, &user, id, true).await
}

pub async fn artwork(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(album_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let visible = user.visible_library_ids();

    let artwork = catalog::get_album_artwork(&state.pool, album_id, &visible)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "artwork not found"))?;

    let mut response = artwork.data.into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&artwork.mime).map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "invalid artwork type")
        })?,
    );
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );

    Ok(response)
}

async fn file_response(
    state: &AppState,
    user: &AuthUser,
    track_id: Uuid,
    download: bool,
) -> Result<Response, ApiError> {
    let visible = user.visible_library_ids();
    let track = catalog::get_track(&state.pool, track_id, &visible)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "track not found"))?;

    let permission = if download {
        Permissions::LIBRARY_DOWNLOAD
    } else {
        Permissions::LIBRARY_VIEW
    };
    if !user.can_library(track.library_id, permission) {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "track not found"));
    }

    let key = Key::new(track.file_key.as_str())?;
    let storage = state
        .registry
        .read()
        .await
        .storage_for_library(track.library_id)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "library storage is unavailable"))?;

    match storage.delivery(&key).await? {
        Delivery::NginxInternal(path) => {
            let mut response = StatusCode::OK.into_response();
            response.headers_mut().insert(
                HeaderName::from_static("x-accel-redirect"),
                HeaderValue::from_str(&path).map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "invalid delivery path")
                })?,
            );

            if download {
                set_download_headers(&mut response, &track.file_key, &track.title)?;
            }

            Ok(response)
        }
        Delivery::Presigned(url) => Ok(Redirect::temporary(&url).into_response()),
        Delivery::Stream => {
            let data = storage.read(&key).await?;
            let mut response = data.into_response();

            if download {
                set_download_headers(&mut response, &track.file_key, &track.title)?;
            }

            Ok(response)
        }
    }
}

fn set_download_headers(
    response: &mut Response,
    file_key: &str,
    title: &str,
) -> Result<(), ApiError> {
    let filename = download_filename(file_key, title);
    response.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "invalid filename"))?,
    );

    Ok(())
}

pub(crate) fn download_filename(file_key: &str, title: &str) -> String {
    let mut name = title
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || " ._-()".contains(character) {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    name = name.trim().to_owned();

    if name.is_empty() {
        name = "track".to_owned();
    }

    if let Some(extension) = FsPath::new(file_key)
        .extension()
        .and_then(|extension| extension.to_str())
    {
        name.push('.');
        name.push_str(extension);
    }

    name
}

#[cfg(test)]
mod tests {
    use super::download_filename;

    #[test]
    fn sanitizes_download_names() {
        assert_eq!(
            download_filename("Artist/Album/01 Song.flac", "01 Song / Live"),
            "01 Song _ Live.flac"
        );
        assert_eq!(download_filename("track.mp3", ""), "track.mp3");
    }
}
