use std::path::Path as FsPath;

use axum::body::Body;

use axum::extract::{Path, Query, State};
use axum::http::header::{
    ACCEPT_RANGES, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE,
    ETAG, IF_NONE_MATCH, RANGE,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use mc_authz::Permissions;
use mc_db::repos::catalog;
use mc_db::repos::libraries::{self, LibraryRecord};
use mc_storage::{Delivery, Key};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::auth::{self, AuthUser};
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct AlbumsQuery {
    pub artist_id: Option<Uuid>,
    #[serde(default)]
    pub library_id: Option<Uuid>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
    #[serde(default)]
    pub sort: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ArtistsQuery {
    #[serde(default)]
    pub library_id: Option<Uuid>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
pub struct TracksQuery {
    #[serde(default)]
    pub library_id: Option<Uuid>,
    #[serde(default)]
    pub genre_id: Option<Uuid>,
    #[serde(default)]
    pub missing_artwork: bool,
    #[serde(default)]
    pub missing_year: bool,
    #[serde(default)]
    pub mine: bool,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
pub struct GenresQuery {
    #[serde(default)]
    pub library_id: Option<Uuid>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ArtworkQuery {
    #[serde(default)]
    pub size: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct ArtistTracksQuery {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
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
    Query(query): Query<ArtistsQuery>,
) -> Result<Response, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let visible = user.visible_library_ids();
    let limit = query.limit.map(|value| value.clamp(1, 500));
    let offset = query.offset.unwrap_or(0).max(0);
    let total = catalog::count_artists(&state.pool, &visible, query.library_id).await?;
    let artists =
        catalog::list_artists_page(&state.pool, &visible, query.library_id, limit, offset).await?;

    Ok(paginated(artists, total, limit, offset))
}

pub async fn albums(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AlbumsQuery>,
) -> Result<Response, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let visible = user.visible_library_ids();
    let limit = query.limit.map(|value| value.clamp(1, 500));
    let offset = query.offset.unwrap_or(0).max(0);
    let sort = match query.sort.as_deref().unwrap_or("artist") {
        "name" | "artist" | "year" => query.sort.as_deref().unwrap_or("artist"),
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "sort must be name, artist or year",
            ))
        }
    };
    let total =
        catalog::count_albums(&state.pool, query.artist_id, &visible, query.library_id).await?;
    let albums = catalog::list_albums_page(
        &state.pool,
        query.artist_id,
        query.library_id,
        &visible,
        limit,
        offset,
        sort,
    )
    .await?;

    Ok(paginated(albums, total, limit, offset))
}

pub async fn tracks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TracksQuery>,
) -> Result<Response, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let visible = user.visible_library_ids();
    let limit = query.limit.map(|value| value.clamp(1, 500));
    let offset = query.offset.unwrap_or(0).max(0);
    let filters = catalog::TrackFilters {
        library_id: query.library_id,
        genre_id: query.genre_id,
        missing_artwork: query.missing_artwork,
        missing_year: query.missing_year,
        uploaded_by: query.mine.then_some(user.id),
    };
    let total = catalog::count_tracks(&state.pool, &visible, filters).await?;
    let tracks = catalog::list_tracks_page(&state.pool, &visible, filters, limit, offset).await?;

    Ok(paginated(tracks, total, limit, offset))
}

pub async fn genres(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<GenresQuery>,
) -> Result<Json<Vec<catalog::GenreSummary>>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let visible = user.visible_library_ids();

    Ok(Json(
        catalog::list_genres(&state.pool, &visible, query.library_id).await?,
    ))
}

pub async fn artist_tracks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Query(query): Query<ArtistTracksQuery>,
) -> Result<Json<Vec<catalog::TrackSummary>>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let visible = user.visible_library_ids();
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let offset = query.offset.unwrap_or(0).max(0);

    Ok(Json(
        catalog::list_artist_tracks_page(&state.pool, id, &visible, limit, offset).await?,
    ))
}

fn paginated<T: serde::Serialize>(
    items: T,
    total: i64,
    limit: Option<i64>,
    offset: i64,
) -> Response {
    let mut response = Json(items).into_response();
    response.headers_mut().insert(
        HeaderName::from_static("x-total-count"),
        HeaderValue::from_str(&total.to_string()).unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-offset"),
        HeaderValue::from_str(&offset.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    if let Some(limit) = limit {
        response.headers_mut().insert(
            HeaderName::from_static("x-limit"),
            HeaderValue::from_str(&limit.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("0")),
        );
    }

    response
}

pub async fn album_zip(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let visible = user.visible_library_ids();
    let album = catalog::get_album(&state.pool, id, &visible)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "album not found"))?;
    if album.tracks.is_empty() {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "album has no tracks"));
    }
    if !album
        .tracks
        .iter()
        .all(|track| user.can_library(track.library_id, Permissions::LIBRARY_DOWNLOAD))
    {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "permission denied"));
    }

    let registry = state.registry.read().await.clone();
    let mut entries = Vec::with_capacity(album.tracks.len());
    for track in &album.tracks {
        let storage = registry
            .storage_for_library(track.library_id)
            .ok_or_else(|| {
                ApiError::new(StatusCode::NOT_FOUND, "library storage is unavailable")
            })?;
        entries.push((track.title.clone(), track.file_key.clone(), storage));
    }

    let directory = state.staging_path.join("zips");
    tokio::fs::create_dir_all(&directory)
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ =
            tokio::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777)).await;
    }
    let path = directory.join(format!("{}-{}.zip", album.album.id, Uuid::now_v7()));
    let zip_path = path.clone();
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        use std::io::Write;

        let file = std::fs::File::create(&zip_path).map_err(|error| error.to_string())?;
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (index, (title, file_key, storage)) in entries.into_iter().enumerate() {
            let key = Key::new(file_key.as_str()).map_err(|error| error.to_string())?;
            let bytes = handle
                .block_on(storage.read(&key))
                .map_err(|error| error.to_string())?;
            let extension = FsPath::new(&file_key)
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or("bin");
            let name = format!(
                "{:02} {}.{}",
                index + 1,
                sanitize_zip_name(&title),
                extension
            );
            zip.start_file(name, options)
                .map_err(|error| error.to_string())?;
            zip.write_all(&bytes).map_err(|error| error.to_string())?;
        }
        zip.finish().map_err(|error| error.to_string())?;
        Ok(())
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?
    .map_err(ApiError::internal)?;

    let metadata = tokio::fs::metadata(&path)
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let cleanup = path.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        let _ = tokio::fs::remove_file(cleanup).await;
    });

    let mut response = Response::new(Body::from_stream(ReaderStream::new(file)));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/zip"));
    response.headers_mut().insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&metadata.len().to_string())
            .map_err(|_| ApiError::internal("invalid zip length"))?,
    );
    response.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&content_disposition(
            "album.zip",
            &format!("{} - {}", album.album.album_artist, album.album.title),
        ))
        .map_err(|_| ApiError::internal("invalid zip filename"))?,
    );

    Ok(response)
}

fn sanitize_zip_name(value: &str) -> String {
    let cleaned = value
        .chars()
        .map(|character| {
            if character.is_alphanumeric() || matches!(character, ' ' | '-' | '_' | '.' | '(' | ')')
            {
                character
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim()
        .to_owned();
    if cleaned.is_empty() {
        "track".to_owned()
    } else {
        cleaned
    }
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
    file_response(&state, &user, id, false, &headers).await
}

pub async fn download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    file_response(&state, &user, id, true, &headers).await
}

pub async fn artwork(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(album_id): Path<Uuid>,
    Query(query): Query<ArtworkQuery>,
) -> Result<Response, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let visible = user.visible_library_ids();

    let artwork = catalog::get_album_artwork(&state.pool, album_id, &visible)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "artwork not found"))?;
    let size = query.size.filter(|size| matches!(size, 96 | 300 | 600));
    let (mime, data, etag) = if let Some(size) = size {
        let cache_key = (album_id, size);
        let cached = state
            .artwork_cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&cache_key).cloned());
        if let Some((mime, data)) = cached {
            (mime, data, format!("\"{}-{size}\"", artwork.etag))
        } else {
            let source = image::load_from_memory(&artwork.data)
                .map_err(|_| ApiError::internal("invalid artwork image"))?;
            let resized = source.thumbnail(size, size);
            let mut cursor = std::io::Cursor::new(Vec::new());
            resized
                .write_to(&mut cursor, image::ImageFormat::WebP)
                .map_err(|_| ApiError::internal("encode artwork preview"))?;
            let data = cursor.into_inner();
            let mime = "image/webp".to_owned();
            if let Ok(mut cache) = state.artwork_cache.lock() {
                if cache.len() > 256 {
                    cache.clear();
                }
                cache.insert(cache_key, (mime.clone(), data.clone()));
            }
            (mime, data, format!("\"{}-{size}\"", artwork.etag))
        }
    } else {
        (artwork.mime, artwork.data, format!("\"{}\"", artwork.etag))
    };

    if headers
        .get(IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        == Some(etag.as_str())
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        response.headers_mut().insert(
            ETAG,
            HeaderValue::from_str(&etag).map_err(|_| ApiError::internal("invalid artwork etag"))?,
        );
        return Ok(response);
    }

    let mut response = data.into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&mime).map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "invalid artwork type")
        })?,
    );
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=86400"),
    );
    response.headers_mut().insert(
        ETAG,
        HeaderValue::from_str(&etag).map_err(|_| ApiError::internal("invalid artwork etag"))?,
    );

    Ok(response)
}

async fn file_response(
    state: &AppState,
    user: &AuthUser,
    track_id: Uuid,
    download: bool,
    headers: &HeaderMap,
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
            let requested = parse_range(
                headers.get(RANGE).and_then(|value| value.to_str().ok()),
                u64::try_from(track.size.max(0)).unwrap_or(0),
            )?;
            stream_range(storage, key, &track, requested, download).await
        }
    }
}

fn parse_range(header: Option<&str>, size: u64) -> Result<Option<(u64, u64)>, ApiError> {
    let Some(header) = header else {
        return Ok(None);
    };
    let Some(value) = header.strip_prefix("bytes=") else {
        return Err(range_not_satisfiable());
    };
    if value.contains(',') {
        return Err(range_not_satisfiable());
    }
    let Some((start, end)) = value.split_once('-') else {
        return Err(range_not_satisfiable());
    };

    if start.is_empty() {
        let suffix = end.parse::<u64>().map_err(|_| range_not_satisfiable())?;
        if suffix == 0 || size == 0 {
            return Err(range_not_satisfiable());
        }
        let start = size.saturating_sub(suffix);
        return Ok(Some((start, size - 1)));
    }

    let start = start.parse::<u64>().map_err(|_| range_not_satisfiable())?;
    if start >= size {
        return Err(range_not_satisfiable());
    }

    let end = if end.is_empty() {
        size - 1
    } else {
        end.parse::<u64>()
            .map_err(|_| range_not_satisfiable())?
            .min(size - 1)
    };

    if end < start {
        return Err(range_not_satisfiable());
    }

    Ok(Some((start, end)))
}

async fn stream_range(
    storage: std::sync::Arc<dyn mc_storage::Storage>,
    key: Key,
    track: &catalog::TrackDetail,
    requested: Option<(u64, u64)>,
    download: bool,
) -> Result<Response, ApiError> {
    let size = track.size.max(0) as u64;
    let (start, end, status) = match requested {
        Some((start, end)) => (start, end, StatusCode::PARTIAL_CONTENT),
        None if size > 0 => (0, size - 1, StatusCode::OK),
        None => (0, 0, StatusCode::OK),
    };
    let length = if size == 0 { 0 } else { end - start + 1 };

    let body = if size == 0 {
        Body::empty()
    } else if let Some(path) = storage.local_path(&key) {
        let mut file = tokio::fs::File::open(&path)
            .await
            .map_err(|error| ApiError::internal(format!("open media file: {error}")))?;
        if start > 0 {
            file.seek(SeekFrom::Start(start))
                .await
                .map_err(|error| ApiError::internal(format!("seek media file: {error}")))?;
        }
        Body::from_stream(ReaderStream::new(file.take(length)))
    } else {
        let data = storage
            .read_range(&key, start..end + 1)
            .await
            .map_err(ApiError::from)?;
        Body::from(data)
    };

    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    response.headers_mut().insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&length.to_string())
            .map_err(|_| ApiError::internal("invalid content length"))?,
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    if let Some(content_type) = content_type(track.format.as_deref(), &track.file_key) {
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_str(content_type)
                .map_err(|_| ApiError::internal("invalid content type"))?,
        );
    }
    if status == StatusCode::PARTIAL_CONTENT {
        response.headers_mut().insert(
            CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {start}-{end}/{size}"))
                .map_err(|_| ApiError::internal("invalid content range"))?,
        );
    }
    if download {
        set_download_headers(&mut response, &track.file_key, &track.title)?;
    }

    Ok(response)
}

fn content_type(format: Option<&str>, file_key: &str) -> Option<&'static str> {
    match format.map(str::to_ascii_lowercase).as_deref().or_else(|| {
        FsPath::new(file_key)
            .extension()
            .and_then(|value| value.to_str())
    }) {
        Some("mp3" | "mpeg") => Some("audio/mpeg"),
        Some("flac") => Some("audio/flac"),
        Some("ogg" | "oga") => Some("audio/ogg"),
        Some("opus") => Some("audio/opus"),
        Some("m4a" | "mp4" | "aac") => Some("audio/mp4"),
        Some("wav") => Some("audio/wav"),
        Some("aiff" | "aif") => Some("audio/aiff"),
        _ => Some("application/octet-stream"),
    }
}

fn range_not_satisfiable() -> ApiError {
    ApiError::new(StatusCode::RANGE_NOT_SATISFIABLE, "range not satisfiable")
}

fn set_download_headers(
    response: &mut Response,
    file_key: &str,
    title: &str,
) -> Result<(), ApiError> {
    response.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&content_disposition(file_key, title))
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "invalid filename"))?,
    );

    Ok(())
}

pub(crate) fn content_disposition(file_key: &str, title: &str) -> String {
    let fallback = download_filename(file_key, title);
    let extension = FsPath::new(file_key)
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!(".{value}"))
        .unwrap_or_default();
    let utf8 = format!("{title}{extension}");
    let encoded = form_urlencoded::byte_serialize(utf8.as_bytes())
        .collect::<String>()
        .replace('+', "%20");

    format!("attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}")
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
