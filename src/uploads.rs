use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::header::{CACHE_CONTROL, LOCATION};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use futures_util::StreamExt;
use mc_authz::Permissions;
use mc_core::{CoreError, Result};
use mc_db::repos::media_files;
use mc_db::repos::uploads::{self, UploadRecord};
use mc_db::repos::{libraries, storages};
use mc_scanner::ScanMode;
use mc_storage::Key;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::auth;
use crate::error::ApiError;
use crate::state::AppState;

const TUS_VERSION: &str = "1.0.0";
const UPLOAD_TTL_HOURS: i64 = 24;
const MAX_ACTIVE_UPLOADS: i64 = 20;

#[derive(Debug, Deserialize)]
pub struct CreateUploadQuery {
    pub library_id: Option<Uuid>,
}

pub async fn options(State(state): State<AppState>) -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    insert_tus_headers(&mut response, None, None, None);
    response.headers_mut().insert(
        HeaderName::from_static("tus-version"),
        HeaderValue::from_static(TUS_VERSION),
    );
    response.headers_mut().insert(
        HeaderName::from_static("tus-extension"),
        HeaderValue::from_static("creation,termination,expiration"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("tus-max-size"),
        HeaderValue::from_str(&state.max_upload_bytes.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );

    response
}

pub async fn create(
    State(state): State<AppState>,
    Query(query): Query<CreateUploadQuery>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;

    if header(&headers, "tus-resumable") != Some(TUS_VERSION) {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "unsupported tus version",
        ));
    }

    let size = header(&headers, "upload-length")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Upload-Length is required"))?;

    if size > state.max_upload_bytes {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "upload is too large",
        ));
    }

    if uploads::count_active_for_user(&state.pool, user.id).await? >= MAX_ACTIVE_UPLOADS {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many active uploads",
        ));
    }

    let library = resolve_library(&state, &user, query.library_id).await?;

    if !user.can_library(library.id, Permissions::LIBRARY_UPLOAD) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "upload permission required for this library",
        ));
    }

    let storage = storages::get(&state.pool, library.storage_id)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "library storage not found"))?;
    if storage.access != "rw" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "library storage is read-only",
        ));
    }

    if state
        .registry
        .read()
        .await
        .storage_for_library(library.id)
        .is_none()
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "library storage is unavailable",
        ));
    }

    let filename = metadata_filename(&headers).unwrap_or_else(|| "upload.bin".to_owned());
    let upload_id = Uuid::now_v7();
    let staging_key = format!("{upload_id}.part");
    let staging_path = state.staging_path.join(&staging_key);

    tokio::fs::File::create(&staging_path)
        .await
        .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    let upload = match uploads::create(
        &state.pool,
        user.id,
        library.id,
        &filename,
        i64::try_from(size).unwrap_or(i64::MAX),
        &staging_key,
    )
    .await
    {
        Ok(upload) => upload,
        Err(error) => {
            let _ = tokio::fs::remove_file(&staging_path).await;
            return Err(ApiError::from(error));
        }
    };

    let mut response = StatusCode::CREATED.into_response();
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(&format!("/tus/{}", upload.id))
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "invalid location"))?,
    );
    insert_tus_headers(
        &mut response,
        Some(0),
        Some(size),
        Some(&upload_expires(&upload.updated_at)),
    );

    Ok(response)
}

pub async fn head(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let upload = load_upload(&state, id).await?;
    authorize_upload(&user, &upload)?;

    let mut response = StatusCode::OK.into_response();
    insert_tus_headers(
        &mut response,
        Some(upload.offset.max(0) as u64),
        Some(upload.size.max(0) as u64),
        Some(&upload_expires(&upload.updated_at)),
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));

    Ok(response)
}

pub async fn patch(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;

    if !header(&headers, "content-type")
        .is_some_and(|value| value.starts_with("application/offset+octet-stream"))
    {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/offset+octet-stream",
        ));
    }

    let requested_offset = header(&headers, "upload-offset")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Upload-Offset is required"))?;

    let lock = upload_lock(&state, id);
    let _guard = lock.lock().await;
    let upload = load_upload(&state, id).await?;
    authorize_upload(&user, &upload)?;

    let size = upload.size.max(0) as u64;
    let offset = upload.offset.max(0) as u64;

    if upload.status == "complete" {
        let mut response = StatusCode::NO_CONTENT.into_response();
        insert_tus_headers(&mut response, Some(size), Some(size), None);
        return Ok(response);
    }

    if offset == size {
        if let Err(error) = complete_upload(&state, &upload).await {
            let _ =
                uploads::finish(&state.pool, upload.id, "failed", Some(&error.to_string())).await;
            return Err(ApiError::from(error));
        }

        let mut response = StatusCode::NO_CONTENT.into_response();
        insert_tus_headers(&mut response, Some(size), Some(size), None);
        return Ok(response);
    }

    if requested_offset != offset {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("upload offset mismatch: expected {offset}"),
        ));
    }

    let content_length = header(&headers, "content-length")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    if offset == 0 && content_length == size {
        let library = libraries::get(&state.pool, upload.library_id)
            .await?
            .ok_or_else(|| CoreError::not_found("library", upload.library_id))?;
        let storage = state
            .registry
            .read()
            .await
            .storage_for_library(library.id)
            .ok_or_else(|| CoreError::Unavailable("library storage is unavailable".to_owned()))?;

        if storage.local_path(&Key::root()).is_none() {
            let filename = sanitize_filename(&upload.filename);
            let mut stream = body.into_data_stream();
            let first = stream
                .next()
                .await
                .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "empty upload body"))?
                .map_err(|error| {
                    ApiError::new(
                        StatusCode::BAD_REQUEST,
                        format!("read upload body: {error}"),
                    )
                })?;
            validate_audio_header(&filename, &first)?;
            let key = choose_upload_key(storage.as_ref(), &upload, &filename).await?;
            let counter = Arc::new(AtomicU64::new(0));
            let count = counter.clone();
            let mapped = futures_util::stream::once(async move { Ok::<_, CoreError>(first) })
                .chain(stream.map(move |item| {
                    item.map_err(|error| {
                        CoreError::Unavailable(format!("read upload body: {error}"))
                    })
                }))
                .map(move |item| {
                    if let Ok(bytes) = &item {
                        count.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                    }
                    item
                });
            storage.write_stream(&key, Box::pin(mapped)).await?;
            if counter.load(Ordering::Relaxed) != size {
                let _ = storage.delete(&key).await;
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "upload body size does not match Upload-Length",
                ));
            }
            let _ = tokio::fs::remove_file(state.staging_path.join(&upload.staging_key)).await;
            uploads::update_offset(
                &state.pool,
                upload.id,
                i64::try_from(size).unwrap_or(i64::MAX),
            )
            .await?;
            finish_direct(&state, &upload, library, storage, key).await?;

            let mut response = StatusCode::NO_CONTENT.into_response();
            insert_tus_headers(&mut response, Some(size), Some(size), None);
            return Ok(response);
        }
    }

    let staging_path = state.staging_path.join(&upload.staging_key);
    let mut file = tokio::fs::OpenOptions::new()
        .append(true)
        .open(&staging_path)
        .await
        .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    let mut stream = body.into_data_stream();
    let mut written = 0_u64;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("read upload body: {error}"),
            )
        })?;

        if offset + written + chunk.len() as u64 > size {
            let _ = file.set_len(offset).await;
            return Err(ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "upload exceeds declared size",
            ));
        }

        file.write_all(&chunk)
            .await
            .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
        written += chunk.len() as u64;
    }

    file.flush()
        .await
        .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    drop(file);

    let new_offset = offset + written;

    if let Err(error) = uploads::update_offset(
        &state.pool,
        upload.id,
        i64::try_from(new_offset).unwrap_or(i64::MAX),
    )
    .await
    {
        if let Ok(file) = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&staging_path)
            .await
        {
            let _ = file.set_len(offset).await;
        }
        return Err(ApiError::from(error));
    }

    if new_offset == size {
        if let Err(error) = complete_upload(&state, &upload).await {
            let _ =
                uploads::finish(&state.pool, upload.id, "failed", Some(&error.to_string())).await;
            return Err(ApiError::from(error));
        }
    }

    let mut response = StatusCode::NO_CONTENT.into_response();
    insert_tus_headers(&mut response, Some(new_offset), Some(size), None);

    Ok(response)
}

pub async fn delete(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    let lock = upload_lock(&state, id);
    let _guard = lock.lock().await;
    let upload = load_upload(&state, id).await?;
    if upload.user_id != user.id && !user.is_admin() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "upload belongs to another user",
        ));
    }

    let staging_path = state.staging_path.join(&upload.staging_key);
    let _ = tokio::fs::remove_file(&staging_path).await;
    uploads::delete(&state.pool, id).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<axum::Json<Vec<UploadRecord>>, ApiError> {
    let user = auth::authenticate(&state, &headers).await?;
    Ok(axum::Json(
        uploads::list_for_user(&state.pool, user.id).await?,
    ))
}

async fn load_upload(state: &AppState, id: Uuid) -> Result<UploadRecord, ApiError> {
    uploads::get(&state.pool, id)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "upload not found"))
}

fn authorize_upload(user: &auth::AuthUser, upload: &UploadRecord) -> Result<(), ApiError> {
    if upload.user_id == user.id {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "upload belongs to another user",
        ))
    }
}

fn upload_lock(state: &AppState, id: Uuid) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = state.upload_locks.lock().expect("upload lock map poisoned");
    locks
        .entry(id)
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

async fn resolve_library(
    state: &AppState,
    user: &auth::AuthUser,
    library_id: Option<Uuid>,
) -> Result<mc_db::repos::libraries::LibraryRecord, ApiError> {
    if let Some(library_id) = library_id {
        return libraries::get(&state.pool, library_id)
            .await?
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "library not found"));
    }

    let visible = user.visible_library_ids();
    let libraries = libraries::list(&state.pool)
        .await?
        .into_iter()
        .filter(|library| visible.contains(&library.id))
        .collect::<Vec<_>>();

    libraries
        .iter()
        .find(|library| library.is_import_target)
        .or_else(|| libraries.first())
        .cloned()
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "no uploadable libraries configured"))
}

async fn complete_upload(state: &AppState, upload: &UploadRecord) -> Result<()> {
    let key = finalize(state, upload).await?;
    uploads::finish(&state.pool, upload.id, "complete", None).await?;

    let payload = serde_json::json!({
        "upload_id": upload.id,
        "library_id": upload.library_id,
        "source_key": key.as_str(),
        "filename": upload.filename,
    });

    if let Err(error) = mc_jobs::enqueue(&state.pool, "import", payload).await {
        tracing::warn!(%error, "failed to enqueue import job");
    }

    Ok(())
}

const AUDIO_EXTENSIONS: &[&str] = &[
    "aac", "aif", "aiff", "ape", "flac", "m4a", "mp3", "mp4", "oga", "ogg", "opus", "wav", "wma",
    "wv",
];

fn audio_extension(filename: &str) -> Result<String> {
    let extension = Path::new(filename)
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| CoreError::Validation("upload must have an audio extension".to_owned()))?;
    if !AUDIO_EXTENSIONS.contains(&extension.as_str()) {
        return Err(CoreError::Validation(format!(
            "unsupported audio extension: {extension}"
        )));
    }

    Ok(extension)
}

fn audio_header_matches(extension: &str, header: &[u8]) -> bool {
    match extension {
        "mp3" => {
            header.starts_with(b"ID3") || header.first().is_some_and(|byte| byte & 0xE0 == 0xE0)
        }
        "flac" => header.starts_with(b"fLaC"),
        "ogg" | "oga" | "opus" => header.starts_with(b"OggS"),
        "wav" => header.starts_with(b"RIFF") && header.get(8..12) == Some(b"WAVE"),
        "m4a" | "mp4" | "aac" => header.get(4..8) == Some(b"ftyp"),
        "wma" => header.starts_with(&[0x30, 0x26, 0xB2, 0x75]),
        "ape" => header.starts_with(b"MAC "),
        "aif" | "aiff" => header.starts_with(b"FORM"),
        "wv" => header.starts_with(b"wvpk"),
        _ => false,
    }
}

fn validate_audio_header(filename: &str, header: &[u8]) -> Result<()> {
    let extension = audio_extension(filename)?;
    if !audio_header_matches(&extension, header) {
        return Err(CoreError::Validation(
            "uploaded file does not match its audio format".to_owned(),
        ));
    }

    Ok(())
}

async fn validate_audio_file(path: &Path, filename: &str) -> Result<()> {
    let extension = audio_extension(filename)?;
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|error| CoreError::Unavailable(format!("open upload: {error}")))?;
    let mut header = [0u8; 16];
    let read = file
        .read(&mut header)
        .await
        .map_err(|error| CoreError::Unavailable(format!("read upload header: {error}")))?;
    if !audio_header_matches(&extension, &header[..read]) {
        return Err(CoreError::Validation(
            "uploaded file does not match its audio format".to_owned(),
        ));
    }

    Ok(())
}

async fn stream_staging(
    storage: &dyn mc_storage::Storage,
    key: &Key,
    staging_path: &Path,
) -> Result<()> {
    let file = tokio::fs::File::open(staging_path)
        .await
        .map_err(|error| CoreError::Unavailable(format!("open staging file: {error}")))?;
    let stream = ReaderStream::new(file).map(|result| {
        result.map_err(|error| CoreError::Unavailable(format!("read staging file: {error}")))
    });
    storage.write_stream(key, Box::pin(stream)).await?;

    Ok(())
}

async fn choose_upload_key(
    storage: &dyn mc_storage::Storage,
    upload: &UploadRecord,
    filename: &str,
) -> Result<Key> {
    let mut key = Key::new(format!("uploads/{}/{}", upload.user_id, filename))?;
    match storage.stat(&key).await {
        Ok(_) => {
            key = Key::new(format!(
                "uploads/{}/{}-{}",
                upload.user_id, upload.id, filename
            ))?;
        }
        Err(CoreError::NotFound { .. }) => {}
        Err(error) => return Err(error),
    }

    Ok(key)
}

fn spawn_upload_scan(
    state: &AppState,
    library: mc_db::repos::libraries::LibraryRecord,
    storage: Arc<dyn mc_storage::Storage>,
    key: Key,
    user_id: Uuid,
) {
    let scanner = state.scanner.clone();
    let pool = state.pool.clone();
    let library_id = library.id;
    let library_name = library.name.clone();
    let key_string = key.as_str().to_owned();
    let scan_mode = ScanMode::Paths(vec![key]);
    tokio::spawn(async move {
        match scanner.scan_library(&library, storage, scan_mode).await {
            Ok(stats) => {
                if let Err(error) =
                    media_files::set_uploaded_by(&pool, library_id, &key_string, user_id).await
                {
                    tracing::warn!(%error, "failed to record uploader on media file");
                }
                tracing::info!(library = %library_name, ?stats, "upload scan finished")
            }
            Err(error) => {
                tracing::error!(library = %library_name, %error, "upload scan failed")
            }
        }
    });
}

async fn finish_direct(
    state: &AppState,
    upload: &UploadRecord,
    library: mc_db::repos::libraries::LibraryRecord,
    storage: Arc<dyn mc_storage::Storage>,
    key: Key,
) -> Result<()> {
    uploads::finish(&state.pool, upload.id, "complete", None).await?;
    let payload = serde_json::json!({
        "upload_id": upload.id,
        "library_id": upload.library_id,
        "source_key": key.as_str(),
        "filename": upload.filename,
    });
    if let Err(error) = mc_jobs::enqueue(&state.pool, "import", payload).await {
        tracing::warn!(%error, "failed to enqueue import job");
    }
    spawn_upload_scan(state, library, storage, key, upload.user_id);

    Ok(())
}

async fn finalize(state: &AppState, upload: &UploadRecord) -> Result<Key> {
    let library = libraries::get(&state.pool, upload.library_id)
        .await?
        .ok_or_else(|| CoreError::not_found("library", upload.library_id))?;
    let storage = state
        .registry
        .read()
        .await
        .storage_for_library(library.id)
        .ok_or_else(|| CoreError::Unavailable("library storage is unavailable".to_owned()))?;

    let filename = sanitize_filename(&upload.filename);
    let staging_path = state.staging_path.join(&upload.staging_key);
    validate_audio_file(&staging_path, &filename).await?;
    let key = choose_upload_key(storage.as_ref(), upload, &filename).await?;

    if let Some(destination) = storage.local_path(&key) {
        if let Some(parent) = destination.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|error| {
                CoreError::Unavailable(format!("create upload directory: {error}"))
            })?;
        }

        if tokio::fs::rename(&staging_path, &destination)
            .await
            .is_err()
        {
            let result = stream_staging(storage.as_ref(), &key, &staging_path).await;
            let _ = tokio::fs::remove_file(&staging_path).await;
            result?;
        }
    } else {
        let result = stream_staging(storage.as_ref(), &key, &staging_path).await;
        let _ = tokio::fs::remove_file(&staging_path).await;
        result?;
    }

    spawn_upload_scan(state, library, storage, key.clone(), upload.user_id);

    Ok(key)
}

fn upload_expires(updated_at: &chrono::DateTime<chrono::Utc>) -> String {
    (*updated_at + chrono::Duration::hours(UPLOAD_TTL_HOURS))
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

fn insert_tus_headers(
    response: &mut Response,
    offset: Option<u64>,
    length: Option<u64>,
    expires: Option<&str>,
) {
    response.headers_mut().insert(
        HeaderName::from_static("tus-resumable"),
        HeaderValue::from_static(TUS_VERSION),
    );

    if let Some(offset) = offset {
        if let Ok(value) = HeaderValue::from_str(&offset.to_string()) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("upload-offset"), value);
        }
    }

    if let Some(length) = length {
        if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("upload-length"), value);
        }
    }

    if let Some(expires) = expires {
        if let Ok(value) = HeaderValue::from_str(expires) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("upload-expires"), value);
        }
    }
}

pub async fn cleanup_stale(state: &AppState) -> Result<()> {
    let stale = uploads::stale(&state.pool, UPLOAD_TTL_HOURS).await?;
    for upload in &stale {
        let path = state.staging_path.join(&upload.staging_key);
        let _ = tokio::fs::remove_file(&path).await;
        let _ = uploads::delete(&state.pool, upload.id).await;
    }
    if !stale.is_empty() {
        tracing::info!(count = stale.len(), "removed stale uploads");
    }

    Ok(())
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn metadata_filename(headers: &HeaderMap) -> Option<String> {
    let metadata = header(headers, "upload-metadata")?;

    for item in metadata.split(',') {
        let (key, value) = item.trim().split_once(' ')?;

        if key == "filename" {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(value)
                .ok()?;
            let name = String::from_utf8(bytes).ok()?;
            return Some(sanitize_filename(&name));
        }
    }

    None
}

fn sanitize_filename(value: &str) -> String {
    let name = Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("upload.bin");

    let sanitized = name
        .chars()
        .map(|character| {
            if character.is_control() || character == '/' || character == '\\' {
                '_'
            } else {
                character
            }
        })
        .collect::<String>();

    let trimmed = sanitized.trim().trim_matches('.').to_owned();

    if trimmed.is_empty() {
        "upload.bin".to_owned()
    } else {
        trimmed.chars().take(200).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_filename;

    #[test]
    fn sanitizes_upload_names() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("Artist/Album/Track.mp3"), "Track.mp3");
        assert_eq!(sanitize_filename(""), "upload.bin");
    }
}
