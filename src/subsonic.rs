use std::collections::{BTreeMap, HashMap};
use std::path::Path as FsPath;

use axum::body::Body;
use axum::extract::{RawQuery, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use mc_authz::Permissions;
use mc_core::{CoreError, Role};
use mc_db::repos::annotations::{self, ItemType};
use mc_db::repos::catalog::{self, AlbumSummary, ArtistSummary, TrackDetail, TrackSummary};
use mc_db::repos::playlists::{self, PlaylistRecord};
use mc_db::repos::{play_queue, users};
use mc_proto::transcoder::TranscodeChunk;
use mc_storage::{Delivery, Key};
use rand::seq::SliceRandom;
use serde_json::{json, Map, Value};
use subtle::ConstantTimeEq;
use tokio_stream::StreamExt;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::authz;
use crate::catalog::download_filename;
use crate::state::AppState;

const API_VERSION: &str = "1.16.1";
const CREATED: &str = "1970-01-01T00:00:00Z";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubsonicFormat {
    Json,
    Jsonp,
    Xml,
}

#[derive(Clone, Debug)]
struct SubsonicParams {
    values: HashMap<String, Vec<String>>,
}

impl SubsonicParams {
    fn from_raw(raw: Option<&str>) -> Self {
        let mut values: HashMap<String, Vec<String>> = HashMap::new();

        if let Some(raw) = raw {
            for (key, value) in form_urlencoded::parse(raw.as_bytes()) {
                values
                    .entry(key.into_owned())
                    .or_default()
                    .push(value.into_owned());
            }
        }

        Self { values }
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.values
            .get(key)
            .and_then(|values| values.first())
            .map(String::as_str)
    }

    fn get_all(&self, key: &str) -> impl Iterator<Item = &str> {
        self.values
            .get(key)
            .into_iter()
            .flatten()
            .map(String::as_str)
    }

    fn required(&self, key: &str) -> Result<&str, SubsonicError> {
        self.get(key).ok_or_else(|| SubsonicError::missing(key))
    }

    fn format(&self) -> SubsonicFormat {
        match self.get("f") {
            Some("json") => SubsonicFormat::Json,
            Some("jsonp") if self.get("callback").is_some() => SubsonicFormat::Jsonp,
            _ => SubsonicFormat::Xml,
        }
    }

    fn callback(&self) -> String {
        self.get("callback")
            .filter(|callback| {
                !callback.is_empty()
                    && callback.chars().all(|character| {
                        character.is_ascii_alphanumeric() || "_.$".contains(character)
                    })
            })
            .unwrap_or("callback")
            .to_owned()
    }
}

#[derive(Debug)]
struct SubsonicError {
    code: i32,
    message: String,
}

impl SubsonicError {
    fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn missing(parameter: &str) -> Self {
        Self::new(10, format!("Required parameter is missing: {parameter}"))
    }

    fn auth() -> Self {
        Self::new(40, "Wrong username or password")
    }

    fn not_found(entity: &str) -> Self {
        Self::new(70, format!("{entity} not found"))
    }

    fn forbidden() -> Self {
        Self::new(50, "Not authorized")
    }

    fn internal() -> Self {
        Self::new(0, "Internal server error")
    }
}

impl From<CoreError> for SubsonicError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::NotFound { .. } => Self::not_found("Item"),
            CoreError::Unauthorized => Self::auth(),
            CoreError::Forbidden => Self::new(50, "Not authorized"),
            CoreError::Validation(message) => Self::new(10, message),
            CoreError::Conflict(message) => Self::new(0, message),
            CoreError::Unavailable(message) => {
                tracing::error!(%message, "subsonic backend unavailable");
                Self::internal()
            }
            CoreError::Internal(message) => {
                tracing::error!(%message, "subsonic internal error");
                Self::internal()
            }
        }
    }
}

pub async fn ping(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, ping_inner(&state, &params).await)
}

pub async fn get_license(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, get_license_inner(&state, &params).await)
}

pub async fn get_music_folders(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, get_music_folders_inner(&state, &params).await)
}

pub async fn get_indexes(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, get_indexes_inner(&state, &params).await)
}

pub async fn get_artists(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, get_artists_inner(&state, &params).await)
}

pub async fn get_artist(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, get_artist_inner(&state, &params).await)
}

pub async fn get_album(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, get_album_inner(&state, &params).await)
}

pub async fn get_album_list2(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, get_album_list2_inner(&state, &params).await)
}

pub async fn get_song(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, get_song_inner(&state, &params).await)
}

pub async fn search3(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, search3_inner(&state, &params).await)
}

pub async fn stream(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    match stream_inner(&state, &params, false).await {
        Ok(response) => response,
        Err(error) => respond(&params, error_value(error)),
    }
}

pub async fn download(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    match stream_inner(&state, &params, true).await {
        Ok(response) => response,
        Err(error) => respond(&params, error_value(error)),
    }
}

pub async fn get_cover_art(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    match get_cover_art_inner(&state, &params).await {
        Ok(response) => response,
        Err(error) => respond(&params, error_value(error)),
    }
}

pub async fn star(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, star_inner(&state, &params, true).await)
}

pub async fn unstar(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, star_inner(&state, &params, false).await)
}

pub async fn scrobble(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, scrobble_inner(&state, &params).await)
}

pub async fn get_playlists(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, get_playlists_inner(&state, &params).await)
}

pub async fn get_playlist(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, get_playlist_inner(&state, &params).await)
}

pub async fn create_playlist(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, create_playlist_inner(&state, &params).await)
}

pub async fn update_playlist(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, update_playlist_inner(&state, &params).await)
}

pub async fn delete_playlist(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, delete_playlist_inner(&state, &params).await)
}

pub async fn get_play_queue(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, get_play_queue_inner(&state, &params).await)
}

pub async fn save_play_queue(State(state): State<AppState>, RawQuery(raw): RawQuery) -> Response {
    let params = SubsonicParams::from_raw(raw.as_deref());
    finish(&params, save_play_queue_inner(&state, &params).await)
}

async fn ping_inner(state: &AppState, params: &SubsonicParams) -> Result<Value, SubsonicError> {
    authenticate(state, params).await?;
    Ok(json!({}))
}

async fn get_license_inner(
    state: &AppState,
    params: &SubsonicParams,
) -> Result<Value, SubsonicError> {
    authenticate(state, params).await?;
    Ok(json!({ "license": { "valid": true } }))
}

async fn get_music_folders_inner(
    state: &AppState,
    params: &SubsonicParams,
) -> Result<Value, SubsonicError> {
    let user = authenticate(state, params).await?;
    let visible = user.visible_library_ids();
    let registry = state.registry.read().await;
    let folders = registry
        .libraries()
        .iter()
        .filter(|library| visible.contains(&library.id))
        .map(|library| {
            json!({
                "id": library.id.to_string(),
                "name": &library.name,
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({ "musicFolders": { "musicFolder": folders } }))
}

async fn get_indexes_inner(
    state: &AppState,
    params: &SubsonicParams,
) -> Result<Value, SubsonicError> {
    let user = authenticate(state, params).await?;
    let visible = user.visible_library_ids();
    let artists = catalog::list_artists(&state.pool, &visible).await?;

    Ok(json!({
        "indexes": {
            "lastModified": 0,
            "ignoredArticles": "",
            "index": artist_index(&artists),
        }
    }))
}

async fn get_artists_inner(
    state: &AppState,
    params: &SubsonicParams,
) -> Result<Value, SubsonicError> {
    let user = authenticate(state, params).await?;
    let visible = user.visible_library_ids();
    let artists = catalog::list_artists(&state.pool, &visible).await?;

    Ok(json!({
        "artists": {
            "ignoredArticles": "",
            "index": artist_index(&artists),
        }
    }))
}

async fn get_artist_inner(
    state: &AppState,
    params: &SubsonicParams,
) -> Result<Value, SubsonicError> {
    let user = authenticate(state, params).await?;
    let visible = user.visible_library_ids();
    let id = required_uuid(params, "id")?;
    let artist = catalog::get_artist(&state.pool, id, &visible)
        .await?
        .ok_or_else(|| SubsonicError::not_found("Artist"))?;
    let albums = artist.albums.iter().map(album_json).collect::<Vec<_>>();

    Ok(json!({
        "artist": {
            "id": artist.id.to_string(),
            "name": &artist.name,
            "albumCount": albums.len(),
            "album": albums,
        }
    }))
}

async fn get_album_inner(
    state: &AppState,
    params: &SubsonicParams,
) -> Result<Value, SubsonicError> {
    let user = authenticate(state, params).await?;
    let visible = user.visible_library_ids();
    let id = required_uuid(params, "id")?;
    let detail = catalog::get_album(&state.pool, id, &visible)
        .await?
        .ok_or_else(|| SubsonicError::not_found("Album"))?;
    let mut album = album_json(&detail.album);

    if let Value::Object(map) = &mut album {
        map.insert(
            "song".to_owned(),
            Value::Array(detail.tracks.iter().map(song_json).collect()),
        );
    }

    Ok(json!({ "album": album }))
}

async fn get_album_list2_inner(
    state: &AppState,
    params: &SubsonicParams,
) -> Result<Value, SubsonicError> {
    let user = authenticate(state, params).await?;
    let visible = user.visible_library_ids();
    let kind = params.get("type").unwrap_or("alphabeticalByName");
    let offset = param_usize(params, "offset", 0);
    let size = param_usize(params, "size", 10).clamp(1, 500);
    let mut albums = catalog::list_albums(&state.pool, None, &visible).await?;

    match kind {
        "newest" | "recent" => albums.sort_by(|left, right| {
            right
                .year
                .cmp(&left.year)
                .then_with(|| left.title.to_lowercase().cmp(&right.title.to_lowercase()))
        }),
        "alphabeticalByArtist" => albums.sort_by(|left, right| {
            left.album_artist
                .to_lowercase()
                .cmp(&right.album_artist.to_lowercase())
                .then_with(|| left.year.cmp(&right.year))
                .then_with(|| left.title.to_lowercase().cmp(&right.title.to_lowercase()))
        }),
        "random" => albums.shuffle(&mut rand::thread_rng()),
        _ => albums.sort_by_key(|album| album.title.to_lowercase()),
    }

    let selected = albums
        .iter()
        .skip(offset)
        .take(size)
        .map(album_json)
        .collect::<Vec<_>>();

    Ok(json!({ "albumList2": { "album": selected } }))
}

async fn get_song_inner(state: &AppState, params: &SubsonicParams) -> Result<Value, SubsonicError> {
    let user = authenticate(state, params).await?;
    let visible = user.visible_library_ids();
    let id = required_uuid(params, "id")?;
    let track = catalog::get_track(&state.pool, id, &visible)
        .await?
        .ok_or_else(|| SubsonicError::not_found("Song"))?;

    Ok(json!({ "song": song_detail_json(&track) }))
}

async fn search3_inner(state: &AppState, params: &SubsonicParams) -> Result<Value, SubsonicError> {
    let user = authenticate(state, params).await?;
    let visible = user.visible_library_ids();
    let query = params.required("query")?.trim();
    let artist_count = param_usize(params, "artistCount", 20).min(500);
    let album_count = param_usize(params, "albumCount", 20).min(500);
    let song_count = param_usize(params, "songCount", 20).min(500);

    if query.is_empty() {
        return Ok(json!({
            "searchResult3": {
                "artist": [],
                "album": [],
                "song": [],
            }
        }));
    }

    let limit = artist_count.max(album_count).max(song_count).max(1) as i64;
    let results = catalog::search(&state.pool, query, limit, &visible).await?;
    let artists = results
        .artists
        .iter()
        .take(artist_count)
        .map(artist_json)
        .collect::<Vec<_>>();
    let albums = results
        .albums
        .iter()
        .take(album_count)
        .map(album_json)
        .collect::<Vec<_>>();
    let songs = results
        .tracks
        .iter()
        .take(song_count)
        .map(song_json)
        .collect::<Vec<_>>();

    Ok(json!({
        "searchResult3": {
            "artist": artists,
            "album": albums,
            "song": songs,
        }
    }))
}

async fn stream_inner(
    state: &AppState,
    params: &SubsonicParams,
    download: bool,
) -> Result<Response, SubsonicError> {
    let user = authenticate(state, params).await?;
    let visible = user.visible_library_ids();
    let id = required_uuid(params, "id")?;
    let track = catalog::get_track(&state.pool, id, &visible)
        .await?
        .ok_or_else(|| SubsonicError::not_found("Song"))?;
    let permission = if download {
        Permissions::LIBRARY_DOWNLOAD
    } else {
        Permissions::LIBRARY_VIEW
    };
    if !user.can_library(track.library_id, permission) {
        return Err(SubsonicError::not_found("Song"));
    }
    let storage = state
        .registry
        .read()
        .await
        .storage_for_library(track.library_id)
        .ok_or_else(|| SubsonicError::not_found("Library storage"))?;
    let requested_format = params.get("format").filter(|value| !value.is_empty());
    let max_bitrate = params
        .get("maxBitRate")
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0);
    let needs_transcode = requested_format.is_some()
        || max_bitrate.is_some_and(|maximum| {
            track
                .bitrate
                .is_none_or(|bitrate| bitrate > i32::try_from(maximum).unwrap_or(i32::MAX))
        });

    if needs_transcode && storage.caps().local_path && user.can(Permissions::TRANSCODE) {
        if let Some(transcoder) = &state.transcoder {
            let format = requested_format.unwrap_or("mp3");
            let bitrate = max_bitrate.unwrap_or(128).clamp(32, 320);

            match transcoder.transcode(&track.file_key, format, bitrate).await {
                Ok(stream) => {
                    return transcoded_response(
                        stream,
                        format,
                        download,
                        &track.file_key,
                        &track.title,
                    )
                }
                Err(error) => {
                    tracing::warn!(%error, "transcoder unavailable, serving original");
                }
            }
        }
    }

    let key = Key::new(track.file_key.as_str())?;
    let suffix = file_suffix(&track.file_key);
    let content_type = content_type(&suffix);

    let mut response = match storage.delivery(&key).await? {
        Delivery::NginxInternal(path) => {
            let mut response = StatusCode::OK.into_response();
            response.headers_mut().insert(
                HeaderName::from_static("x-accel-redirect"),
                HeaderValue::from_str(&path).map_err(|_| SubsonicError::internal())?,
            );
            response
        }
        Delivery::Presigned(url) => Redirect::temporary(&url).into_response(),
        Delivery::Stream => storage.read(&key).await?.into_response(),
    };

    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_str(content_type).map_err(|_| SubsonicError::internal())?,
    );

    if download {
        let filename = download_filename(&track.file_key, &track.title);
        response.headers_mut().insert(
            CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
                .map_err(|_| SubsonicError::internal())?,
        );
    }

    Ok(response)
}

async fn get_cover_art_inner(
    state: &AppState,
    params: &SubsonicParams,
) -> Result<Response, SubsonicError> {
    let user = authenticate(state, params).await?;
    let visible = user.visible_library_ids();
    let id = required_uuid(params, "id")?;

    let artwork = match catalog::get_album_artwork(&state.pool, id, &visible).await? {
        Some(artwork) => Some(artwork),
        None => match catalog::get_track(&state.pool, id, &visible).await? {
            Some(track) => match track.album_id {
                Some(album_id) => {
                    catalog::get_album_artwork(&state.pool, album_id, &visible).await?
                }
                None => None,
            },
            None => None,
        },
    };

    let artwork = artwork.ok_or_else(|| SubsonicError::not_found("Cover art"))?;
    let mut response = artwork.data.into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&artwork.mime).map_err(|_| SubsonicError::internal())?,
    );

    Ok(response)
}

async fn star_inner(
    state: &AppState,
    params: &SubsonicParams,
    star: bool,
) -> Result<Value, SubsonicError> {
    let user = authenticate(state, params).await?;
    let mut any = false;

    for value in params.get_all("id") {
        let id = parse_uuid(value, "id")?;
        apply_star(state, &user, ItemType::Track, id, star).await?;
        any = true;
    }

    for value in params.get_all("albumId") {
        let id = parse_uuid(value, "albumId")?;
        apply_star(state, &user, ItemType::Album, id, star).await?;
        any = true;
    }

    for value in params.get_all("artistId") {
        let id = parse_uuid(value, "artistId")?;
        apply_star(state, &user, ItemType::Artist, id, star).await?;
        any = true;
    }

    if !any {
        return Err(SubsonicError::missing("id"));
    }

    Ok(json!({}))
}

async fn apply_star(
    state: &AppState,
    user: &AuthUser,
    item_type: ItemType,
    item_id: Uuid,
    star: bool,
) -> Result<(), SubsonicError> {
    let visible = user.visible_library_ids();
    let exists = match item_type {
        ItemType::Track => catalog::get_track(&state.pool, item_id, &visible)
            .await?
            .is_some(),
        ItemType::Album => catalog::get_album(&state.pool, item_id, &visible)
            .await?
            .is_some(),
        ItemType::Artist => catalog::get_artist(&state.pool, item_id, &visible)
            .await?
            .is_some(),
    };
    if !exists {
        return Err(SubsonicError::not_found("Item"));
    }

    if star {
        annotations::star(&state.pool, user.id, item_type, item_id).await?;
    } else {
        annotations::unstar(&state.pool, user.id, item_type, item_id).await?;
    }

    Ok(())
}

async fn scrobble_inner(state: &AppState, params: &SubsonicParams) -> Result<Value, SubsonicError> {
    let user = authenticate(state, params).await?;
    let submission = params
        .get("submission")
        .map(|value| value != "false")
        .unwrap_or(true);
    let mut any = false;

    let visible = user.visible_library_ids();
    for value in params.get_all("id") {
        let id = parse_uuid(value, "id")?;
        if catalog::get_track(&state.pool, id, &visible)
            .await?
            .is_some()
        {
            annotations::scrobble(&state.pool, user.id, id, submission).await?;
            any = true;
        }
    }

    if !any {
        return Err(SubsonicError::missing("id"));
    }

    Ok(json!({}))
}

async fn get_playlists_inner(
    state: &AppState,
    params: &SubsonicParams,
) -> Result<Value, SubsonicError> {
    let user = authenticate(state, params).await?;
    let visible = user.visible_library_ids();
    let all = playlists::list_with_counts(&state.pool, &visible).await?;
    let overwrites = authz::playlist_overwrites(&state.pool, &user.authz)
        .await
        .map_err(|_| SubsonicError::internal())?;
    let playlists = all
        .iter()
        .filter(|playlist| {
            let records = overwrites.get(&playlist.id).map_or(&[][..], Vec::as_slice);
            authz::resolve_playlist(&user.authz, playlist, records).can_view_playlist()
        })
        .map(playlist_json)
        .collect::<Vec<_>>();

    Ok(json!({ "playlists": { "playlist": playlists } }))
}

async fn get_playlist_inner(
    state: &AppState,
    params: &SubsonicParams,
) -> Result<Value, SubsonicError> {
    let user = authenticate(state, params).await?;
    let visible = user.visible_library_ids();
    let id = required_uuid(params, "id")?;
    let detail = playlists::get(&state.pool, id, &visible)
        .await?
        .ok_or_else(|| SubsonicError::not_found("Playlist"))?;
    if !playlist_permissions(state, &user, &detail.playlist)
        .await?
        .can_view_playlist()
    {
        return Err(SubsonicError::not_found("Playlist"));
    }
    let mut playlist = playlist_json(&detail.playlist);

    if let Value::Object(map) = &mut playlist {
        map.insert(
            "entry".to_owned(),
            Value::Array(detail.tracks.iter().map(song_json).collect()),
        );
    }

    Ok(json!({ "playlist": playlist }))
}

async fn create_playlist_inner(
    state: &AppState,
    params: &SubsonicParams,
) -> Result<Value, SubsonicError> {
    let user = authenticate(state, params).await?;
    let name = params
        .get("name")
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let song_ids =
        filter_visible_track_ids(state, &user, &collect_ids(params, &["songId", "id"])?).await?;

    if let Some(value) = params.get("playlistId") {
        let playlist_id = parse_uuid(value, "playlistId")?;
        let playlist = load_playlist_record(state, &user, playlist_id).await?;
        if !playlist_permissions(state, &user, &playlist)
            .await?
            .contains(Permissions::PLAYLIST_EDIT)
        {
            return Err(SubsonicError::forbidden());
        }

        let updated =
            playlists::update(&state.pool, playlist_id, name, None, &song_ids, &[]).await?;

        if !updated {
            return Err(SubsonicError::not_found("Playlist"));
        }

        return Ok(json!({ "playlist": { "id": playlist_id.to_string() } }));
    }

    if !user.can(Permissions::PLAYLIST_CREATE) {
        return Err(SubsonicError::forbidden());
    }

    let name = name.ok_or_else(|| SubsonicError::missing("name"))?;
    let id = playlists::create(&state.pool, user.id, name, &song_ids).await?;

    Ok(json!({ "playlist": { "id": id.to_string() } }))
}

async fn update_playlist_inner(
    state: &AppState,
    params: &SubsonicParams,
) -> Result<Value, SubsonicError> {
    let user = authenticate(state, params).await?;
    let playlist_id = required_uuid(params, "playlistId")?;
    let playlist = load_playlist_record(state, &user, playlist_id).await?;
    let permissions = playlist_permissions(state, &user, &playlist).await?;
    let name = params
        .get("name")
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let is_public = params.get("public").map(|value| value == "true");
    let add =
        filter_visible_track_ids(state, &user, &collect_ids(params, &["songIdToAdd"])?).await?;
    let remove = params
        .get_all("songIndexToRemove")
        .filter_map(|value| value.parse::<usize>().ok())
        .collect::<Vec<_>>();

    if (name.is_some() || is_public.is_some())
        && !permissions.contains(Permissions::PLAYLIST_MANAGE)
    {
        return Err(SubsonicError::forbidden());
    }
    if (!add.is_empty() || !remove.is_empty()) && !permissions.contains(Permissions::PLAYLIST_EDIT)
    {
        return Err(SubsonicError::forbidden());
    }

    if let Some(is_public) = is_public {
        if is_public {
            mc_db::repos::permissions::upsert(
                &state.pool,
                "playlist",
                playlist_id,
                "role",
                user.authz.everyone_role_id,
                i64::try_from(Permissions::PLAYLIST_VIEW.bits()).unwrap_or(i64::MAX),
                0,
            )
            .await?;
        } else {
            mc_db::repos::permissions::delete(
                &state.pool,
                "playlist",
                playlist_id,
                "role",
                user.authz.everyone_role_id,
            )
            .await?;
        }
    }

    let updated =
        playlists::update(&state.pool, playlist_id, name, is_public, &add, &remove).await?;

    if !updated {
        return Err(SubsonicError::not_found("Playlist"));
    }

    Ok(json!({}))
}

async fn delete_playlist_inner(
    state: &AppState,
    params: &SubsonicParams,
) -> Result<Value, SubsonicError> {
    let user = authenticate(state, params).await?;
    let playlist_id = required_uuid(params, "id")?;
    let playlist = load_playlist_record(state, &user, playlist_id).await?;
    if !playlist_permissions(state, &user, &playlist)
        .await?
        .contains(Permissions::PLAYLIST_MANAGE)
    {
        return Err(SubsonicError::forbidden());
    }

    if playlists::delete(&state.pool, playlist_id).await? {
        Ok(json!({}))
    } else {
        Err(SubsonicError::not_found("Playlist"))
    }
}

async fn get_play_queue_inner(
    state: &AppState,
    params: &SubsonicParams,
) -> Result<Value, SubsonicError> {
    let user = authenticate(state, params).await?;

    let Some(queue) = play_queue::get(&state.pool, user.id).await? else {
        return Ok(json!({
            "playQueue": {
                "entry": [],
                "current": -1,
                "position": 0,
            }
        }));
    };

    let visible = user.visible_library_ids();
    let tracks = catalog::get_tracks_by_ids(&state.pool, &queue.track_ids, &visible).await?;
    let current = queue
        .track_ids
        .get(usize::try_from(queue.current_index.max(0)).unwrap_or(0))
        .map_or_else(|| json!(-1), |id| json!(id.to_string()));

    Ok(json!({
        "playQueue": {
            "entry": tracks.iter().map(song_json).collect::<Vec<_>>(),
            "current": current,
            "position": queue.position_ms,
            "username": &user.username,
            "changed": CREATED,
        }
    }))
}

async fn save_play_queue_inner(
    state: &AppState,
    params: &SubsonicParams,
) -> Result<Value, SubsonicError> {
    let user = authenticate(state, params).await?;
    let ids = filter_visible_track_ids(state, &user, &collect_ids(params, &["id"])?).await?;

    if ids.is_empty() {
        return Err(SubsonicError::missing("id"));
    }

    let current_index = params
        .get("current")
        .and_then(|value| Uuid::parse_str(value).ok())
        .and_then(|current| ids.iter().position(|id| *id == current))
        .unwrap_or(0);
    let position = params
        .get("position")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);

    play_queue::save(
        &state.pool,
        user.id,
        &ids,
        i32::try_from(current_index).unwrap_or(0),
        position,
    )
    .await?;

    Ok(json!({}))
}

async fn filter_visible_track_ids(
    state: &AppState,
    user: &AuthUser,
    ids: &[Uuid],
) -> Result<Vec<Uuid>, SubsonicError> {
    let visible = user.visible_library_ids();
    Ok(catalog::get_tracks_by_ids(&state.pool, ids, &visible)
        .await?
        .into_iter()
        .map(|track| track.id)
        .collect())
}

async fn load_playlist_record(
    state: &AppState,
    user: &AuthUser,
    id: Uuid,
) -> Result<PlaylistRecord, SubsonicError> {
    let visible = user.visible_library_ids();
    playlists::get(&state.pool, id, &visible)
        .await?
        .map(|detail| detail.playlist)
        .ok_or_else(|| SubsonicError::not_found("Playlist"))
}

async fn playlist_permissions(
    state: &AppState,
    user: &AuthUser,
    playlist: &PlaylistRecord,
) -> Result<Permissions, SubsonicError> {
    let overwrites = authz::playlist_overwrites(&state.pool, &user.authz)
        .await
        .map_err(|_| SubsonicError::internal())?;
    let records = overwrites.get(&playlist.id).map_or(&[][..], Vec::as_slice);
    Ok(authz::resolve_playlist(&user.authz, playlist, records))
}

async fn authenticate(
    state: &AppState,
    params: &SubsonicParams,
) -> Result<AuthUser, SubsonicError> {
    let username = params.get("u").ok_or_else(|| SubsonicError::missing("u"))?;
    let limiter_key = format!("subsonic:{}", username.to_lowercase());

    if state.login_limiter.blocked_for(&limiter_key).is_some() {
        return Err(SubsonicError::auth());
    }

    let Some(user) = users::find_by_username(&state.pool, username)
        .await?
        .filter(|user| user.is_active)
    else {
        state.login_limiter.record_failure(&limiter_key);
        return Err(SubsonicError::auth());
    };

    if let Some(password) = params.get("p") {
        let password = decode_password(password)?;
        let matches = password
            .as_bytes()
            .ct_eq(user.subsonic_secret.as_bytes())
            .unwrap_u8()
            == 1;
        if !matches {
            state.login_limiter.record_failure(&limiter_key);
            return Err(SubsonicError::auth());
        }
    } else if let (Some(token), Some(salt)) = (params.get("t"), params.get("s")) {
        if !mc_auth::verify_subsonic_token(&user.subsonic_secret, salt, token) {
            state.login_limiter.record_failure(&limiter_key);
            return Err(SubsonicError::auth());
        }
    } else {
        return Err(SubsonicError::missing("p or t/s"));
    }

    state.login_limiter.record_success(&limiter_key);

    let role = user
        .role
        .parse::<Role>()
        .map_err(|_| SubsonicError::internal())?;
    let authz = authz::load_cached(&state.pool, &state.authz_cache, user.id)
        .await
        .map_err(|_| SubsonicError::internal())?;

    Ok(AuthUser {
        id: user.id,
        username: user.username,
        role,
        subsonic_secret: user.subsonic_secret,
        authz,
    })
}

fn decode_password(value: &str) -> Result<String, SubsonicError> {
    if let Some(encoded) = value.strip_prefix("enc:") {
        let bytes = hex::decode(encoded).map_err(|_| SubsonicError::auth())?;
        String::from_utf8(bytes).map_err(|_| SubsonicError::auth())
    } else {
        Ok(value.to_owned())
    }
}

fn finish(params: &SubsonicParams, result: Result<Value, SubsonicError>) -> Response {
    match result {
        Ok(body) => respond(params, ok_value(body)),
        Err(error) => respond(params, error_value(error)),
    }
}

fn ok_value(body: Value) -> Value {
    let mut root = Map::new();
    root.insert("status".to_owned(), json!("ok"));
    root.insert("version".to_owned(), json!(API_VERSION));

    if let Value::Object(map) = body {
        root.extend(map);
    }

    json!({ "subsonic-response": Value::Object(root) })
}

fn error_value(error: SubsonicError) -> Value {
    json!({
        "subsonic-response": {
            "status": "failed",
            "version": API_VERSION,
            "error": {
                "code": error.code,
                "message": error.message,
            }
        }
    })
}

fn respond(params: &SubsonicParams, value: Value) -> Response {
    match params.format() {
        SubsonicFormat::Json => Json(value).into_response(),
        SubsonicFormat::Jsonp => {
            let callback = params.callback();
            let body = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_owned());
            (
                [(CONTENT_TYPE, "application/javascript")],
                format!("{callback}({body});"),
            )
                .into_response()
        }
        SubsonicFormat::Xml => {
            let root = value.get("subsonic-response").unwrap_or(&value);
            (
                [(CONTENT_TYPE, "application/xml; charset=utf-8")],
                to_xml(root),
            )
                .into_response()
        }
    }
}

fn to_xml(root: &Value) -> String {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    write_element(
        &mut xml,
        "subsonic-response",
        root,
        &[("xmlns", "http://subsonic.org/restapi")],
    );
    xml
}

fn write_element(out: &mut String, name: &str, value: &Value, extra: &[(&str, &str)]) {
    match value {
        Value::Object(map) => {
            out.push('<');
            out.push_str(name);
            for (key, value) in extra {
                write_attribute(out, key, value);
            }

            let mut children = Vec::new();
            for (key, value) in map {
                match value {
                    Value::Null => {}
                    Value::String(value) => write_attribute(out, key, value),
                    Value::Number(value) => write_attribute(out, key, &value.to_string()),
                    Value::Bool(value) => {
                        write_attribute(out, key, if *value { "true" } else { "false" });
                    }
                    Value::Array(_) | Value::Object(_) => children.push((key, value)),
                }
            }

            if children.is_empty() {
                out.push_str("/>");
                return;
            }

            out.push('>');
            for (key, value) in children {
                write_child(out, key, value);
            }
            out.push_str("</");
            out.push_str(name);
            out.push('>');
        }
        Value::Array(items) => {
            for item in items {
                write_element(out, name, item, &[]);
            }
        }
        Value::String(value) => write_text_element(out, name, value),
        Value::Number(value) => write_text_element(out, name, &value.to_string()),
        Value::Bool(value) => write_text_element(out, name, if *value { "true" } else { "false" }),
        Value::Null => {}
    }
}

fn write_child(out: &mut String, name: &str, value: &Value) {
    if let Value::Array(items) = value {
        for item in items {
            write_element(out, name, item, &[]);
        }
    } else {
        write_element(out, name, value, &[]);
    }
}

fn write_attribute(out: &mut String, name: &str, value: &str) {
    out.push(' ');
    out.push_str(name);
    out.push_str("=\"");
    escape(out, value, true);
    out.push('"');
}

fn write_text_element(out: &mut String, name: &str, value: &str) {
    out.push('<');
    out.push_str(name);
    out.push('>');
    escape(out, value, false);
    out.push_str("</");
    out.push_str(name);
    out.push('>');
}

fn escape(out: &mut String, value: &str, attribute: bool) {
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if attribute => out.push_str("&quot;"),
            '\'' if attribute => out.push_str("&apos;"),
            _ => out.push(character),
        }
    }
}

fn artist_index(artists: &[ArtistSummary]) -> Vec<Value> {
    let mut groups: BTreeMap<char, Vec<Value>> = BTreeMap::new();

    for artist in artists {
        let letter = artist
            .name
            .chars()
            .next()
            .map(|character| character.to_ascii_uppercase())
            .filter(|character| character.is_ascii_alphabetic())
            .unwrap_or('#');

        groups.entry(letter).or_default().push(artist_json(artist));
    }

    groups
        .into_iter()
        .map(|(letter, artists)| json!({ "name": letter.to_string(), "artist": artists }))
        .collect()
}

fn artist_json(artist: &ArtistSummary) -> Value {
    json!({
        "id": artist.id.to_string(),
        "name": &artist.name,
        "albumCount": artist.album_count,
    })
}

fn album_json(album: &AlbumSummary) -> Value {
    json!({
        "id": album.id.to_string(),
        "name": &album.title,
        "artist": &album.album_artist,
        "artistId": album.album_artist_id.to_string(),
        "coverArt": album.id.to_string(),
        "songCount": album.track_count,
        "duration": album.duration_ms / 1000,
        "created": CREATED,
        "year": album.year,
    })
}

fn song_json(track: &TrackSummary) -> Value {
    let suffix = file_suffix(&track.file_key);

    json!({
        "id": track.id.to_string(),
        "parent": track.album_id.map(|id| id.to_string()).unwrap_or_default(),
        "isDir": false,
        "title": &track.title,
        "album": track.album.as_deref(),
        "artist": track.artist.as_deref(),
        "albumArtist": track.album_artist.as_deref(),
        "track": track.track_no,
        "discNumber": track.disc_no,
        "year": track.album_year.unwrap_or(0),
        "duration": track.duration_ms.unwrap_or(0) / 1000,
        "size": track.size,
        "suffix": suffix,
        "contentType": content_type(&suffix),
        "coverArt": track.album_id.map(|id| id.to_string()).unwrap_or_default(),
        "albumId": track.album_id.map(|id| id.to_string()).unwrap_or_default(),
        "artistId": track.album_artist_id.map(|id| id.to_string()).unwrap_or_default(),
        "path": &track.file_key,
        "type": "music",
        "isVideo": false,
        "created": CREATED,
    })
}

fn song_detail_json(track: &TrackDetail) -> Value {
    let suffix = file_suffix(&track.file_key);

    json!({
        "id": track.id.to_string(),
        "parent": track.album_id.map(|id| id.to_string()).unwrap_or_default(),
        "isDir": false,
        "title": &track.title,
        "album": track.album.as_deref(),
        "artist": track.artist.as_deref(),
        "albumArtist": track.album_artist.as_deref(),
        "track": track.track_no,
        "discNumber": track.disc_no,
        "year": track.year,
        "duration": track.duration_ms.unwrap_or(0) / 1000,
        "size": track.size,
        "suffix": suffix,
        "contentType": content_type(&suffix),
        "coverArt": track.album_id.map(|id| id.to_string()).unwrap_or_default(),
        "albumId": track.album_id.map(|id| id.to_string()).unwrap_or_default(),
        "artistId": track.album_artist_id.map(|id| id.to_string()).unwrap_or_default(),
        "path": &track.file_key,
        "type": "music",
        "isVideo": false,
        "created": CREATED,
    })
}

fn playlist_json(playlist: &PlaylistRecord) -> Value {
    json!({
        "id": playlist.id.to_string(),
        "name": &playlist.name,
        "owner": &playlist.owner,
        "public": playlist.is_public,
        "songCount": playlist.song_count,
        "duration": playlist.duration_ms / 1000,
        "created": CREATED,
        "changed": CREATED,
    })
}

fn parse_uuid(value: &str, key: &str) -> Result<Uuid, SubsonicError> {
    Uuid::parse_str(value).map_err(|_| SubsonicError::new(10, format!("Invalid parameter: {key}")))
}

fn collect_ids(params: &SubsonicParams, keys: &[&str]) -> Result<Vec<Uuid>, SubsonicError> {
    let mut ids = Vec::new();

    for key in keys {
        for value in params.get_all(key) {
            ids.push(parse_uuid(value, key)?);
        }
    }

    Ok(ids)
}

fn required_uuid(params: &SubsonicParams, key: &str) -> Result<Uuid, SubsonicError> {
    let value = params.required(key)?;
    Uuid::parse_str(value).map_err(|_| SubsonicError::new(10, format!("Invalid parameter: {key}")))
}

fn param_usize(params: &SubsonicParams, key: &str, default: usize) -> usize {
    params
        .get(key)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn transcoded_response(
    stream: tonic::Streaming<TranscodeChunk>,
    format: &str,
    download: bool,
    file_key: &str,
    title: &str,
) -> Result<Response, SubsonicError> {
    let content_type = transcoder_content_type(format);
    let stream = stream.map(|item| {
        item.map(|chunk| chunk.data)
            .map_err(|status| std::io::Error::other(status.message()))
    });
    let mut response = Response::new(Body::from_stream(stream));

    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));

    if download {
        let filename = download_filename(file_key, title);
        response.headers_mut().insert(
            CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
                .map_err(|_| SubsonicError::internal())?,
        );
    }

    Ok(response)
}

fn transcoder_content_type(format: &str) -> &'static str {
    match format.to_ascii_lowercase().as_str() {
        "opus" | "ogg" => "audio/ogg",
        "aac" | "m4a" => "audio/aac",
        _ => "audio/mpeg",
    }
}

fn file_suffix(file_key: &str) -> String {
    FsPath::new(file_key)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default()
}

fn content_type(suffix: &str) -> &'static str {
    match suffix {
        "mp3" => "audio/mpeg",
        "flac" => "audio/flac",
        "ogg" | "oga" => "audio/ogg",
        "opus" => "audio/opus",
        "m4a" | "mp4" => "audio/mp4",
        "aac" => "audio/aac",
        "wav" => "audio/wav",
        "aiff" | "aif" => "audio/aiff",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{error_value, ok_value, to_xml};

    #[test]
    fn renders_subsonic_xml_with_attributes_and_arrays() {
        let value = ok_value(json!({
            "musicFolders": {
                "musicFolder": [{ "id": "1", "name": "Music & More" }]
            }
        }));
        let root = value.get("subsonic-response").unwrap();
        let xml = to_xml(root);

        assert!(xml.starts_with("<?xml version=\"1.0\""));
        assert!(xml.contains("xmlns=\"http://subsonic.org/restapi\""));
        assert!(xml.contains("status=\"ok\""));
        assert!(xml.contains("<musicFolder id=\"1\" name=\"Music &amp; More\"/>"));
    }

    #[test]
    fn renders_subsonic_error_xml() {
        let value = error_value(super::SubsonicError::auth());
        let root = value.get("subsonic-response").unwrap();
        let xml = to_xml(root);

        assert!(xml.contains("status=\"failed\""));
        assert!(xml.contains("<error code=\"40\" message=\"Wrong username or password\"/>"));
    }
}
