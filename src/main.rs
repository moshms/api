mod admin;
mod auth;
mod authz;
mod authz_cache;
mod catalog;
mod config;
mod error;
mod favorites;
mod permissions;
mod playlists;
mod probe;
mod rate_limit;
mod roles;
mod state;
mod subsonic;
mod tag_edits;
mod transcoder;
mod uploads;

use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use authz_cache::AuthzCache;
use axum::extract::{DefaultBodyLimit, MatchedPath, Request, State};
use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, head, options, patch, post, put};
use axum::{Json, Router};
use config::Config;
use error::ApiError;
use mc_authz::Permissions;
use mc_crypto::MasterKey;
use mc_db::repos::{libraries, permissions as db_permissions, roles as db_roles, users};
use mc_db::PgPool;
use mc_media::LoftyParser;
use mc_runtime::StorageRegistry;
use mc_scanner::{ScanMode, ScanStats, Scanner};
use mc_telemetry::{check_fn, Health, TelemetryConfig};
use rate_limit::LoginLimiter;
use serde::Serialize;
use state::AppState;
use tokio::net::TcpListener;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use transcoder::TranscoderClient;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return probe::run();
    }

    if std::env::args().nth(1).as_deref() == Some("migrate") {
        let config = Config::from_env()?;
        mc_db::connect_and_migrate(&config.database_url, config.database_max_connections)
            .await
            .context("apply migrations")?;
        println!("migrations applied");
        return Ok(());
    }

    let config = Config::from_env()?;

    mc_telemetry::init(&TelemetryConfig::new(
        config.log_json,
        config.log_filter.clone(),
    ));

    info!(
        admin_bootstrap = config.admin_user.is_some() && config.admin_password.is_some(),
        metrics = config.metrics,
        library = %config.library_path,
        scan_on_start = config.scan_on_start,
        transcoder = config.transcoder_url.as_deref().unwrap_or(""),
        "starting mc-api"
    );

    let metrics_handle = if config.metrics {
        Some(mc_telemetry::install_metrics().map_err(|error| anyhow::anyhow!(error))?)
    } else {
        None
    };

    let pool = mc_db::connect_and_migrate(&config.database_url, config.database_max_connections)
        .await
        .context("connect to postgres")?;

    auth::ensure_admin(&pool, &config)
        .await
        .context("ensure initial administrator")?;

    let master_key = config
        .master_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(MasterKey::from_encoded)
        .transpose()
        .context("parse MC_MASTER_KEY")?;

    if libraries::list(&pool).await?.is_empty() {
        let library = libraries::ensure_default(&pool, &config.library_name, &config.library_path)
            .await
            .context("ensure default library")?;

        if config.library_access == "everyone" {
            if let Some(everyone) = db_roles::everyone(&pool).await? {
                db_permissions::upsert(
                    &pool,
                    "library",
                    library.id,
                    "role",
                    everyone.id,
                    i64::try_from(
                        Permissions::LIBRARY_VIEW
                            .union(Permissions::LIBRARY_DOWNLOAD)
                            .bits(),
                    )
                    .unwrap_or(i64::MAX),
                    0,
                )
                .await?;
            }
        }
    }

    tokio::fs::create_dir_all(&config.staging_path)
        .await
        .with_context(|| format!("create staging directory {}", config.staging_path))?;

    let registry = StorageRegistry::load(&pool, master_key.as_ref())
        .await
        .context("load storage registry")?;
    let scanner = Arc::new(Scanner::new(pool.clone(), Arc::new(LoftyParser)));

    let transcoder = config
        .transcoder_url
        .as_deref()
        .filter(|url| !url.is_empty())
        .map(TranscoderClient::new);

    let local_storage_roots = config
        .local_storage_roots
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .collect::<Vec<_>>();

    let setup_token = if users::count(&pool).await? == 0 {
        let token = config
            .setup_token
            .clone()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(mc_auth::generate_token);
        warn!(setup_token = %token, "initial setup token generated; use it on /setup");
        Some(token)
    } else {
        None
    };

    let state = AppState {
        pool: pool.clone(),
        scanner,
        registry: Arc::new(tokio::sync::RwLock::new(registry)),
        master_key,
        session_ttl_hours: config.session_ttl_hours,
        setup_token,
        login_limiter: Arc::new(LoginLimiter::new()),
        authz_cache: Arc::new(AuthzCache::new()),
        cookie_secure: config.cookie_secure,
        scan_lock: Arc::new(tokio::sync::Mutex::new(())),
        transcoder,
        metrics: metrics_handle,
        staging_path: std::path::PathBuf::from(&config.staging_path),
        local_storage_roots,
        max_upload_bytes: config.max_upload_bytes,
        upload_locks: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
    };

    if config.scan_on_start {
        let state = state.clone();
        tokio::spawn(async move {
            for result in scan_all(&state).await {
                match (result.stats, result.error) {
                    (Some(stats), _) => {
                        info!(library = %result.library_name, ?stats, "startup scan finished")
                    }
                    (None, Some(scan_error)) => {
                        error!(library = %result.library_name, %scan_error, "startup scan failed")
                    }
                    _ => {}
                }
            }
        });
    }

    let health = health_router(pool);
    let api = api_router(state);

    let app = health.merge(api).layer(TraceLayer::new_for_http());
    let app = if config.metrics {
        app.layer(axum::middleware::from_fn(metrics_middleware))
    } else {
        app
    };

    let listener = TcpListener::bind(&config.bind_addr)
        .await
        .with_context(|| format!("bind {}", config.bind_addr))?;
    let address = listener.local_addr()?;

    info!(%address, "mc-api listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("http server")?;

    Ok(())
}

fn health_router(pool: PgPool) -> Router {
    let health = Health::new().with_check(check_fn("postgres", move || {
        let pool = pool.clone();
        async move {
            mc_db::ping(&pool)
                .await
                .map_err(|ping_error| ping_error.to_string())
        }
    }));

    health.router()
}

fn api_router(state: AppState) -> Router {
    let auth_routes = Router::new()
        .route(
            "/api/v1/auth/setup",
            get(auth::setup_status).post(auth::setup),
        )
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/auth/me", get(auth::me))
        .route("/api/v1/auth/subsonic", get(auth::subsonic_credentials))
        .route(
            "/api/v1/auth/tokens",
            get(auth::list_tokens).post(auth::create_token),
        )
        .route("/api/v1/auth/tokens/{id}", delete(auth::delete_token))
        .route("/api/v1/auth/password", post(auth::change_password))
        .route(
            "/api/v1/auth/sessions",
            get(auth::list_sessions).delete(auth::delete_other_sessions),
        )
        .route("/api/v1/auth/sessions/{id}", delete(auth::delete_session))
        .route("/api/v1/auth/subsonic/rotate", post(auth::rotate_subsonic))
        .layer(SetResponseHeaderLayer::overriding(
            CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ));

    Router::new()
        .merge(auth_routes)
        .route("/api/v1/features", get(features))
        .route("/metrics", get(metrics))
        .route("/api/v1/libraries", get(catalog::libraries))
        .route("/api/v1/uploads", get(uploads::list))
        .route("/tus", options(uploads::options).post(uploads::create))
        .route(
            "/tus/{id}",
            head(uploads::head)
                .patch(uploads::patch)
                .delete(uploads::delete),
        )
        .route("/api/v1/artists", get(catalog::artists))
        .route("/api/v1/artists/{id}/tracks", get(catalog::artist_tracks))
        .route("/api/v1/albums", get(catalog::albums))
        .route("/api/v1/albums/{id}", get(catalog::album))
        .route("/api/v1/tracks/{id}", get(catalog::track))
        .route("/api/v1/search", get(catalog::search))
        .route("/api/v1/stream/{id}", get(catalog::stream))
        .route("/api/v1/download/{id}", get(catalog::download))
        .route("/api/v1/artwork/{id}", get(catalog::artwork))
        .route(
            "/api/v1/playlists",
            get(playlists::list).post(playlists::create),
        )
        .route(
            "/api/v1/playlists/{id}",
            get(playlists::get)
                .patch(playlists::update)
                .delete(playlists::delete),
        )
        .route("/api/v1/playlists/{id}/tracks", post(playlists::add_track))
        .route(
            "/api/v1/playlists/{id}/tracks/{position}",
            delete(playlists::remove_track),
        )
        .route("/api/v1/favorites", get(favorites::list))
        .route(
            "/api/v1/tracks/{id}/star",
            put(favorites::star_track).delete(favorites::unstar_track),
        )
        .route(
            "/api/v1/albums/{id}/star",
            put(favorites::star_album).delete(favorites::unstar_album),
        )
        .route(
            "/api/v1/artists/{id}/star",
            put(favorites::star_artist).delete(favorites::unstar_artist),
        )
        .route("/api/v1/admin/scan", post(scan))
        .route("/api/v1/admin/scan/async", post(scan_async))
        .route(
            "/api/v1/admin/storages",
            get(admin::list_storages).post(admin::create_storage),
        )
        .route("/api/v1/admin/storages/{id}", delete(admin::delete_storage))
        .route(
            "/api/v1/admin/libraries",
            get(admin::list_libraries).post(admin::create_library),
        )
        .route(
            "/api/v1/admin/libraries/{id}",
            delete(admin::delete_library),
        )
        .route(
            "/api/v1/admin/users",
            get(admin::list_users).post(admin::create_user),
        )
        .route(
            "/api/v1/admin/users/{id}",
            patch(admin::update_user).delete(admin::delete_user),
        )
        .route("/api/v1/admin/jobs", get(admin::list_jobs))
        .route("/api/v1/admin/jobs/{id}/retry", post(admin::retry_job))
        .route(
            "/api/v1/tag-edits",
            get(tag_edits::list).post(tag_edits::create),
        )
        .route("/api/v1/tag-edits/{id}", get(tag_edits::get))
        .layer(DefaultBodyLimit::max(15 * 1024 * 1024))
        .route(
            "/api/v1/admin/tag-edits",
            get(tag_edits::list).post(tag_edits::create),
        )
        .route("/api/v1/admin/tag-edits/{id}", get(tag_edits::get))
        .route("/api/v1/roles", get(roles::list).post(roles::create))
        .route("/api/v1/roles/available", get(roles::available_roles))
        .route("/api/v1/roles/order", put(roles::reorder))
        .route(
            "/api/v1/roles/{id}",
            patch(roles::update).delete(roles::delete),
        )
        .route("/api/v1/users/available", get(roles::available_users))
        .route(
            "/api/v1/users/{id}/roles/{role_id}",
            put(roles::assign).delete(roles::unassign),
        )
        .route("/api/v1/permissions", get(roles::permission_catalog))
        .route("/api/v1/audit-log", get(roles::audit_log))
        .route(
            "/api/v1/libraries/{id}/permissions",
            get(permissions::library_list),
        )
        .route(
            "/api/v1/libraries/{id}/permissions/{target_type}/{target_id}",
            put(permissions::library_set).delete(permissions::library_delete),
        )
        .route(
            "/api/v1/playlists/{id}/permissions",
            get(permissions::playlist_list),
        )
        .route(
            "/api/v1/playlists/{id}/permissions/{target_type}/{target_id}",
            put(permissions::playlist_set).delete(permissions::playlist_delete),
        )
        .route("/rest/ping", get(subsonic::ping))
        .route("/rest/ping.view", get(subsonic::ping))
        .route("/rest/getLicense", get(subsonic::get_license))
        .route("/rest/getLicense.view", get(subsonic::get_license))
        .route("/rest/getMusicFolders", get(subsonic::get_music_folders))
        .route(
            "/rest/getMusicFolders.view",
            get(subsonic::get_music_folders),
        )
        .route("/rest/getIndexes", get(subsonic::get_indexes))
        .route("/rest/getIndexes.view", get(subsonic::get_indexes))
        .route("/rest/getArtists", get(subsonic::get_artists))
        .route("/rest/getArtists.view", get(subsonic::get_artists))
        .route("/rest/getArtist", get(subsonic::get_artist))
        .route("/rest/getArtist.view", get(subsonic::get_artist))
        .route("/rest/getAlbum", get(subsonic::get_album))
        .route("/rest/getAlbum.view", get(subsonic::get_album))
        .route("/rest/getAlbumList2", get(subsonic::get_album_list2))
        .route("/rest/getAlbumList2.view", get(subsonic::get_album_list2))
        .route("/rest/getSong", get(subsonic::get_song))
        .route("/rest/getSong.view", get(subsonic::get_song))
        .route("/rest/search3", get(subsonic::search3))
        .route("/rest/search3.view", get(subsonic::search3))
        .route("/rest/stream", get(subsonic::stream))
        .route("/rest/stream.view", get(subsonic::stream))
        .route("/rest/download", get(subsonic::download))
        .route("/rest/download.view", get(subsonic::download))
        .route("/rest/getCoverArt", get(subsonic::get_cover_art))
        .route("/rest/getCoverArt.view", get(subsonic::get_cover_art))
        .route("/rest/star", get(subsonic::star))
        .route("/rest/star.view", get(subsonic::star))
        .route("/rest/unstar", get(subsonic::unstar))
        .route("/rest/unstar.view", get(subsonic::unstar))
        .route("/rest/scrobble", get(subsonic::scrobble))
        .route("/rest/scrobble.view", get(subsonic::scrobble))
        .route("/rest/getPlaylists", get(subsonic::get_playlists))
        .route("/rest/getPlaylists.view", get(subsonic::get_playlists))
        .route("/rest/getPlaylist", get(subsonic::get_playlist))
        .route("/rest/getPlaylist.view", get(subsonic::get_playlist))
        .route("/rest/createPlaylist", get(subsonic::create_playlist))
        .route("/rest/createPlaylist.view", get(subsonic::create_playlist))
        .route("/rest/updatePlaylist", get(subsonic::update_playlist))
        .route("/rest/updatePlaylist.view", get(subsonic::update_playlist))
        .route("/rest/deletePlaylist", get(subsonic::delete_playlist))
        .route("/rest/deletePlaylist.view", get(subsonic::delete_playlist))
        .route("/rest/getPlayQueue", get(subsonic::get_play_queue))
        .route("/rest/getPlayQueue.view", get(subsonic::get_play_queue))
        .route("/rest/savePlayQueue", get(subsonic::save_play_queue))
        .route("/rest/savePlayQueue.view", get(subsonic::save_play_queue))
        .with_state(state)
}

#[derive(Debug, Serialize)]
struct Features {
    worker: bool,
    transcoder: bool,
    tag_editor: bool,
    monitoring: bool,
}

async fn metrics_middleware(request: Request, next: Next) -> Response {
    let method = request.method().to_string();
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_owned())
        .unwrap_or_else(|| request.uri().path().to_owned());
    let started = Instant::now();
    let response = next.run(request).await;

    metrics::counter!(
        "http_requests_total",
        "method" => method.clone(),
        "path" => path.clone(),
        "status" => response.status().as_u16().to_string()
    )
    .increment(1);
    metrics::histogram!(
        "http_request_duration_seconds",
        "method" => method,
        "path" => path
    )
    .record(started.elapsed().as_secs_f64());

    response
}

async fn metrics(State(state): State<AppState>) -> Response {
    match &state.metrics {
        Some(handle) => handle.render().into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn features(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Features>, ApiError> {
    auth::authenticate(&state, &headers).await?;
    let transcoder = match &state.transcoder {
        Some(client) => client.is_available().await,
        None => false,
    };
    let worker = mc_jobs::is_worker_online(&state.pool, 30)
        .await
        .unwrap_or(false);

    Ok(Json(Features {
        worker,
        transcoder,
        tag_editor: worker,
        monitoring: state.metrics.is_some(),
    }))
}

#[derive(Debug, Serialize)]
struct ScanQueued {
    job_id: Uuid,
}

async fn scan_async(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<ScanQueued>), ApiError> {
    auth::require_permission(&state, &headers, mc_authz::Permissions::RUN_SCANS).await?;

    if !mc_jobs::is_worker_online(&state.pool, 30).await? {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "worker is offline",
        ));
    }

    let job_id = mc_jobs::enqueue(&state.pool, "scan", serde_json::json!({})).await?;
    Ok((StatusCode::ACCEPTED, Json(ScanQueued { job_id })))
}

async fn scan(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(api_error) =
        auth::require_permission(&state, &headers, mc_authz::Permissions::RUN_SCANS).await
    {
        return api_error.into_response();
    }

    let Ok(_scan_guard) = state.scan_lock.try_lock() else {
        return ApiError::new(StatusCode::CONFLICT, "scan already running").into_response();
    };

    (StatusCode::OK, Json(scan_all(&state).await)).into_response()
}

#[derive(Debug, Serialize)]
struct LibraryScanResult {
    library_id: Uuid,
    library_name: String,
    stats: Option<ScanStats>,
    error: Option<String>,
}

async fn scan_all(state: &AppState) -> Vec<LibraryScanResult> {
    let registry = state.registry.read().await.clone();
    let mut results = Vec::new();

    for library in registry.libraries() {
        let Some(storage) = registry.storage_for_library(library.id) else {
            results.push(LibraryScanResult {
                library_id: library.id,
                library_name: library.name.clone(),
                stats: None,
                error: Some("library storage is unavailable".to_owned()),
            });
            continue;
        };

        match state
            .scanner
            .scan_library(library, storage, ScanMode::Full)
            .await
        {
            Ok(stats) => results.push(LibraryScanResult {
                library_id: library.id,
                library_name: library.name.clone(),
                stats: Some(stats),
                error: None,
            }),
            Err(scan_error) => results.push(LibraryScanResult {
                library_id: library.id,
                library_name: library.name.clone(),
                stats: None,
                error: Some(scan_error.to_string()),
            }),
        }
    }

    results
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }

    info!("shutdown signal received");
}
