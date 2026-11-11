mod admin;
mod auth;
mod catalog;
mod config;
mod error;
mod favorites;
mod playlists;
mod probe;
mod state;
mod subsonic;
mod tag_edits;
mod transcoder;
mod uploads;

use std::sync::Arc;

use anyhow::Context;
use axum::extract::{Request, State};
use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, head, options, patch, post, put};
use axum::{Json, Router};
use config::Config;
use error::ApiError;
use mc_crypto::MasterKey;
use mc_db::repos::libraries;
use mc_db::PgPool;
use mc_media::LoftyParser;
use mc_runtime::StorageRegistry;
use mc_scanner::{ScanMode, ScanStats, Scanner};
use mc_telemetry::{check_fn, Health, TelemetryConfig};
use serde::Serialize;
use state::AppState;
use tokio::net::TcpListener;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info};
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
        libraries::ensure_default(&pool, &config.library_name, &config.library_path)
            .await
            .context("ensure default library")?;
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

    let state = AppState {
        pool: pool.clone(),
        scanner,
        registry: Arc::new(tokio::sync::RwLock::new(registry)),
        master_key,
        session_ttl_hours: config.session_ttl_hours,
        cookie_secure: config.cookie_secure,
        scan_lock: Arc::new(tokio::sync::Mutex::new(())),
        transcoder,
        metrics: metrics_handle,
        staging_path: std::path::PathBuf::from(&config.staging_path),
        max_upload_bytes: config.max_upload_bytes,
        upload_lock: Arc::new(tokio::sync::Mutex::new(())),
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
            "/api/v1/admin/tag-edits",
            get(tag_edits::list).post(tag_edits::create),
        )
        .route("/api/v1/admin/tag-edits/{id}", get(tag_edits::get))
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
    let path = request.uri().path().to_owned();
    let response = next.run(request).await;

    metrics::counter!(
        "http_requests_total",
        "method" => method,
        "path" => path,
        "status" => response.status().as_u16().to_string()
    )
    .increment(1);

    response
}

async fn metrics(State(state): State<AppState>) -> Response {
    match &state.metrics {
        Some(handle) => handle.render().into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn features(State(state): State<AppState>) -> Json<Features> {
    let transcoder = match &state.transcoder {
        Some(client) => client.is_available().await,
        None => false,
    };
    let worker = mc_jobs::is_worker_online(&state.pool, 30)
        .await
        .unwrap_or(false);

    Json(Features {
        worker,
        transcoder,
        tag_editor: worker,
        monitoring: state.metrics.is_some(),
    })
}

async fn scan(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(api_error) = auth::require_admin(&state, &headers).await {
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
