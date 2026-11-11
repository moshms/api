use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use mc_core::Role;
use mc_db::repos::libraries::{self, LibraryRecord};
use mc_db::repos::storages::{self, StorageRecord};
use mc_db::repos::users::{self, UserSummary};
use mc_storage::Key;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::auth;
use crate::error::ApiError;
use crate::state::AppState;
use mc_runtime::StorageRegistry;
use mc_runtime::{build_storage, encode_storage_config, redacted_config};

#[derive(Debug, Serialize)]
pub struct StorageDto {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub access: String,
    pub status: String,
    pub config: Value,
}

impl From<&StorageRecord> for StorageDto {
    fn from(record: &StorageRecord) -> Self {
        Self {
            id: record.id,
            name: record.name.clone(),
            kind: record.kind.clone(),
            access: record.access.clone(),
            status: record.status.clone(),
            config: redacted_config(record),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateStorageRequest {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub access: Option<String>,
    pub config: Value,
}

#[derive(Debug, Deserialize)]
pub struct CreateLibraryRequest {
    pub name: String,
    pub storage_id: Uuid,
    #[serde(default)]
    pub root_prefix: Option<String>,
    #[serde(default)]
    pub is_import_target: Option<bool>,
}

pub async fn list_storages(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<StorageDto>>, ApiError> {
    auth::require_admin(&state, &headers).await?;
    let records = storages::list(&state.pool).await?;

    Ok(Json(records.iter().map(StorageDto::from).collect()))
}

pub async fn create_storage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateStorageRequest>,
) -> Result<(StatusCode, Json<StorageDto>), ApiError> {
    auth::require_admin(&state, &headers).await?;

    let name = request.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "storage name must be between 1 and 100 characters",
        ));
    }

    if !matches!(request.kind.as_str(), "local" | "s3") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "storage kind must be local or s3",
        ));
    }

    let access = request.access.as_deref().unwrap_or("rw");
    if !matches!(access, "ro" | "rw") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "storage access must be ro or rw",
        ));
    }

    let config = encode_storage_config(&request.kind, &request.config, state.master_key.as_ref())?;

    let candidate = StorageRecord {
        id: Uuid::now_v7(),
        name: name.to_owned(),
        kind: request.kind.clone(),
        config: config.clone(),
        access: access.to_owned(),
        status: "online".to_owned(),
    };
    build_storage(&candidate, state.master_key.as_ref())?;

    let record = storages::create(&state.pool, name, &request.kind, config, access).await?;
    reload_registry(&state).await?;

    Ok((StatusCode::CREATED, Json(StorageDto::from(&record))))
}

pub async fn delete_storage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    auth::require_admin(&state, &headers).await?;

    if libraries::count_by_storage(&state.pool, id).await? > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "storage still has libraries",
        ));
    }

    if !storages::delete(&state.pool, id).await? {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "storage not found"));
    }

    reload_registry(&state).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_libraries(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<LibraryRecord>>, ApiError> {
    auth::require_admin(&state, &headers).await?;
    Ok(Json(libraries::list(&state.pool).await?))
}

pub async fn create_library(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateLibraryRequest>,
) -> Result<(StatusCode, Json<LibraryRecord>), ApiError> {
    auth::require_admin(&state, &headers).await?;

    let name = request.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "library name must be between 1 and 100 characters",
        ));
    }

    if storages::get(&state.pool, request.storage_id)
        .await?
        .is_none()
    {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "storage not found"));
    }

    let root_prefix = request.root_prefix.unwrap_or_default();
    Key::new(root_prefix.as_str())?;

    let library = libraries::create(
        &state.pool,
        name,
        request.storage_id,
        &root_prefix,
        request.is_import_target.unwrap_or(false),
    )
    .await?;

    reload_registry(&state).await?;
    Ok((StatusCode::CREATED, Json(library)))
}

pub async fn delete_library(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    auth::require_admin(&state, &headers).await?;

    if !libraries::delete(&state.pool, id).await? {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "library not found"));
    }

    reload_registry(&state).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn reload_registry(state: &AppState) -> Result<(), ApiError> {
    let registry = StorageRegistry::load(&state.pool, state.master_key.as_ref()).await?;
    *state.registry.write().await = registry;
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct AdminUserDto {
    pub id: Uuid,
    pub username: String,
    pub role: String,
    pub is_active: bool,
}

impl From<&UserSummary> for AdminUserDto {
    fn from(user: &UserSummary) -> Self {
        Self {
            id: user.id,
            username: user.username.clone(),
            role: user.role.clone(),
            is_active: user.is_active,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub is_active: Option<bool>,
    #[serde(default)]
    pub password: Option<String>,
}

pub async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AdminUserDto>>, ApiError> {
    auth::require_admin(&state, &headers).await?;
    let users = users::list(&state.pool).await?;

    Ok(Json(users.iter().map(AdminUserDto::from).collect()))
}

pub async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<AdminUserDto>), ApiError> {
    auth::require_admin(&state, &headers).await?;

    let username = request.username.trim();
    if username.is_empty() || username.chars().count() > 100 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "username must be between 1 and 100 characters",
        ));
    }

    if request.password.chars().count() < 8 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "password must contain at least 8 characters",
        ));
    }

    let role = parse_role(&request.role)?;
    let password_hash = mc_auth::hash_password(&request.password)?;
    let subsonic_secret = mc_auth::generate_secret();
    let user = users::create(
        &state.pool,
        username,
        &password_hash,
        &subsonic_secret,
        role.as_str(),
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(AdminUserDto {
            id: user.id,
            username: user.username,
            role: user.role,
            is_active: user.is_active,
        }),
    ))
}

pub async fn update_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<Json<AdminUserDto>, ApiError> {
    auth::require_admin(&state, &headers).await?;

    let Some(current) = users::get(&state.pool, id).await? else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "user not found"));
    };

    let role = request.role.as_deref().map(parse_role).transpose()?;
    let new_role = role.map_or_else(|| current.role.clone(), |role| role.as_str().to_owned());
    let new_active = request.is_active.unwrap_or(current.is_active);

    if current.role == "admin"
        && current.is_active
        && (new_role.as_str() != "admin" || !new_active)
        && users::count_active_admins(&state.pool).await? <= 1
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "cannot remove the last active administrator",
        ));
    }

    if role.is_some() {
        users::update_role(&state.pool, id, &new_role).await?;
    }

    if request.is_active.is_some() {
        users::update_active(&state.pool, id, new_active).await?;
    }

    if let Some(password) = request.password.as_deref() {
        if password.chars().count() < 8 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "password must contain at least 8 characters",
            ));
        }

        let password_hash = mc_auth::hash_password(password)?;
        users::update_password(&state.pool, id, &password_hash).await?;
    }

    let user = users::get(&state.pool, id)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "user not found"))?;

    Ok(Json(AdminUserDto {
        id: user.id,
        username: user.username,
        role: user.role,
        is_active: user.is_active,
    }))
}

pub async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let current = auth::require_admin(&state, &headers).await?;

    if current.id == id {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "cannot delete the current user",
        ));
    }

    let Some(user) = users::get(&state.pool, id).await? else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "user not found"));
    };

    if user.role == "admin" && user.is_active && users::count_active_admins(&state.pool).await? <= 1
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "cannot delete the last active administrator",
        ));
    }

    if users::delete(&state.pool, id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::new(StatusCode::NOT_FOUND, "user not found"))
    }
}

fn parse_role(value: &str) -> Result<Role, ApiError> {
    value.parse().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "role must be admin, uploader or listener",
        )
    })
}

pub async fn list_jobs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<mc_jobs::JobRecord>>, ApiError> {
    auth::require_admin(&state, &headers).await?;
    Ok(Json(mc_jobs::list(&state.pool, 100).await?))
}

pub async fn retry_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    auth::require_admin(&state, &headers).await?;

    if mc_jobs::retry(&state.pool, id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::new(StatusCode::NOT_FOUND, "job not found"))
    }
}
