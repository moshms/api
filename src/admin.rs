use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use mc_authz::Permissions;
use mc_core::Role;
use mc_db::repos::audit;
use mc_db::repos::libraries::{self, LibraryRecord};
use mc_db::repos::permissions;
use mc_db::repos::roles;
use mc_db::repos::storages::{self, StorageRecord};
use mc_db::repos::users::{self, UserSummary};
use mc_storage::Key;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::auth::{self, RoleDto};
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LibraryAccessRequest {
    #[serde(default)]
    pub everyone: bool,
    #[serde(default)]
    pub roles: Vec<Uuid>,
    #[serde(default)]
    pub users: Vec<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct CreateLibraryRequest {
    pub name: String,
    pub storage_id: Uuid,
    #[serde(default)]
    pub root_prefix: Option<String>,
    #[serde(default)]
    pub is_import_target: Option<bool>,
    #[serde(default)]
    pub access: Option<LibraryAccessRequest>,
}

pub async fn list_storages(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<StorageDto>>, ApiError> {
    auth::require_permission(&state, &headers, Permissions::MANAGE_STORAGES).await?;
    let records = storages::list(&state.pool).await?;

    Ok(Json(records.iter().map(StorageDto::from).collect()))
}

pub async fn create_storage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateStorageRequest>,
) -> Result<(StatusCode, Json<StorageDto>), ApiError> {
    auth::require_permission(&state, &headers, Permissions::MANAGE_STORAGES).await?;

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

    if request.kind == "local" {
        let root = request
            .config
            .get("root")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "local storage requires root"))?;
        let canonical = tokio::fs::canonicalize(root).await.map_err(|_| {
            ApiError::new(StatusCode::BAD_REQUEST, "local storage root is unavailable")
        })?;
        let allowed = state.local_storage_roots.iter().any(|base| {
            base.canonicalize()
                .map(|base| canonical.starts_with(base))
                .unwrap_or(false)
        });
        if !allowed {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "local storage root is outside MC_LOCAL_STORAGE_ROOTS",
            ));
        }
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
    auth::require_permission(&state, &headers, Permissions::MANAGE_STORAGES).await?;

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
    auth::require_permission(&state, &headers, Permissions::MANAGE_LIBRARIES).await?;
    Ok(Json(libraries::list(&state.pool).await?))
}

pub async fn create_library(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateLibraryRequest>,
) -> Result<(StatusCode, Json<LibraryRecord>), ApiError> {
    let actor = auth::require_permission(&state, &headers, Permissions::MANAGE_LIBRARIES).await?;

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
    let access_targets = resolve_library_access(&state, request.access.as_ref()).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let library = libraries::create(
        &mut *tx,
        name,
        request.storage_id,
        &root_prefix,
        request.is_import_target.unwrap_or(false),
    )
    .await?;
    let allow = i64::try_from(
        Permissions::LIBRARY_VIEW
            .union(Permissions::LIBRARY_DOWNLOAD)
            .bits(),
    )
    .unwrap_or(i64::MAX);
    for (target_type, target_id) in &access_targets {
        permissions::upsert(
            &mut *tx,
            "library",
            library.id,
            target_type,
            *target_id,
            allow,
            0,
        )
        .await?;
    }
    audit::log(
        &mut *tx,
        Some(actor.id),
        "library.create",
        "library",
        Some(library.id),
        json!({ "name": library.name, "access": request.access }),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;

    reload_registry(&state).await?;
    state.authz_cache.clear();

    Ok((StatusCode::CREATED, Json(library)))
}

pub async fn delete_library(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let actor = auth::require_permission(&state, &headers, Permissions::MANAGE_LIBRARIES).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    if !libraries::delete(&mut *tx, id).await? {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "library not found"));
    }
    audit::log(
        &mut *tx,
        Some(actor.id),
        "library.delete",
        "library",
        Some(id),
        json!({}),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;

    reload_registry(&state).await?;
    state.authz_cache.clear();
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
    pub roles: Vec<RoleDto>,
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
    let actor = auth::authenticate(&state, &headers).await?;
    if !actor.can(Permissions::MANAGE_USERS) && !actor.can(Permissions::MANAGE_ROLES) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "permission denied"));
    }
    let users = users::list(&state.pool).await?;
    let mut result = Vec::with_capacity(users.len());

    for user in &users {
        result.push(admin_user_dto(&state.pool, user).await?);
    }

    Ok(Json(result))
}

pub async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<AdminUserDto>), ApiError> {
    let actor = auth::require_permission(&state, &headers, Permissions::MANAGE_USERS).await?;

    let username = request.username.trim();
    if username.is_empty() || username.chars().count() > 100 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "username must be between 1 and 100 characters",
        ));
    }

    validate_password(&request.password)?;

    let role = parse_role(&request.role)?;
    if role.is_admin() && !actor.is_admin() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "only administrators can create administrators",
        ));
    }
    let password_hash = mc_auth::hash_password(&request.password)?;
    let subsonic_secret = mc_auth::generate_secret();
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let user = users::create(&mut *tx, username, &password_hash, &subsonic_secret).await?;
    sync_legacy_role(&mut tx, user.id, role.as_str(), actor.is_admin()).await?;
    audit::log(
        &mut *tx,
        Some(actor.id),
        "user.create",
        "user",
        Some(user.id),
        json!({ "username": user.username, "role": role.as_str() }),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    state.authz_cache.invalidate(user.id);

    let summary = UserSummary {
        id: user.id,
        username: user.username,
        is_active: user.is_active,
    };

    Ok((
        StatusCode::CREATED,
        Json(admin_user_dto(&state.pool, &summary).await?),
    ))
}

pub async fn update_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<Json<AdminUserDto>, ApiError> {
    let actor = auth::require_permission(&state, &headers, Permissions::MANAGE_USERS).await?;

    let Some(current) = users::get(&state.pool, id).await? else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "user not found"));
    };

    if roles::has_admin_role(&state.pool, id).await? && !actor.is_admin() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "only administrators can edit administrators",
        ));
    }

    let role = request.role.as_deref().map(parse_role).transpose()?;
    if role.is_some_and(Role::is_admin) && !actor.is_admin() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "only administrators can grant the administrator role",
        ));
    }
    let new_active = request.is_active.unwrap_or(current.is_active);
    let currently_admin = roles::has_admin_role(&state.pool, id).await?;
    let new_admin = role.map_or(currently_admin, Role::is_admin);

    if current.is_active
        && (!new_admin || !new_active)
        && currently_admin
        && roles::count_active_admins(&state.pool).await? <= 1
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "cannot remove the last active administrator",
        ));
    }

    if let Some(password) = request.password.as_deref() {
        validate_password(password)?;
    }

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    if let Some(role) = role {
        sync_legacy_role(&mut tx, id, role.as_str(), actor.is_admin()).await?;
    }

    if request.is_active.is_some() {
        users::update_active(&mut *tx, id, new_active).await?;
    }

    if let Some(password) = request.password.as_deref() {
        let password_hash = mc_auth::hash_password(password)?;
        users::update_password(&mut *tx, id, &password_hash).await?;
    }

    audit::log(
        &mut *tx,
        Some(actor.id),
        "user.update",
        "user",
        Some(id),
        json!({ "is_active": new_active }),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    state.authz_cache.invalidate(id);

    let user = users::get(&state.pool, id)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "user not found"))?;

    let summary = UserSummary {
        id: user.id,
        username: user.username,
        is_active: user.is_active,
    };

    Ok(Json(admin_user_dto(&state.pool, &summary).await?))
}

pub async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let current = auth::require_permission(&state, &headers, Permissions::MANAGE_USERS).await?;

    if current.id == id {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "cannot delete the current user",
        ));
    }

    let Some(user) = users::get(&state.pool, id).await? else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "user not found"));
    };

    if roles::has_admin_role(&state.pool, id).await? && !current.is_admin() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "only administrators can delete administrators",
        ));
    }

    if user.is_active
        && roles::has_admin_role(&state.pool, id).await?
        && roles::count_active_admins(&state.pool).await? <= 1
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "cannot delete the last active administrator",
        ));
    }

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    if !users::delete(&mut *tx, id).await? {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "user not found"));
    }
    audit::log(
        &mut *tx,
        Some(current.id),
        "user.delete",
        "user",
        Some(id),
        json!({ "username": user.username }),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?;
    state.authz_cache.invalidate(id);
    Ok(StatusCode::NO_CONTENT)
}

async fn admin_user_dto(
    pool: &mc_db::PgPool,
    user: &UserSummary,
) -> Result<AdminUserDto, ApiError> {
    let roles = roles::for_user(pool, user.id).await?;

    Ok(AdminUserDto {
        id: user.id,
        username: user.username.clone(),
        role: auth::legacy_role(&roles).as_str().to_owned(),
        is_active: user.is_active,
        roles: roles.iter().map(RoleDto::from).collect(),
    })
}

fn validate_password(password: &str) -> Result<(), ApiError> {
    if password.chars().count() < 12 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "password must contain at least 12 characters",
        ));
    }

    if password.eq_ignore_ascii_case("change-me") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "default password is not allowed",
        ));
    }

    Ok(())
}

async fn sync_legacy_role(
    conn: &mut PgConnection,
    user_id: Uuid,
    role: &str,
    actor_is_admin: bool,
) -> Result<(), ApiError> {
    if role == "admin" && !actor_is_admin {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "only administrators can grant the administrator role",
        ));
    }

    let all_roles = roles::list(&mut *conn).await?;
    let admin_role = all_roles
        .iter()
        .find(|role| !role.is_everyone && role.permissions & 1 != 0);
    let uploader_role = all_roles
        .iter()
        .find(|role| !role.is_everyone && role.name.eq_ignore_ascii_case("Загрузчик"));

    match role {
        "admin" => {
            if let Some(role) = admin_role {
                roles::assign(&mut *conn, user_id, role.id).await?;
            }
            if let Some(role) = uploader_role {
                let _ = roles::unassign(&mut *conn, user_id, role.id).await?;
            }
        }
        "uploader" => {
            if let Some(role) = uploader_role {
                roles::assign(&mut *conn, user_id, role.id).await?;
            }
            if let Some(role) = admin_role {
                let _ = roles::unassign(&mut *conn, user_id, role.id).await?;
            }
        }
        _ => {
            if let Some(role) = admin_role {
                let _ = roles::unassign(&mut *conn, user_id, role.id).await?;
            }
            if let Some(role) = uploader_role {
                let _ = roles::unassign(&mut *conn, user_id, role.id).await?;
            }
        }
    }

    Ok(())
}

async fn resolve_library_access(
    state: &AppState,
    access: Option<&LibraryAccessRequest>,
) -> Result<Vec<(&'static str, Uuid)>, ApiError> {
    let Some(access) = access else {
        return Ok(Vec::new());
    };

    let mut targets = Vec::new();
    if access.everyone {
        let everyone = roles::everyone(&state.pool)
            .await?
            .ok_or_else(|| ApiError::internal("everyone role is missing"))?;
        targets.push(("role", everyone.id));
    }

    for role_id in &access.roles {
        if roles::get(&state.pool, *role_id).await?.is_none() {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "role not found"));
        }
        targets.push(("role", *role_id));
    }

    for user_id in &access.users {
        if users::get(&state.pool, *user_id).await?.is_none() {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "user not found"));
        }
        targets.push(("user", *user_id));
    }

    Ok(targets)
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
    auth::require_permission(&state, &headers, Permissions::RUN_SCANS).await?;
    Ok(Json(mc_jobs::list(&state.pool, 100).await?))
}

pub async fn retry_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    auth::require_permission(&state, &headers, Permissions::RUN_SCANS).await?;

    if mc_jobs::retry(&state.pool, id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::new(StatusCode::NOT_FOUND, "job not found"))
    }
}
