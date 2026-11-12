use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use mc_authz::{PermissionInfo, Permissions, PERMISSIONS};
use mc_db::repos::audit::{self, AuditRecord};
use mc_db::repos::roles;
use mc_db::repos::users;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::{self, AuthUser, RoleDto};
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    #[serde(default)]
    pub color: Option<i32>,
    pub permissions: u64,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub color: Option<i32>,
    #[serde(default)]
    pub permissions: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct ReorderRolesRequest {
    pub ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct UserAvailableDto {
    pub id: Uuid,
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct RoleAvailableDto {
    pub id: Uuid,
    pub name: String,
    pub color: Option<i32>,
    pub is_everyone: bool,
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<RoleDto>>, ApiError> {
    auth::require_permission(&state, &headers, Permissions::MANAGE_ROLES).await?;
    let roles = roles::list(&state.pool).await?;
    Ok(Json(roles.iter().map(RoleDto::from).collect()))
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<RoleDto>), ApiError> {
    let actor = auth::require_permission(&state, &headers, Permissions::MANAGE_ROLES).await?;
    let name = validate_name(&request.name)?;
    let permissions = validate_permissions(&actor, request.permissions)?;
    let role = roles::create(
        &state.pool,
        name,
        request.color,
        i64::try_from(permissions.bits()).unwrap_or(i64::MAX),
    )
    .await?;

    audit::log(
        &state.pool,
        Some(actor.id),
        "role.create",
        "role",
        Some(role.id),
        json!({ "name": role.name, "permissions": permissions.bits() }),
    )
    .await?;

    Ok((StatusCode::CREATED, Json(RoleDto::from(&role))))
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateRoleRequest>,
) -> Result<Json<RoleDto>, ApiError> {
    let actor = auth::require_permission(&state, &headers, Permissions::MANAGE_ROLES).await?;
    let Some(current) = roles::get(&state.pool, id).await? else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "role not found"));
    };

    let permissions = match request.permissions {
        Some(value) => validate_permissions(&actor, value)?,
        None => Permissions::from_bits(u64::try_from(current.permissions.max(0)).unwrap_or(0)),
    };

    if current.is_everyone {
        if request.name.is_some() || request.color.is_some() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "the everyone role can only change permissions",
            ));
        }
        roles::update_everyone(
            &state.pool,
            i64::try_from(permissions.bits()).unwrap_or(i64::MAX),
        )
        .await?;
    } else {
        let name = request.name.as_deref().map(validate_name).transpose()?;
        let name = name.unwrap_or(&current.name);
        roles::update(
            &state.pool,
            id,
            name,
            request.color.or(current.color),
            i64::try_from(permissions.bits()).unwrap_or(i64::MAX),
        )
        .await?;
    }

    let role = roles::get(&state.pool, id)
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "role not found"))?;

    audit::log(
        &state.pool,
        Some(actor.id),
        "role.update",
        "role",
        Some(id),
        json!({ "name": role.name, "permissions": permissions.bits() }),
    )
    .await?;

    Ok(Json(RoleDto::from(&role)))
}

pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let actor = auth::require_permission(&state, &headers, Permissions::MANAGE_ROLES).await?;
    let Some(role) = roles::get(&state.pool, id).await? else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "role not found"));
    };

    if role.is_everyone {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "the everyone role cannot be deleted",
        ));
    }

    if role.permissions & 1 != 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "administrator roles cannot be deleted",
        ));
    }

    if !roles::delete(&state.pool, id).await? {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "role not found"));
    }

    audit::log(
        &state.pool,
        Some(actor.id),
        "role.delete",
        "role",
        Some(id),
        json!({ "name": role.name }),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn reorder(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ReorderRolesRequest>,
) -> Result<StatusCode, ApiError> {
    let actor = auth::require_permission(&state, &headers, Permissions::MANAGE_ROLES).await?;

    for id in &request.ids {
        if roles::get(&state.pool, *id).await?.is_none() {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "role not found"));
        }
    }

    roles::reorder(&state.pool, &request.ids).await?;

    audit::log(
        &state.pool,
        Some(actor.id),
        "role.reorder",
        "role",
        None,
        json!({ "ids": request.ids }),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn assign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((user_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let actor = auth::require_permission(&state, &headers, Permissions::MANAGE_ROLES).await?;
    let Some(role) = roles::get(&state.pool, role_id).await? else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "role not found"));
    };

    if role.is_everyone {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "the everyone role is assigned automatically",
        ));
    }

    if role.permissions & 1 != 0 && !actor.is_admin() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "only administrators can grant the administrator role",
        ));
    }

    if users::get(&state.pool, user_id).await?.is_none() {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "user not found"));
    }

    roles::assign(&state.pool, user_id, role_id).await?;

    audit::log(
        &state.pool,
        Some(actor.id),
        "role.assign",
        "user",
        Some(user_id),
        json!({ "role_id": role_id, "role": role.name }),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn unassign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((user_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let actor = auth::require_permission(&state, &headers, Permissions::MANAGE_ROLES).await?;
    let Some(role) = roles::get(&state.pool, role_id).await? else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "role not found"));
    };

    if role.permissions & 1 != 0
        && roles::has_admin_role(&state.pool, user_id).await?
        && roles::count_active_admins(&state.pool).await? <= 1
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "cannot remove the last active administrator",
        ));
    }

    if !roles::unassign(&state.pool, user_id, role_id).await? {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "role assignment not found",
        ));
    }

    audit::log(
        &state.pool,
        Some(actor.id),
        "role.unassign",
        "user",
        Some(user_id),
        json!({ "role_id": role_id, "role": role.name }),
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn available_roles(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<RoleAvailableDto>>, ApiError> {
    let actor = auth::authenticate(&state, &headers).await?;
    if !actor.can(Permissions::PLAYLIST_SHARE)
        && !actor.can(Permissions::MANAGE_ROLES)
        && !actor.can(Permissions::MANAGE_LIBRARIES)
    {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "permission denied"));
    }

    let roles = roles::list(&state.pool).await?;
    Ok(Json(
        roles
            .iter()
            .map(|role| RoleAvailableDto {
                id: role.id,
                name: role.name.clone(),
                color: role.color,
                is_everyone: role.is_everyone,
            })
            .collect(),
    ))
}

pub async fn available_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<UserAvailableDto>>, ApiError> {
    let actor = auth::authenticate(&state, &headers).await?;
    if !actor.can(Permissions::PLAYLIST_SHARE)
        && !actor.can(Permissions::MANAGE_USERS)
        && !actor.can(Permissions::MANAGE_LIBRARIES)
    {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "permission denied"));
    }

    let users = users::list(&state.pool).await?;
    Ok(Json(
        users
            .iter()
            .filter(|user| user.is_active)
            .map(|user| UserAvailableDto {
                id: user.id,
                username: user.username.clone(),
            })
            .collect(),
    ))
}

pub async fn permission_catalog(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<&'static [PermissionInfo]>, ApiError> {
    auth::require_permission(&state, &headers, Permissions::MANAGE_ROLES).await?;
    Ok(Json(PERMISSIONS))
}

pub async fn audit_log(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AuditRecord>>, ApiError> {
    auth::require_permission(&state, &headers, Permissions::VIEW_AUDIT_LOG).await?;
    Ok(Json(audit::list(&state.pool, 200).await?))
}

fn validate_name(value: &str) -> Result<&str, ApiError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 100 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "role name must be between 1 and 100 characters",
        ));
    }
    Ok(value)
}

fn validate_permissions(actor: &AuthUser, value: u64) -> Result<Permissions, ApiError> {
    let permissions = Permissions::from_bits(value);
    if permissions.bits() != value {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "unknown permission bits",
        ));
    }

    if !actor.is_admin() {
        let allowed = actor
            .authz
            .libraries
            .iter()
            .fold(actor.authz.server, |current, library| {
                current.union(library.permissions)
            });
        if !permissions.difference(allowed).is_empty() {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "cannot grant permissions you do not have",
            ));
        }
    }

    Ok(permissions)
}
