use axum::extract::{Path, State};
use axum::http::header::{AUTHORIZATION, COOKIE, SET_COOKIE, USER_AGENT};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use mc_authz::Permissions;
use mc_core::Role;
use mc_db::repos::roles::RoleRecord;
use mc_db::repos::{api_tokens, sessions, users};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::{info, warn};
use uuid::Uuid;

use crate::authz::{self, AuthzContext};
use crate::config::Config;
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub id: Uuid,
    pub username: String,
    pub role: Role,
    pub subsonic_secret: String,
    pub authz: AuthzContext,
}

impl AuthUser {
    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.authz.is_admin()
    }

    #[must_use]
    pub fn can(&self, permission: Permissions) -> bool {
        self.authz.can(permission)
    }

    #[must_use]
    pub fn can_library(&self, library_id: Uuid, permission: Permissions) -> bool {
        self.authz.can_library(library_id, permission)
    }

    #[must_use]
    pub fn visible_library_ids(&self) -> Vec<Uuid> {
        self.authz.visible_library_ids()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RoleDto {
    pub id: Uuid,
    pub name: String,
    pub color: Option<i32>,
    pub position: i32,
    pub permissions: u64,
    pub is_everyone: bool,
    pub member_count: i64,
}

impl From<&RoleRecord> for RoleDto {
    fn from(role: &RoleRecord) -> Self {
        Self {
            id: role.id,
            name: role.name.clone(),
            color: role.color,
            position: role.position,
            permissions: u64::try_from(role.permissions.max(0)).unwrap_or(0),
            is_everyone: role.is_everyone,
            member_count: role.member_count,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LibraryPermissionDto {
    pub id: Uuid,
    pub name: String,
    pub permissions: u64,
}

#[derive(Debug, Serialize)]
pub struct UserDto {
    pub id: Uuid,
    pub username: String,
    pub role: Role,
    pub roles: Vec<RoleDto>,
    pub permissions: u64,
    pub libraries: Vec<LibraryPermissionDto>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct SetupStatus {
    pub required: bool,
    pub token_required: bool,
}

#[derive(Debug, Deserialize)]
pub struct SetupRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub setup_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenCreateRequest {
    pub name: String,
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct TokenCreated {
    pub id: Uuid,
    pub name: String,
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct SubsonicCredentials {
    pub username: String,
    pub password: String,
}

pub async fn ensure_admin(pool: &mc_db::PgPool, config: &Config) -> anyhow::Result<()> {
    if users::count(pool).await? > 0 {
        return Ok(());
    }

    let (Some(username), Some(password)) = (&config.admin_user, &config.admin_password) else {
        warn!("no users exist and MC_ADMIN_USER/MC_ADMIN_PASSWORD are not set");
        return Ok(());
    };

    let username = username.trim();
    if username.is_empty() || password.is_empty() {
        warn!("no users exist and admin credentials are empty");
        return Ok(());
    }

    if password.chars().count() < 12 || password.eq_ignore_ascii_case("change-me") {
        anyhow::bail!("MC_ADMIN_PASSWORD must be at least 12 characters and not change-me");
    }

    let password_hash = mc_auth::hash_password(password)?;
    let subsonic_secret = mc_auth::generate_secret();

    if let Some(user) = create_first_admin(pool, username, &password_hash, &subsonic_secret).await?
    {
        info!(%username, "created initial administrator");
        let _ = user;
    }

    Ok(())
}

pub async fn setup_status(State(state): State<AppState>) -> Result<Json<SetupStatus>, ApiError> {
    let required = users::count(&state.pool).await? == 0;
    Ok(Json(SetupStatus {
        required,
        token_required: required && state.setup_token.is_some(),
    }))
}

pub async fn setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SetupRequest>,
) -> Result<Response, ApiError> {
    let expected = state
        .setup_token
        .as_deref()
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "setup is already complete"))?;
    let provided = request
        .setup_token
        .as_deref()
        .or_else(|| {
            headers
                .get("x-setup-token")
                .and_then(|value| value.to_str().ok())
        })
        .unwrap_or("");

    if provided.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() != 1 {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid setup token",
        ));
    }

    let username = request.username.trim();
    if username.is_empty() || username.chars().count() > 100 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "username must be between 1 and 100 characters",
        ));
    }

    validate_password(&request.password)?;

    let password_hash = mc_auth::hash_password(&request.password)?;
    let subsonic_secret = mc_auth::generate_secret();
    let user = create_first_admin(&state.pool, username, &password_hash, &subsonic_secret)
        .await
        .map_err(|error| ApiError::internal(error.to_string()))?
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "setup is already complete"))?;

    info!(%username, "created initial administrator via setup");
    issue_session(&state, &headers, &user).await
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    let key = login_key(&headers, request.username.trim());
    if let Some(remaining) = state.login_limiter.blocked_for(&key) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "too many login attempts, retry in {} seconds",
                remaining.as_secs().max(1)
            ),
        ));
    }

    let user = users::find_by_username(&state.pool, request.username.trim())
        .await?
        .filter(|user| user.is_active);

    let Some(user) = user else {
        state.login_limiter.record_failure(&key);
        return Err(invalid_credentials());
    };

    if !mc_auth::verify_password(&user.password_hash, &request.password)? {
        state.login_limiter.record_failure(&key);
        return Err(invalid_credentials());
    }

    state.login_limiter.record_success(&key);
    issue_session(&state, &headers, &user).await
}

async fn issue_session(
    state: &AppState,
    headers: &HeaderMap,
    user: &users::UserRecord,
) -> Result<Response, ApiError> {
    let token = mc_auth::generate_token();
    let token_hash = mc_auth::hash_token(&token);
    let client_name = headers
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(200).collect::<String>());

    sessions::create(
        &state.pool,
        user.id,
        &token_hash,
        state.session_ttl_hours,
        client_name.as_deref(),
    )
    .await?;

    let authz = authz::load(&state.pool, user.id).await?;
    let body = user_dto(user, &authz);
    let mut response = Json(body).into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&session_cookie(
            &token,
            state.session_ttl_hours,
            state.cookie_secure,
        ))
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "invalid cookie"))?,
    );

    Ok(response)
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if let Some(token) = session_token(&headers) {
        let token_hash = mc_auth::hash_token(token);
        sessions::delete(&state.pool, &token_hash).await?;
    }

    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&clear_cookie(state.cookie_secure))
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "invalid cookie"))?,
    );

    Ok(response)
}

pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<UserDto>, ApiError> {
    let user = authenticate(&state, &headers).await?;

    Ok(Json(UserDto {
        id: user.id,
        username: user.username,
        role: user.role,
        roles: user.authz.roles.iter().map(RoleDto::from).collect(),
        permissions: user.authz.server.bits(),
        libraries: user
            .authz
            .libraries
            .iter()
            .filter(|library| {
                user.authz.is_admin() || library.permissions.intersects(Permissions::LIBRARY_BITS)
            })
            .map(|library| LibraryPermissionDto {
                id: library.id,
                name: library.name.clone(),
                permissions: library.permissions.bits(),
            })
            .collect(),
    }))
}

pub async fn subsonic_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SubsonicCredentials>, ApiError> {
    let user = authenticate(&state, &headers).await?;

    Ok(Json(SubsonicCredentials {
        username: user.username,
        password: user.subsonic_secret,
    }))
}

pub async fn create_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TokenCreateRequest>,
) -> Result<(StatusCode, Json<TokenCreated>), ApiError> {
    let user = authenticate(&state, &headers).await?;
    let name = request.name.trim();

    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "token name must be between 1 and 100 characters",
        ));
    }

    if let Some(days) = request.expires_in_days {
        if !(1..=3650).contains(&days) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "expires_in_days must be between 1 and 3650",
            ));
        }
    }

    let token = mc_auth::generate_token();
    let token_hash = mc_auth::hash_token(&token);
    let id = api_tokens::create(
        &state.pool,
        user.id,
        name,
        &token_hash,
        request.expires_in_days,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(TokenCreated {
            id,
            name: name.to_owned(),
            token,
        }),
    ))
}

pub async fn list_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<api_tokens::ApiTokenRecord>>, ApiError> {
    let user = authenticate(&state, &headers).await?;
    Ok(Json(api_tokens::list(&state.pool, user.id).await?))
}

pub async fn delete_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let user = authenticate(&state, &headers).await?;

    if api_tokens::delete(&state.pool, user.id, id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::new(StatusCode::NOT_FOUND, "token not found"))
    }
}

pub async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<AuthUser, ApiError> {
    if let Some(token) = bearer_token(headers) {
        let token_hash = mc_auth::hash_token(token);

        if let Some(user) = api_tokens::find_user(&state.pool, &token_hash).await? {
            let _ = api_tokens::touch(&state.pool, &token_hash).await;
            return auth_user(
                &state.pool,
                user.user_id,
                user.username,
                &user.role,
                user.subsonic_secret,
            )
            .await;
        }

        return Err(authentication_required());
    }

    let Some(token) = session_token(headers) else {
        return Err(authentication_required());
    };
    let token_hash = mc_auth::hash_token(token);

    let Some(user) = sessions::find_active(&state.pool, &token_hash).await? else {
        return Err(authentication_required());
    };

    let _ = sessions::touch(&state.pool, &token_hash).await;
    auth_user(
        &state.pool,
        user.user_id,
        user.username,
        &user.role,
        user.subsonic_secret,
    )
    .await
}

pub async fn require_permission(
    state: &AppState,
    headers: &HeaderMap,
    permission: Permissions,
) -> Result<AuthUser, ApiError> {
    let user = authenticate(state, headers).await?;

    if user.can(permission) {
        Ok(user)
    } else {
        Err(ApiError::new(StatusCode::FORBIDDEN, "permission denied"))
    }
}

async fn auth_user(
    pool: &mc_db::PgPool,
    id: Uuid,
    username: String,
    role: &str,
    subsonic_secret: String,
) -> Result<AuthUser, ApiError> {
    let authz = authz::load(pool, id).await?;

    Ok(AuthUser {
        id,
        username,
        role: role_from_str(role)?,
        subsonic_secret,
        authz,
    })
}

fn user_dto(user: &users::UserRecord, authz: &AuthzContext) -> UserDto {
    UserDto {
        id: user.id,
        username: user.username.clone(),
        role: role_from_str(&user.role).unwrap_or(Role::Listener),
        roles: authz.roles.iter().map(RoleDto::from).collect(),
        permissions: authz.server.bits(),
        libraries: authz
            .libraries
            .iter()
            .filter(|library| {
                authz.is_admin() || library.permissions.intersects(Permissions::LIBRARY_BITS)
            })
            .map(|library| LibraryPermissionDto {
                id: library.id,
                name: library.name.clone(),
                permissions: library.permissions.bits(),
            })
            .collect(),
    }
}

async fn create_first_admin(
    pool: &mc_db::PgPool,
    username: &str,
    password_hash: &str,
    subsonic_secret: &str,
) -> anyhow::Result<Option<users::UserRecord>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(42424242)")
        .execute(&mut *transaction)
        .await?;

    let count = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM users")
        .fetch_one(&mut *transaction)
        .await?;
    if count > 0 {
        transaction.rollback().await?;
        return Ok(None);
    }

    let user = sqlx::query_as::<_, users::UserRecord>(
        "INSERT INTO users (id, username, password_hash, subsonic_secret, role)
         VALUES ($1, $2, $3, $4, 'admin')
         RETURNING id, username, password_hash, subsonic_secret, role, is_active",
    )
    .bind(Uuid::now_v7())
    .bind(username)
    .bind(password_hash)
    .bind(subsonic_secret)
    .fetch_one(&mut *transaction)
    .await?;

    let admin_role = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM roles
         WHERE NOT is_everyone AND (permissions & 1) <> 0
         LIMIT 1",
    )
    .fetch_optional(&mut *transaction)
    .await?;

    let Some(admin_role) = admin_role else {
        anyhow::bail!("administrator role is missing");
    };

    sqlx::query(
        "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)
         ON CONFLICT DO NOTHING",
    )
    .bind(user.id)
    .bind(admin_role)
    .execute(&mut *transaction)
    .await?;

    transaction.commit().await?;
    Ok(Some(user))
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

fn role_from_str(value: &str) -> Result<Role, ApiError> {
    value.parse().map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid user role in database",
        )
    })
}

fn login_key(headers: &HeaderMap, username: &str) -> String {
    let ip = headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(',').next())
        })
        .unwrap_or("-");

    format!("{}:{ip}", username.to_lowercase())
}

fn invalid_credentials() -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "invalid username or password")
}

fn authentication_required() -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "authentication required")
}

fn session_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let (name, value) = cookie.trim().split_once('=')?;
                (name == mc_auth::SESSION_COOKIE).then_some(value)
            })
        })
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn session_cookie(token: &str, ttl_hours: i64, secure: bool) -> String {
    let max_age = ttl_hours.saturating_mul(3600);
    let mut cookie = format!(
        "{}={token}; HttpOnly; Path=/; SameSite=Lax; Max-Age={max_age}",
        mc_auth::SESSION_COOKIE
    );

    if secure {
        cookie.push_str("; Secure");
    }

    cookie
}

fn clear_cookie(secure: bool) -> String {
    let mut cookie = format!(
        "{}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0",
        mc_auth::SESSION_COOKIE
    );

    if secure {
        cookie.push_str("; Secure");
    }

    cookie
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::{bearer_token, session_cookie, session_token};

    #[test]
    fn extracts_session_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("other=1; mc_session=abc123; theme=dark"),
        );

        assert_eq!(session_token(&headers), Some("abc123"));
    }

    #[test]
    fn extracts_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret"),
        );

        assert_eq!(bearer_token(&headers), Some("secret"));
    }

    #[test]
    fn session_cookie_has_security_flags() {
        let cookie = session_cookie("token", 1, true);
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("Max-Age=3600"));
    }
}
