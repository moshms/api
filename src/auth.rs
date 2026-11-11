use axum::extract::{Path, State};
use axum::http::header::{AUTHORIZATION, COOKIE, SET_COOKIE, USER_AGENT};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use mc_core::Role;
use mc_db::repos::{api_tokens, sessions, users};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::Config;
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub id: Uuid,
    pub username: String,
    pub role: Role,
    pub subsonic_secret: String,
}

#[derive(Debug, Serialize)]
pub struct UserDto {
    pub id: Uuid,
    pub username: String,
    pub role: Role,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct SetupStatus {
    pub required: bool,
}

#[derive(Debug, Deserialize)]
pub struct SetupRequest {
    pub username: String,
    pub password: String,
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

    let password_hash = mc_auth::hash_password(password)?;
    let subsonic_secret = mc_auth::generate_secret();
    users::create(
        pool,
        username,
        &password_hash,
        &subsonic_secret,
        Role::Admin.as_str(),
    )
    .await?;

    info!(%username, "created initial administrator");
    Ok(())
}

pub async fn setup_status(State(state): State<AppState>) -> Result<Json<SetupStatus>, ApiError> {
    Ok(Json(SetupStatus {
        required: users::count(&state.pool).await? == 0,
    }))
}

pub async fn setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SetupRequest>,
) -> Result<Response, ApiError> {
    if users::count(&state.pool).await? > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "setup is already complete",
        ));
    }

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

    let password_hash = mc_auth::hash_password(&request.password)?;
    let subsonic_secret = mc_auth::generate_secret();
    let user = users::create(
        &state.pool,
        username,
        &password_hash,
        &subsonic_secret,
        Role::Admin.as_str(),
    )
    .await?;

    info!(%username, "created initial administrator via setup");
    issue_session(&state, &headers, &user).await
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    let user = users::find_by_username(&state.pool, request.username.trim())
        .await?
        .filter(|user| user.is_active);

    let Some(user) = user else {
        return Err(invalid_credentials());
    };

    if !mc_auth::verify_password(&user.password_hash, &request.password)? {
        return Err(invalid_credentials());
    }

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

    let body = UserDto {
        id: user.id,
        username: user.username.clone(),
        role: role_from_str(&user.role)?,
    };
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
                user.user_id,
                user.username,
                &user.role,
                user.subsonic_secret,
            );
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
        user.user_id,
        user.username,
        &user.role,
        user.subsonic_secret,
    )
}

pub async fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<AuthUser, ApiError> {
    let user = authenticate(state, headers).await?;

    if user.role.is_admin() {
        Ok(user)
    } else {
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "administrator role required",
        ))
    }
}

fn auth_user(
    id: Uuid,
    username: String,
    role: &str,
    subsonic_secret: String,
) -> Result<AuthUser, ApiError> {
    Ok(AuthUser {
        id,
        username,
        role: role_from_str(role)?,
        subsonic_secret,
    })
}

fn role_from_str(value: &str) -> Result<Role, ApiError> {
    value.parse().map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid user role in database",
        )
    })
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
