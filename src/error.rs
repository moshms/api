use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use mc_core::CoreError;
use serde::Serialize;

pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl From<CoreError> for ApiError {
    fn from(error: CoreError) -> Self {
        let status = match error {
            CoreError::NotFound { .. } => StatusCode::NOT_FOUND,
            CoreError::Validation(_) => StatusCode::BAD_REQUEST,
            CoreError::Conflict(_) => StatusCode::CONFLICT,
            CoreError::Unauthorized => StatusCode::UNAUTHORIZED,
            CoreError::Forbidden => StatusCode::FORBIDDEN,
            CoreError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            CoreError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        Self::new(status, error.to_string())
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}
