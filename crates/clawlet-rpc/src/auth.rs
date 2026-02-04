//! Token-based authentication middleware.
//!
//! Validates bearer tokens on incoming requests.

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;

use crate::server::AppState;

/// Axum middleware that validates Bearer token authentication.
///
/// If the server's `auth_token` is empty, authentication is skipped
/// (useful for development). Otherwise, requests must include a valid
/// `Authorization: Bearer <token>` header.
pub async fn auth_middleware(
    axum::extract::State(state): axum::extract::State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // If no auth token is configured, skip authentication
    if state.auth_token.is_empty() {
        return Ok(next.run(request).await);
    }

    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let token = &header[7..];
            if token == state.auth_token {
                Ok(next.run(request).await)
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
