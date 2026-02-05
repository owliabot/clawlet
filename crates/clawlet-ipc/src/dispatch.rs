//! Request dispatch — routes incoming IPC requests to the appropriate handler.
//!
//! Replaces the old axum router with a simple match on [`RpcMethod`].

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use clawlet_core::auth::{self, AuthError, TokenScope};

use crate::handlers::{self, BalanceQuery, ExecuteRequest, HandlerError, TransferRequest};
use crate::server::AppState;
use crate::types::{RpcMethod, RpcRequest, RpcResponse, RpcStatus};

/// Request body for granting a new session.
#[derive(Debug, Deserialize)]
pub struct AuthGrantRequest {
    /// Password for authentication.
    pub password: String,
    /// Agent identifier to grant the session to.
    pub agent_id: String,
    /// Scope for the session (read, trade, admin).
    pub scope: String,
    /// Session duration in hours (optional, uses default if not specified).
    #[serde(default)]
    pub expires_hours: Option<u64>,
}

/// Response for auth grant.
#[derive(Debug, Serialize)]
pub struct AuthGrantResponse {
    /// The session token to use for authentication.
    pub token: String,
    /// When the session expires (ISO 8601).
    pub expires_at: String,
}

/// Request body for revoking a session.
#[derive(Debug, Deserialize)]
pub struct AuthRevokeRequest {
    /// Password for authentication.
    pub password: String,
    /// Agent identifier to revoke.
    pub agent_id: String,
}

/// Request body for revoking all sessions.
#[derive(Debug, Deserialize)]
pub struct AuthRevokeAllRequest {
    /// Password for authentication.
    pub password: String,
}

/// Request body for listing sessions (password required).
#[derive(Debug, Deserialize)]
pub struct AuthListRequest {
    /// Password for authentication.
    pub password: String,
}

/// A single session summary in the list response.
#[derive(Debug, Serialize)]
pub struct SessionSummary {
    /// Agent identifier.
    pub id: String,
    /// Session scope.
    pub scope: String,
    /// When the session was created (ISO 8601).
    pub created_at: String,
    /// When the session expires (ISO 8601).
    pub expires_at: String,
    /// When the session was last used (ISO 8601).
    pub last_used_at: String,
    /// Number of requests made with this session.
    pub request_count: u64,
}

/// Response for auth list.
#[derive(Debug, Serialize)]
pub struct AuthListResponse {
    /// Active sessions.
    pub sessions: Vec<SessionSummary>,
}

/// Response for auth revoke.
#[derive(Debug, Serialize)]
pub struct AuthRevokeResponse {
    /// Whether the session was revoked.
    pub revoked: bool,
}

/// Response for auth revoke all.
#[derive(Debug, Serialize)]
pub struct AuthRevokeAllResponse {
    /// Number of sessions revoked.
    pub count: usize,
}

/// Dispatch a single [`RpcRequest`] to the appropriate handler and produce an [`RpcResponse`].
///
/// Auth is checked here for all methods except [`RpcMethod::Health`].
/// Async handlers are executed via the provided tokio runtime handle.
pub fn dispatch(
    state: &AppState,
    request: &RpcRequest,
    rt: &tokio::runtime::Handle,
) -> RpcResponse {
    let method = match request.rpc_method() {
        Some(m) => m,
        None => {
            warn!(method = request.method, "unknown RPC method");
            return RpcResponse::error(RpcStatus::BadRequest, "unknown method");
        }
    };

    // Check auth for protected methods
    if let Some(required_scope) = method.required_scope() {
        match check_auth(state, request, required_scope) {
            Ok(_) => {}
            Err(e) => {
                warn!("unauthorized request for {:?}: {}", method, e);
                return auth_error_to_response(e);
            }
        }
    }

    info!(?method, "dispatching RPC request");

    match method {
        RpcMethod::Health => {
            let result = handlers::handle_health(state);
            let json = serde_json::to_vec(&result).unwrap_or_default();
            RpcResponse::ok(&json)
        }
        RpcMethod::Balance => {
            let query: BalanceQuery = match serde_json::from_slice(request.payload_bytes()) {
                Ok(q) => q,
                Err(e) => {
                    return RpcResponse::error(
                        RpcStatus::BadRequest,
                        &format!("invalid payload: {e}"),
                    )
                }
            };
            match rt.block_on(handlers::handle_balance(state, query)) {
                Ok(resp) => {
                    let json = serde_json::to_vec(&resp).unwrap_or_default();
                    RpcResponse::ok(&json)
                }
                Err(e) => handler_error_to_response(e),
            }
        }
        RpcMethod::Transfer => {
            let req: TransferRequest = match serde_json::from_slice(request.payload_bytes()) {
                Ok(r) => r,
                Err(e) => {
                    return RpcResponse::error(
                        RpcStatus::BadRequest,
                        &format!("invalid payload: {e}"),
                    )
                }
            };
            match rt.block_on(handlers::handle_transfer(state, req)) {
                Ok(resp) => {
                    let json = serde_json::to_vec(&resp).unwrap_or_default();
                    RpcResponse::ok(&json)
                }
                Err(e) => handler_error_to_response(e),
            }
        }
        RpcMethod::Skills => match handlers::handle_skills(state) {
            Ok(resp) => {
                let json = serde_json::to_vec(&resp).unwrap_or_default();
                RpcResponse::ok(&json)
            }
            Err(e) => handler_error_to_response(e),
        },
        RpcMethod::Execute => {
            let req: ExecuteRequest = match serde_json::from_slice(request.payload_bytes()) {
                Ok(r) => r,
                Err(e) => {
                    return RpcResponse::error(
                        RpcStatus::BadRequest,
                        &format!("invalid payload: {e}"),
                    )
                }
            };
            match rt.block_on(handlers::handle_execute(state, req)) {
                Ok(resp) => {
                    let json = serde_json::to_vec(&resp).unwrap_or_default();
                    RpcResponse::ok(&json)
                }
                Err(e) => handler_error_to_response(e),
            }
        }
        RpcMethod::AuthGrant => handle_auth_grant(state, request),
        RpcMethod::AuthList => handle_auth_list(state, request),
        RpcMethod::AuthRevoke => handle_auth_revoke(state, request),
        RpcMethod::AuthRevokeAll => handle_auth_revoke_all(state, request),
    }
}

/// Check authentication using the session store.
///
/// For admin auth methods, we verify the password from the request payload.
/// For other methods, we verify the session token from the auth header.
fn check_auth(
    state: &AppState,
    request: &RpcRequest,
    required_scope: TokenScope,
) -> Result<(), AuthError> {
    let token = request.token_str();

    // If no auth is configured (no password hash), allow all requests
    if state.auth_config.password_hash.is_none() {
        return Ok(());
    }

    // If token is empty, deny
    if token.is_empty() {
        return Err(AuthError::InvalidToken);
    }

    // Verify the token and scope
    let mut store = state
        .session_store
        .write()
        .map_err(|_| AuthError::InvalidToken)?;

    store.verify_with_scope(token, required_scope)?;
    Ok(())
}

/// Verify password for admin operations.
fn verify_admin_password(state: &AppState, password: &str) -> Result<(), AuthError> {
    // Check lockout
    {
        let store = state
            .session_store
            .read()
            .map_err(|_| AuthError::InvalidToken)?;
        if store.is_locked_out(
            "admin",
            state.auth_config.max_failed_attempts,
            state.auth_config.lockout_minutes,
        ) {
            return Err(AuthError::TooManyAttempts);
        }
    }

    let password_hash = state
        .auth_config
        .password_hash
        .as_ref()
        .ok_or(AuthError::PasswordIncorrect)?;

    if auth::verify_password(password, password_hash) {
        // Clear failed attempts on success
        if let Ok(mut store) = state.session_store.write() {
            store.clear_failed_attempts("admin");
        }
        Ok(())
    } else {
        // Record failed attempt
        if let Ok(mut store) = state.session_store.write() {
            store.record_failed_attempt("admin");
        }
        Err(AuthError::PasswordIncorrect)
    }
}

/// Handle auth grant request.
fn handle_auth_grant(state: &AppState, request: &RpcRequest) -> RpcResponse {
    let req: AuthGrantRequest = match serde_json::from_slice(request.payload_bytes()) {
        Ok(r) => r,
        Err(e) => {
            return RpcResponse::error(RpcStatus::BadRequest, &format!("invalid payload: {e}"))
        }
    };

    // Verify password
    if let Err(e) = verify_admin_password(state, &req.password) {
        return auth_error_to_response(e);
    }

    // Parse scope
    let scope: TokenScope = match req.scope.parse() {
        Ok(s) => s,
        Err(e) => return auth_error_to_response(e),
    };

    // Calculate expiration
    let expires_hours = req
        .expires_hours
        .unwrap_or(state.auth_config.default_session_ttl_hours);
    let expires_in = Duration::from_secs(expires_hours * 3600);

    // Get current Unix UID (use 0 for unknown)
    #[cfg(unix)]
    let uid = unsafe { libc::getuid() };
    #[cfg(not(unix))]
    let uid = 0u32;

    // Grant the session
    let mut store = match state.session_store.write() {
        Ok(s) => s,
        Err(_) => return RpcResponse::error(RpcStatus::InternalError, "failed to lock store"),
    };

    let token = store.grant(&req.agent_id, scope, expires_in, uid);

    // Get the session to return expiration time
    let session = store.get(&req.agent_id).unwrap();

    let response = AuthGrantResponse {
        token,
        expires_at: session.expires_at.to_rfc3339(),
    };

    let json = serde_json::to_vec(&response).unwrap_or_default();
    RpcResponse::ok(&json)
}

/// Handle auth list request.
fn handle_auth_list(state: &AppState, request: &RpcRequest) -> RpcResponse {
    let req: AuthListRequest = match serde_json::from_slice(request.payload_bytes()) {
        Ok(r) => r,
        Err(e) => {
            return RpcResponse::error(RpcStatus::BadRequest, &format!("invalid payload: {e}"))
        }
    };

    // Verify password
    if let Err(e) = verify_admin_password(state, &req.password) {
        return auth_error_to_response(e);
    }

    let store = match state.session_store.read() {
        Ok(s) => s,
        Err(_) => return RpcResponse::error(RpcStatus::InternalError, "failed to lock store"),
    };

    let sessions: Vec<SessionSummary> = store
        .list()
        .into_iter()
        .map(|s| SessionSummary {
            id: s.id.clone(),
            scope: s.scope.to_string(),
            created_at: s.created_at.to_rfc3339(),
            expires_at: s.expires_at.to_rfc3339(),
            last_used_at: s.last_used_at.to_rfc3339(),
            request_count: s.request_count,
        })
        .collect();

    let response = AuthListResponse { sessions };

    let json = serde_json::to_vec(&response).unwrap_or_default();
    RpcResponse::ok(&json)
}

/// Handle auth revoke request.
fn handle_auth_revoke(state: &AppState, request: &RpcRequest) -> RpcResponse {
    let req: AuthRevokeRequest = match serde_json::from_slice(request.payload_bytes()) {
        Ok(r) => r,
        Err(e) => {
            return RpcResponse::error(RpcStatus::BadRequest, &format!("invalid payload: {e}"))
        }
    };

    // Verify password
    if let Err(e) = verify_admin_password(state, &req.password) {
        return auth_error_to_response(e);
    }

    let mut store = match state.session_store.write() {
        Ok(s) => s,
        Err(_) => return RpcResponse::error(RpcStatus::InternalError, "failed to lock store"),
    };

    let revoked = store.revoke(&req.agent_id);

    let response = AuthRevokeResponse { revoked };

    let json = serde_json::to_vec(&response).unwrap_or_default();
    RpcResponse::ok(&json)
}

/// Handle auth revoke all request.
fn handle_auth_revoke_all(state: &AppState, request: &RpcRequest) -> RpcResponse {
    let req: AuthRevokeAllRequest = match serde_json::from_slice(request.payload_bytes()) {
        Ok(r) => r,
        Err(e) => {
            return RpcResponse::error(RpcStatus::BadRequest, &format!("invalid payload: {e}"))
        }
    };

    // Verify password
    if let Err(e) = verify_admin_password(state, &req.password) {
        return auth_error_to_response(e);
    }

    let mut store = match state.session_store.write() {
        Ok(s) => s,
        Err(_) => return RpcResponse::error(RpcStatus::InternalError, "failed to lock store"),
    };

    let count = store.revoke_all();

    let response = AuthRevokeAllResponse { count };

    let json = serde_json::to_vec(&response).unwrap_or_default();
    RpcResponse::ok(&json)
}

/// Map an [`AuthError`] to an [`RpcResponse`] with appropriate status.
fn auth_error_to_response(err: AuthError) -> RpcResponse {
    match err {
        AuthError::InvalidToken | AuthError::TokenExpired => {
            RpcResponse::error(RpcStatus::Unauthorized, &err.to_string())
        }
        AuthError::InsufficientScope { .. } => {
            RpcResponse::error(RpcStatus::Unauthorized, &err.to_string())
        }
        AuthError::PasswordIncorrect => {
            RpcResponse::error(RpcStatus::Unauthorized, "incorrect password")
        }
        AuthError::TooManyAttempts => RpcResponse::error(RpcStatus::Unauthorized, &err.to_string()),
        AuthError::InvalidScope(ref s) => {
            RpcResponse::error(RpcStatus::BadRequest, &format!("invalid scope: {s}"))
        }
        AuthError::SessionNotFound(ref s) => {
            RpcResponse::error(RpcStatus::NotFound, &format!("session not found: {s}"))
        }
        AuthError::HashingError(ref s) => {
            RpcResponse::error(RpcStatus::InternalError, &format!("hashing error: {s}"))
        }
    }
}

/// Map a [`HandlerError`] to an [`RpcResponse`] with appropriate status.
fn handler_error_to_response(err: HandlerError) -> RpcResponse {
    match err {
        HandlerError::BadRequest(msg) => RpcResponse::error(RpcStatus::BadRequest, &msg),
        HandlerError::NotFound(msg) => RpcResponse::error(RpcStatus::NotFound, &msg),
        HandlerError::Internal(msg) => RpcResponse::error(RpcStatus::InternalError, &msg),
    }
}
