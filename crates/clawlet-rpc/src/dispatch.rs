//! Request/response types for auth operations.
//!
//! These types are shared between the server handlers and tests.

use serde::{Deserialize, Serialize};

/// Request body for granting a new session.
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthGrantRequest {
    /// Password for authentication.
    pub password: String,
    /// Agent identifier to grant the session to.
    pub agent_id: String,
    /// Scope for the session (read, trade, admin).
    pub scope: String,
}

/// Response for auth grant.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthGrantResponse {
    /// The session token to use for authentication.
    pub token: String,
    /// When the session expires (ISO 8601).
    pub expires_at: String,
}

/// Request body for revoking all sessions for an agent.
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthRevokeRequest {
    /// Password for authentication.
    pub password: String,
    /// Agent identifier whose sessions should all be revoked.
    pub agent_id: String,
}

/// Request body for revoking a single session by key.
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthRevokeSessionRequest {
    /// Password for authentication.
    pub password: String,
    /// Session key (hex-encoded token hash) to revoke.
    pub session_key: String,
}

/// Request body for revoking all sessions.
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthRevokeAllRequest {
    /// Password for authentication.
    pub password: String,
}

/// Request body for listing sessions (password required).
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthListRequest {
    /// Password for authentication.
    pub password: String,
}

/// A single session summary in the list response.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionSummary {
    /// Session key (hex-encoded token hash), used to revoke individual sessions.
    pub session_key: String,
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
    /// Whether this session has expired (still in grace period).
    pub is_expired: bool,
}

/// Response for auth list.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthListResponse {
    /// All sessions (including expired ones still within the grace period).
    pub sessions: Vec<SessionSummary>,
}

/// Response for auth revoke (by agent ID).
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRevokeResponse {
    /// Whether any sessions were revoked.
    pub revoked: bool,
}

/// Response for auth revoke session (by session key).
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRevokeSessionResponse {
    /// Whether the session was revoked.
    pub revoked: bool,
}

/// Response for auth revoke all.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRevokeAllResponse {
    /// Number of sessions revoked.
    pub count: usize,
}
