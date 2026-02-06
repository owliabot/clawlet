//! HTTP JSON-RPC server using jsonrpsee.
//!
//! Exposes a JSON-RPC 2.0 interface over HTTP at `127.0.0.1:9100` (configurable).
//!
//! # Protocol
//!
//! `POST /` with `Content-Type: application/json`
//!
//! Request format:
//! ```json
//! {"jsonrpc":"2.0","method":"balance","params":{"address":"0x...","chain_id":8453},"id":1}
//! ```
//!
//! Authorization header: `Authorization: Bearer clwt_xxx`
//!
//! Success response:
//! ```json
//! {"jsonrpc":"2.0","result":{"eth":"1.5","tokens":[]},"id":1}
//! ```
//!
//! Error response:
//! ```json
//! {"jsonrpc":"2.0","error":{"code":-32600,"message":"Unauthorized"},"id":1}
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types::ErrorObjectOwned;
use serde_json::Value;
use tracing::info;

use clawlet_core::audit::AuditLogger;
use clawlet_core::auth::{AuthError, SessionStore, TokenScope};
use clawlet_core::config::{AuthConfig, Config};
use clawlet_core::policy::PolicyEngine;
use clawlet_evm::EvmAdapter;
use clawlet_signer::keystore::Keystore;
use clawlet_signer::signer::LocalSigner;

use crate::dispatch::{
    AuthGrantRequest, AuthGrantResponse, AuthListResponse, AuthRevokeAllResponse,
    AuthRevokeResponse, SessionSummary,
};
use crate::handlers::{self, BalanceQuery, ExecuteRequest, HandlerError, TransferRequest};

// ---- Server Error Type ----

/// Errors that can occur when running the RPC server.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Failed to parse or load configuration.
    #[error("config error: {0}")]
    Config(String),

    /// Failed to initialize the policy engine.
    #[error("policy error: {0}")]
    Policy(#[from] clawlet_core::policy::PolicyError),

    /// Failed to create or write to the audit log.
    #[error("audit error: {0}")]
    Audit(#[from] clawlet_core::audit::AuditError),

    /// Failed to create an EVM adapter.
    #[error("evm adapter error: {0}")]
    EvmAdapter(String),

    /// Failed to bind the HTTP listener.
    #[error("bind error: {0}")]
    Bind(String),

    /// I/O error during server operation.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

// ---- JSON-RPC Error Codes ----

/// Standard JSON-RPC 2.0 error codes.
pub mod error_code {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
    // Server-defined errors (-32000 to -32099)
    pub const UNAUTHORIZED: i32 = -32001;
    pub const NOT_FOUND: i32 = -32002;
}

// ---- Application State ----

/// Shared application state available to all handlers.
#[derive(Clone)]
pub struct AppState {
    /// Policy engine for evaluating transfer requests.
    pub policy: Arc<PolicyEngine>,
    /// Audit logger (needs `&mut self`, so wrapped in `Mutex`).
    pub audit: Arc<Mutex<AuditLogger>>,
    /// EVM adapters keyed by chain ID.
    pub adapters: Arc<HashMap<u64, EvmAdapter>>,
    /// Session store for authentication (replaces simple auth_token).
    pub session_store: Arc<RwLock<SessionStore>>,
    /// Authentication configuration.
    pub auth_config: AuthConfig,
    /// Signer for transaction execution.
    pub signer: Arc<LocalSigner>,
    /// Skills directory containing AIS specs.
    pub skills_dir: PathBuf,
    /// Path to keystore directory (for password verification).
    pub keystore_path: PathBuf,
}

// ---- HTTP Server ----

/// Default server address.
pub const DEFAULT_ADDR: &str = "127.0.0.1:9100";

/// HTTP server configuration.
pub struct ServerConfig {
    /// Address to bind to.
    pub addr: SocketAddr,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            addr: DEFAULT_ADDR.parse().unwrap(),
        }
    }
}

// ---- JSON-RPC API Definition ----

/// JSON-RPC API trait using jsonrpsee macros.
#[rpc(server)]
pub trait ClawletApi {
    /// Health check.
    #[method(name = "health")]
    async fn health(&self) -> Result<Value, ErrorObjectOwned>;

    /// Get wallet address.
    #[method(name = "address")]
    async fn address(&self) -> Result<Value, ErrorObjectOwned>;

    /// Query balance.
    #[method(name = "balance")]
    async fn balance(&self, params: BalanceQuery) -> Result<Value, ErrorObjectOwned>;

    /// Execute transfer.
    #[method(name = "transfer")]
    async fn transfer(&self, params: TransferRequest) -> Result<Value, ErrorObjectOwned>;

    /// List available skills.
    #[method(name = "skills")]
    async fn skills(&self) -> Result<Value, ErrorObjectOwned>;

    /// Execute a skill.
    #[method(name = "execute")]
    async fn execute(&self, params: ExecuteRequest) -> Result<Value, ErrorObjectOwned>;

    /// Grant a new session token.
    #[method(name = "auth.grant")]
    async fn auth_grant(&self, params: AuthGrantRequest) -> Result<Value, ErrorObjectOwned>;

    /// List all active sessions.
    #[method(name = "auth.list")]
    async fn auth_list(&self, password: String) -> Result<Value, ErrorObjectOwned>;

    /// Revoke a session.
    #[method(name = "auth.revoke")]
    async fn auth_revoke(
        &self,
        password: String,
        agent_id: String,
    ) -> Result<Value, ErrorObjectOwned>;

    /// Revoke all sessions.
    #[method(name = "auth.revoke_all")]
    async fn auth_revoke_all(&self, password: String) -> Result<Value, ErrorObjectOwned>;
}

/// RPC server implementation.
pub struct RpcServerImpl {
    state: Arc<AppState>,
}

impl RpcServerImpl {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl ClawletApiServer for RpcServerImpl {
    async fn health(&self) -> Result<Value, ErrorObjectOwned> {
        Ok(serde_json::json!({"status": "ok"}))
    }

    async fn address(&self) -> Result<Value, ErrorObjectOwned> {
        match handlers::handle_address(&self.state) {
            Ok(result) => Ok(serde_json::to_value(result).unwrap()),
            Err(e) => Err(handler_error_to_rpc(e)),
        }
    }

    async fn balance(&self, params: BalanceQuery) -> Result<Value, ErrorObjectOwned> {
        // Note: In a full implementation, we'd extract the auth token from headers
        // For now, skip auth check if no keystore exists (unauthenticated mode)
        if let Err(e) = check_auth(&self.state, "", TokenScope::Read) {
            return Err(auth_error_to_rpc(e));
        }

        match handlers::handle_balance(&self.state, params).await {
            Ok(result) => Ok(serde_json::to_value(result).unwrap()),
            Err(e) => Err(handler_error_to_rpc(e)),
        }
    }

    async fn transfer(&self, params: TransferRequest) -> Result<Value, ErrorObjectOwned> {
        if let Err(e) = check_auth(&self.state, "", TokenScope::Trade) {
            return Err(auth_error_to_rpc(e));
        }

        match handlers::handle_transfer(&self.state, params).await {
            Ok(result) => Ok(serde_json::to_value(result).unwrap()),
            Err(e) => Err(handler_error_to_rpc(e)),
        }
    }

    async fn skills(&self) -> Result<Value, ErrorObjectOwned> {
        if let Err(e) = check_auth(&self.state, "", TokenScope::Read) {
            return Err(auth_error_to_rpc(e));
        }

        match handlers::handle_skills(&self.state) {
            Ok(result) => Ok(serde_json::to_value(result).unwrap()),
            Err(e) => Err(handler_error_to_rpc(e)),
        }
    }

    async fn execute(&self, params: ExecuteRequest) -> Result<Value, ErrorObjectOwned> {
        if let Err(e) = check_auth(&self.state, "", TokenScope::Trade) {
            return Err(auth_error_to_rpc(e));
        }

        match handlers::handle_execute(&self.state, params).await {
            Ok(result) => Ok(serde_json::to_value(result).unwrap()),
            Err(e) => Err(handler_error_to_rpc(e)),
        }
    }

    async fn auth_grant(&self, params: AuthGrantRequest) -> Result<Value, ErrorObjectOwned> {
        // Verify password
        if let Err(e) = verify_admin_password(&self.state, &params.password) {
            return Err(auth_error_to_rpc(e));
        }

        // Parse scope
        let scope: TokenScope = params
            .scope
            .parse()
            .map_err(|e: AuthError| auth_error_to_rpc(e))?;

        // Calculate expiration
        let expires_hours = params
            .expires_hours
            .unwrap_or(self.state.auth_config.default_session_ttl_hours);
        let expires_in = Duration::from_secs(expires_hours * 3600);

        // Get current Unix UID
        #[cfg(unix)]
        let uid = unsafe { libc::getuid() };
        #[cfg(not(unix))]
        let uid = 0u32;

        // Grant the session
        let mut store = self.state.session_store.write().map_err(|_| {
            ErrorObjectOwned::owned(error_code::INTERNAL_ERROR, "lock error", None::<()>)
        })?;

        let token = store.grant(&params.agent_id, scope, expires_in, uid);
        let session = store.get(&params.agent_id).unwrap();

        let response = AuthGrantResponse {
            token,
            expires_at: session.expires_at.to_rfc3339(),
        };

        Ok(serde_json::to_value(response).unwrap())
    }

    async fn auth_list(&self, password: String) -> Result<Value, ErrorObjectOwned> {
        if let Err(e) = verify_admin_password(&self.state, &password) {
            return Err(auth_error_to_rpc(e));
        }

        let store = self.state.session_store.read().map_err(|_| {
            ErrorObjectOwned::owned(error_code::INTERNAL_ERROR, "lock error", None::<()>)
        })?;

        let sessions: Vec<_> = store
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

        Ok(serde_json::to_value(AuthListResponse { sessions }).unwrap())
    }

    async fn auth_revoke(
        &self,
        password: String,
        agent_id: String,
    ) -> Result<Value, ErrorObjectOwned> {
        if let Err(e) = verify_admin_password(&self.state, &password) {
            return Err(auth_error_to_rpc(e));
        }

        let mut store = self.state.session_store.write().map_err(|_| {
            ErrorObjectOwned::owned(error_code::INTERNAL_ERROR, "lock error", None::<()>)
        })?;

        let revoked = store.revoke(&agent_id);
        Ok(serde_json::to_value(AuthRevokeResponse { revoked }).unwrap())
    }

    async fn auth_revoke_all(&self, password: String) -> Result<Value, ErrorObjectOwned> {
        if let Err(e) = verify_admin_password(&self.state, &password) {
            return Err(auth_error_to_rpc(e));
        }

        let mut store = self.state.session_store.write().map_err(|_| {
            ErrorObjectOwned::owned(error_code::INTERNAL_ERROR, "lock error", None::<()>)
        })?;

        let count = store.revoke_all();
        Ok(serde_json::to_value(AuthRevokeAllResponse { count }).unwrap())
    }
}

/// RPC server using jsonrpsee.
pub struct RpcServer {
    config: ServerConfig,
    state: Arc<AppState>,
}

impl RpcServer {
    /// Create a new server with the given configuration and state.
    pub fn new(config: ServerConfig, state: Arc<AppState>) -> Self {
        Self { config, state }
    }

    /// Start the RPC server using the provided configuration.
    pub async fn start_with_config(
        config: &Config,
        signer: LocalSigner,
        addr: Option<SocketAddr>,
    ) -> Result<(), ServerError> {
        // Load policy
        let policy = PolicyEngine::from_file(&config.policy_path)?;

        // Create audit logger (ensure parent dir exists)
        if let Some(parent) = config.audit_log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let audit = AuditLogger::new(&config.audit_log_path)?;

        // Build EVM adapters for each configured chain
        let mut adapters = HashMap::new();
        for (chain_id, rpc_url) in &config.chain_rpc_urls {
            let adapter =
                EvmAdapter::new(rpc_url).map_err(|e| ServerError::EvmAdapter(e.to_string()))?;
            adapters.insert(*chain_id, adapter);
        }

        // Initialize session store
        let session_store = SessionStore::new();

        let skills_dir = std::env::var("CLAWLET_SKILLS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("skills"));

        let state = Arc::new(AppState {
            policy: Arc::new(policy),
            audit: Arc::new(Mutex::new(audit)),
            adapters: Arc::new(adapters),
            session_store: Arc::new(RwLock::new(session_store)),
            auth_config: config.auth.clone(),
            signer: Arc::new(signer),
            skills_dir,
            keystore_path: config.keystore_path.clone(),
        });

        let server_config = ServerConfig {
            addr: addr.unwrap_or_else(|| DEFAULT_ADDR.parse().unwrap()),
        };

        let server = RpcServer::new(server_config, state);
        server.run().await
    }

    /// Run the HTTP server.
    pub async fn run(&self) -> Result<(), ServerError> {
        let server = Server::builder()
            .build(self.config.addr)
            .await
            .map_err(|e| ServerError::Bind(e.to_string()))?;

        let rpc_impl = RpcServerImpl::new(Arc::clone(&self.state));
        let handle = server.start(rpc_impl.into_rpc());

        info!(addr = %self.config.addr, "HTTP JSON-RPC server listening");

        // Wait for server to finish (runs until stopped)
        handle.stopped().await;

        Ok(())
    }

    /// Get the server address.
    pub fn addr(&self) -> SocketAddr {
        self.config.addr
    }
}

// ---- Auth Helpers ----

/// Check authentication for token-based methods.
fn check_auth(state: &AppState, token: &str, required_scope: TokenScope) -> Result<(), AuthError> {
    // If no keystore exists, allow all requests (unauthenticated mode)
    if !state.keystore_path.exists() {
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

    // Try to unlock any keystore file
    let keystores =
        Keystore::list(&state.keystore_path).map_err(|_| AuthError::PasswordIncorrect)?;

    if keystores.is_empty() {
        return Err(AuthError::PasswordIncorrect);
    }

    let (_, keystore_path) = &keystores[0];
    match Keystore::unlock(keystore_path, password) {
        Ok(_) => {
            if let Ok(mut store) = state.session_store.write() {
                store.clear_failed_attempts("admin");
            }
            Ok(())
        }
        Err(_) => {
            if let Ok(mut store) = state.session_store.write() {
                store.record_failed_attempt("admin");
            }
            Err(AuthError::PasswordIncorrect)
        }
    }
}

/// Convert an auth error to a jsonrpsee error.
fn auth_error_to_rpc(err: AuthError) -> ErrorObjectOwned {
    match err {
        AuthError::InvalidToken | AuthError::TokenExpired => {
            ErrorObjectOwned::owned(error_code::UNAUTHORIZED, err.to_string(), None::<()>)
        }
        AuthError::InsufficientScope { .. } => {
            ErrorObjectOwned::owned(error_code::UNAUTHORIZED, err.to_string(), None::<()>)
        }
        AuthError::PasswordIncorrect => {
            ErrorObjectOwned::owned(error_code::UNAUTHORIZED, "incorrect password", None::<()>)
        }
        AuthError::TooManyAttempts => {
            ErrorObjectOwned::owned(error_code::UNAUTHORIZED, err.to_string(), None::<()>)
        }
        AuthError::InvalidScope(ref s) => ErrorObjectOwned::owned(
            error_code::INVALID_PARAMS,
            format!("invalid scope: {s}"),
            None::<()>,
        ),
        AuthError::SessionNotFound(ref s) => ErrorObjectOwned::owned(
            error_code::NOT_FOUND,
            format!("session not found: {s}"),
            None::<()>,
        ),
        AuthError::HashingError(ref s) => ErrorObjectOwned::owned(
            error_code::INTERNAL_ERROR,
            format!("hashing error: {s}"),
            None::<()>,
        ),
    }
}

/// Convert a handler error to a jsonrpsee error.
fn handler_error_to_rpc(err: HandlerError) -> ErrorObjectOwned {
    match err {
        HandlerError::BadRequest(msg) => {
            ErrorObjectOwned::owned(error_code::INVALID_PARAMS, msg, None::<()>)
        }
        HandlerError::NotFound(msg) => {
            ErrorObjectOwned::owned(error_code::NOT_FOUND, msg, None::<()>)
        }
        HandlerError::Internal(msg) => {
            ErrorObjectOwned::owned(error_code::INTERNAL_ERROR, msg, None::<()>)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_addr() {
        let config = ServerConfig::default();
        assert_eq!(config.addr.to_string(), DEFAULT_ADDR);
    }
}
