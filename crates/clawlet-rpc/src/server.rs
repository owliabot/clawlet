//! HTTP JSON-RPC server using axum.
//!
//! Exposes a JSON-RPC 2.0 interface over HTTP at `127.0.0.1:9100` (configurable).
//!
//! # Protocol
//!
//! `POST /rpc` with `Content-Type: application/json`
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

use axum::{
    extract::State,
    http::header,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

use clawlet_core::audit::AuditLogger;
use clawlet_core::auth::{AuthError, SessionStore, TokenScope};
use clawlet_core::config::{AuthConfig, Config};
use clawlet_core::policy::PolicyEngine;
use clawlet_evm::EvmAdapter;
use clawlet_signer::keystore::Keystore;
use clawlet_signer::signer::LocalSigner;

use crate::dispatch::{
    AuthGrantRequest, AuthGrantResponse, AuthListRequest, AuthListResponse, AuthRevokeAllRequest,
    AuthRevokeAllResponse, AuthRevokeRequest, AuthRevokeResponse,
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

// ---- JSON-RPC 2.0 Types ----

/// Standard JSON-RPC 2.0 error codes.
#[derive(Debug, Clone, Copy)]
#[repr(i32)]
pub enum JsonRpcErrorCode {
    /// Invalid JSON was received.
    ParseError = -32700,
    /// The JSON sent is not a valid Request object.
    InvalidRequest = -32600,
    /// The method does not exist / is not available.
    MethodNotFound = -32601,
    /// Invalid method parameter(s).
    InvalidParams = -32602,
    /// Internal JSON-RPC error.
    InternalError = -32603,
    // Server-defined errors (-32000 to -32099)
    /// Authentication required or failed.
    Unauthorized = -32001,
    /// Resource not found.
    NotFound = -32002,
}

/// JSON-RPC 2.0 request object.
#[derive(Debug, Deserialize, Serialize)]
pub struct JsonRpcRequest {
    /// Protocol version (should be "2.0").
    pub jsonrpc: String,
    /// Method name to invoke.
    pub method: String,
    /// Method parameters (optional).
    #[serde(default)]
    pub params: Value,
    /// Request ID (can be string, number, or null).
    pub id: Value,
}

/// JSON-RPC 2.0 success response.
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Protocol version.
    pub jsonrpc: String,
    /// Result on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    /// Request ID (echoed from request).
    pub id: Value,
}

impl JsonRpcResponse {
    /// Create a success response.
    pub fn success(id: Value, result: impl Serialize) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(serde_json::to_value(result).unwrap_or(Value::Null)),
            error: None,
            id,
        }
    }

    /// Create an error response.
    pub fn error(id: Value, code: JsonRpcErrorCode, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code: code as i32,
                message: message.into(),
                data: None,
            }),
            id,
        }
    }

    /// Create an error response with additional data.
    #[allow(dead_code)]
    pub fn error_with_data(
        id: Value,
        code: JsonRpcErrorCode,
        message: impl Into<String>,
        data: Value,
    ) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code: code as i32,
                message: message.into(),
                data: Some(data),
            }),
            id,
        }
    }
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code.
    pub code: i32,
    /// Error message.
    pub message: String,
    /// Additional error data (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
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

/// RPC server using HTTP with axum.
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
    ///
    /// This will:
    /// 1. Load the policy engine from the configured policy file
    /// 2. Create an audit logger at the configured path
    /// 3. Build EVM adapters for each configured chain
    /// 4. Start the HTTP server and process requests
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
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        let app = Router::new()
            .route("/", get(health_handler))
            .route("/health", get(health_handler))
            .route("/rpc", post(rpc_handler))
            .layer(cors)
            .layer(TraceLayer::new_for_http())
            .with_state(Arc::clone(&self.state));

        let listener = tokio::net::TcpListener::bind(self.config.addr)
            .await
            .map_err(|e| ServerError::Bind(e.to_string()))?;

        info!(addr = %self.config.addr, "HTTP JSON-RPC server listening");

        axum::serve(listener, app)
            .await
            .map_err(|e| ServerError::Io(std::io::Error::other(e)))
    }

    /// Get the server address.
    pub fn addr(&self) -> SocketAddr {
        self.config.addr
    }
}

// ---- HTTP Handlers ----

/// Health check endpoint.
async fn health_handler() -> Json<Value> {
    Json(serde_json::json!({"status": "ok"}))
}

/// JSON-RPC endpoint handler.
async fn rpc_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(request): Json<JsonRpcRequest>,
) -> Json<JsonRpcResponse> {
    // Extract auth token from Authorization header
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .unwrap_or("");

    let response = handle_request(&state, request, token).await;
    Json(response)
}

/// Handle a single JSON-RPC request.
async fn handle_request(state: &AppState, request: JsonRpcRequest, token: &str) -> JsonRpcResponse {
    // Validate JSON-RPC version
    if request.jsonrpc != "2.0" {
        return JsonRpcResponse::error(
            request.id,
            JsonRpcErrorCode::InvalidRequest,
            "invalid JSON-RPC version",
        );
    }

    let id = request.id.clone();

    // Route to appropriate handler
    match request.method.as_str() {
        "health" => handle_health(id),
        "address" => handle_address(state, id),
        "balance" => handle_balance(state, id, request.params, token).await,
        "transfer" => handle_transfer(state, id, request.params, token).await,
        "skills" => handle_skills(state, id, token),
        "execute" => handle_execute(state, id, request.params, token).await,
        "auth.grant" => handle_auth_grant(state, id, request.params).await,
        "auth.list" => handle_auth_list(state, id, request.params).await,
        "auth.revoke" => handle_auth_revoke(state, id, request.params).await,
        "auth.revoke_all" => handle_auth_revoke_all(state, id, request.params).await,
        _ => JsonRpcResponse::error(
            id,
            JsonRpcErrorCode::MethodNotFound,
            format!("method not found: {}", request.method),
        ),
    }
}

// ---- Method Handlers ----

fn handle_health(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::success(id, serde_json::json!({"status": "ok"}))
}

fn handle_address(state: &AppState, id: Value) -> JsonRpcResponse {
    // No auth required — address query is public information
    match handlers::handle_address(state) {
        Ok(result) => JsonRpcResponse::success(id, result),
        Err(e) => handler_error_response(id, e),
    }
}

async fn handle_balance(
    state: &AppState,
    id: Value,
    params: Value,
    token: &str,
) -> JsonRpcResponse {
    // Check auth (Read scope required)
    if let Err(e) = check_auth(state, token, TokenScope::Read) {
        return auth_error_response(id, e);
    }

    // Parse params
    let query: BalanceQuery = match serde_json::from_value(params) {
        Ok(q) => q,
        Err(e) => {
            return JsonRpcResponse::error(
                id,
                JsonRpcErrorCode::InvalidParams,
                format!("invalid params: {}", e),
            )
        }
    };

    // Call handler
    match handlers::handle_balance(state, query).await {
        Ok(result) => JsonRpcResponse::success(id, result),
        Err(e) => handler_error_response(id, e),
    }
}

async fn handle_transfer(
    state: &AppState,
    id: Value,
    params: Value,
    token: &str,
) -> JsonRpcResponse {
    // Check auth (Trade scope required)
    if let Err(e) = check_auth(state, token, TokenScope::Trade) {
        return auth_error_response(id, e);
    }

    // Parse params
    let req: TransferRequest = match serde_json::from_value(params) {
        Ok(r) => r,
        Err(e) => {
            return JsonRpcResponse::error(
                id,
                JsonRpcErrorCode::InvalidParams,
                format!("invalid params: {}", e),
            )
        }
    };

    // Call handler
    match handlers::handle_transfer(state, req).await {
        Ok(result) => JsonRpcResponse::success(id, result),
        Err(e) => handler_error_response(id, e),
    }
}

fn handle_skills(state: &AppState, id: Value, token: &str) -> JsonRpcResponse {
    // Check auth (Read scope required)
    if let Err(e) = check_auth(state, token, TokenScope::Read) {
        return auth_error_response(id, e);
    }

    // Call handler
    match handlers::handle_skills(state) {
        Ok(result) => JsonRpcResponse::success(id, result),
        Err(e) => handler_error_response(id, e),
    }
}

async fn handle_execute(
    state: &AppState,
    id: Value,
    params: Value,
    token: &str,
) -> JsonRpcResponse {
    // Check auth (Trade scope required)
    if let Err(e) = check_auth(state, token, TokenScope::Trade) {
        return auth_error_response(id, e);
    }

    // Parse params
    let req: ExecuteRequest = match serde_json::from_value(params) {
        Ok(r) => r,
        Err(e) => {
            return JsonRpcResponse::error(
                id,
                JsonRpcErrorCode::InvalidParams,
                format!("invalid params: {}", e),
            )
        }
    };

    // Call handler
    match handlers::handle_execute(state, req).await {
        Ok(result) => JsonRpcResponse::success(id, result),
        Err(e) => handler_error_response(id, e),
    }
}

async fn handle_auth_grant(state: &AppState, id: Value, params: Value) -> JsonRpcResponse {
    // Parse params
    let req: AuthGrantRequest = match serde_json::from_value(params) {
        Ok(r) => r,
        Err(e) => {
            return JsonRpcResponse::error(
                id,
                JsonRpcErrorCode::InvalidParams,
                format!("invalid params: {}", e),
            )
        }
    };

    // Verify password
    if let Err(e) = verify_admin_password(state, &req.password) {
        return auth_error_response(id, e);
    }

    // Parse scope
    let scope: TokenScope = match req.scope.parse() {
        Ok(s) => s,
        Err(e) => return auth_error_response(id, e),
    };

    // Calculate expiration
    let expires_hours = req
        .expires_hours
        .unwrap_or(state.auth_config.default_session_ttl_hours);
    let expires_in = Duration::from_secs(expires_hours * 3600);

    // Get current Unix UID
    #[cfg(unix)]
    let uid = unsafe { libc::getuid() };
    #[cfg(not(unix))]
    let uid = 0u32;

    // Grant the session
    let mut store = match state.session_store.write() {
        Ok(s) => s,
        Err(_) => {
            return JsonRpcResponse::error(
                id,
                JsonRpcErrorCode::InternalError,
                "failed to lock store",
            )
        }
    };

    let token = store.grant(&req.agent_id, scope, expires_in, uid);
    let session = store.get(&req.agent_id).unwrap();

    let response = AuthGrantResponse {
        token,
        expires_at: session.expires_at.to_rfc3339(),
    };

    JsonRpcResponse::success(id, response)
}

async fn handle_auth_list(state: &AppState, id: Value, params: Value) -> JsonRpcResponse {
    // Parse params
    let req: AuthListRequest = match serde_json::from_value(params) {
        Ok(r) => r,
        Err(e) => {
            return JsonRpcResponse::error(
                id,
                JsonRpcErrorCode::InvalidParams,
                format!("invalid params: {}", e),
            )
        }
    };

    // Verify password
    if let Err(e) = verify_admin_password(state, &req.password) {
        return auth_error_response(id, e);
    }

    let store = match state.session_store.read() {
        Ok(s) => s,
        Err(_) => {
            return JsonRpcResponse::error(
                id,
                JsonRpcErrorCode::InternalError,
                "failed to lock store",
            )
        }
    };

    let sessions: Vec<_> = store
        .list()
        .into_iter()
        .map(|s| crate::dispatch::SessionSummary {
            id: s.id.clone(),
            scope: s.scope.to_string(),
            created_at: s.created_at.to_rfc3339(),
            expires_at: s.expires_at.to_rfc3339(),
            last_used_at: s.last_used_at.to_rfc3339(),
            request_count: s.request_count,
        })
        .collect();

    JsonRpcResponse::success(id, AuthListResponse { sessions })
}

async fn handle_auth_revoke(state: &AppState, id: Value, params: Value) -> JsonRpcResponse {
    // Parse params
    let req: AuthRevokeRequest = match serde_json::from_value(params) {
        Ok(r) => r,
        Err(e) => {
            return JsonRpcResponse::error(
                id,
                JsonRpcErrorCode::InvalidParams,
                format!("invalid params: {}", e),
            )
        }
    };

    // Verify password
    if let Err(e) = verify_admin_password(state, &req.password) {
        return auth_error_response(id, e);
    }

    let mut store = match state.session_store.write() {
        Ok(s) => s,
        Err(_) => {
            return JsonRpcResponse::error(
                id,
                JsonRpcErrorCode::InternalError,
                "failed to lock store",
            )
        }
    };

    let revoked = store.revoke(&req.agent_id);
    JsonRpcResponse::success(id, AuthRevokeResponse { revoked })
}

async fn handle_auth_revoke_all(state: &AppState, id: Value, params: Value) -> JsonRpcResponse {
    // Parse params
    let req: AuthRevokeAllRequest = match serde_json::from_value(params) {
        Ok(r) => r,
        Err(e) => {
            return JsonRpcResponse::error(
                id,
                JsonRpcErrorCode::InvalidParams,
                format!("invalid params: {}", e),
            )
        }
    };

    // Verify password
    if let Err(e) = verify_admin_password(state, &req.password) {
        return auth_error_response(id, e);
    }

    let mut store = match state.session_store.write() {
        Ok(s) => s,
        Err(_) => {
            return JsonRpcResponse::error(
                id,
                JsonRpcErrorCode::InternalError,
                "failed to lock store",
            )
        }
    };

    let count = store.revoke_all();
    JsonRpcResponse::success(id, AuthRevokeAllResponse { count })
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

/// Verify password for admin operations by attempting to unlock the keystore.
///
/// Instead of storing a separate password hash, we verify the password by
/// attempting to unlock the keystore. If the keystore unlocks successfully,
/// the password is valid.
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

    // Try to unlock any keystore file - if successful, password is valid
    let keystores =
        Keystore::list(&state.keystore_path).map_err(|_| AuthError::PasswordIncorrect)?;

    if keystores.is_empty() {
        return Err(AuthError::PasswordIncorrect);
    }

    let (_, keystore_path) = &keystores[0];
    match Keystore::unlock(keystore_path, password) {
        Ok(_) => {
            // Clear failed attempts on success
            if let Ok(mut store) = state.session_store.write() {
                store.clear_failed_attempts("admin");
            }
            Ok(())
        }
        Err(_) => {
            // Record failed attempt
            if let Ok(mut store) = state.session_store.write() {
                store.record_failed_attempt("admin");
            }
            Err(AuthError::PasswordIncorrect)
        }
    }
}

/// Convert an auth error to a JSON-RPC response.
fn auth_error_response(id: Value, err: AuthError) -> JsonRpcResponse {
    match err {
        AuthError::InvalidToken | AuthError::TokenExpired => {
            JsonRpcResponse::error(id, JsonRpcErrorCode::Unauthorized, err.to_string())
        }
        AuthError::InsufficientScope { .. } => {
            JsonRpcResponse::error(id, JsonRpcErrorCode::Unauthorized, err.to_string())
        }
        AuthError::PasswordIncorrect => {
            JsonRpcResponse::error(id, JsonRpcErrorCode::Unauthorized, "incorrect password")
        }
        AuthError::TooManyAttempts => {
            JsonRpcResponse::error(id, JsonRpcErrorCode::Unauthorized, err.to_string())
        }
        AuthError::InvalidScope(ref s) => JsonRpcResponse::error(
            id,
            JsonRpcErrorCode::InvalidParams,
            format!("invalid scope: {s}"),
        ),
        AuthError::SessionNotFound(ref s) => JsonRpcResponse::error(
            id,
            JsonRpcErrorCode::NotFound,
            format!("session not found: {s}"),
        ),
        AuthError::HashingError(ref s) => JsonRpcResponse::error(
            id,
            JsonRpcErrorCode::InternalError,
            format!("hashing error: {s}"),
        ),
    }
}

/// Convert a handler error to a JSON-RPC response.
fn handler_error_response(id: Value, err: HandlerError) -> JsonRpcResponse {
    match err {
        HandlerError::BadRequest(msg) => {
            JsonRpcResponse::error(id, JsonRpcErrorCode::InvalidParams, msg)
        }
        HandlerError::NotFound(msg) => JsonRpcResponse::error(id, JsonRpcErrorCode::NotFound, msg),
        HandlerError::Internal(msg) => {
            JsonRpcResponse::error(id, JsonRpcErrorCode::InternalError, msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json_rpc_request() {
        let json = r#"{"jsonrpc":"2.0","method":"health","params":{},"id":1}"#;
        let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.jsonrpc, "2.0");
        assert_eq!(request.method, "health");
        assert_eq!(request.id, serde_json::json!(1));
    }

    #[test]
    fn test_json_rpc_success_response() {
        let response =
            JsonRpcResponse::success(serde_json::json!(1), serde_json::json!({"status": "ok"}));
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"result\":"));
        assert!(!json.contains("\"error\":"));
    }

    #[test]
    fn test_json_rpc_error_response() {
        let response = JsonRpcResponse::error(
            serde_json::json!(1),
            JsonRpcErrorCode::Unauthorized,
            "invalid token",
        );
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"error\":"));
        assert!(json.contains("\"code\":-32001"));
        assert!(json.contains("\"message\":\"invalid token\""));
        assert!(!json.contains("\"result\":"));
    }

    #[test]
    fn test_json_rpc_null_id() {
        let json = r#"{"jsonrpc":"2.0","method":"health","id":null}"#;
        let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert!(request.id.is_null());
    }

    #[test]
    fn test_json_rpc_string_id() {
        let json = r#"{"jsonrpc":"2.0","method":"health","id":"request-123"}"#;
        let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.id, serde_json::json!("request-123"));
    }

    #[test]
    fn test_default_addr() {
        let config = ServerConfig::default();
        assert_eq!(config.addr.to_string(), DEFAULT_ADDR);
    }
}
