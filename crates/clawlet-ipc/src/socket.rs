//! Unix Domain Socket server for non-Rust clients (e.g., Node.js, Python).
//!
//! Exposes a JSON-RPC 2.0 interface over Unix stream sockets. Each connection
//! reads newline-delimited JSON requests and writes newline-delimited responses.
//!
//! # Protocol
//!
//! Request format:
//! ```json
//! {"jsonrpc":"2.0","method":"balance","params":{"address":"0x...","chain_id":8453},"id":1,"meta":{"authorization":"Bearer clwt_xxx"}}
//! ```
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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info, warn};

use clawlet_core::auth::{self, AuthError, TokenScope};

use crate::dispatch::{
    AuthGrantRequest, AuthGrantResponse, AuthListRequest, AuthListResponse, AuthRevokeAllRequest,
    AuthRevokeAllResponse, AuthRevokeRequest, AuthRevokeResponse,
};
use crate::handlers::{self, BalanceQuery, ExecuteRequest, HandlerError, TransferRequest};
use crate::server::AppState;

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
#[derive(Debug, Deserialize)]
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
    /// Metadata including authorization (non-standard extension).
    #[serde(default)]
    pub meta: RequestMeta,
}

/// Metadata attached to requests (non-standard JSON-RPC extension).
#[derive(Debug, Default, Deserialize)]
pub struct RequestMeta {
    /// Authorization header value (e.g., "Bearer clwt_xxx").
    #[serde(default)]
    pub authorization: Option<String>,
}

/// JSON-RPC 2.0 success response.
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    /// Protocol version.
    pub jsonrpc: &'static str,
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
            jsonrpc: "2.0",
            result: Some(serde_json::to_value(result).unwrap_or(Value::Null)),
            error: None,
            id,
        }
    }

    /// Create an error response.
    pub fn error(id: Value, code: JsonRpcErrorCode, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
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
    pub fn error_with_data(
        id: Value,
        code: JsonRpcErrorCode,
        message: impl Into<String>,
        data: Value,
    ) -> Self {
        Self {
            jsonrpc: "2.0",
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
#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    /// Error code.
    pub code: i32,
    /// Error message.
    pub message: String,
    /// Additional error data (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// ---- Socket Server ----

/// Default socket path.
pub const DEFAULT_SOCKET_PATH: &str = "/run/clawlet/clawlet.sock";

/// Unix socket server configuration.
pub struct SocketServerConfig {
    /// Path to the Unix socket file.
    pub socket_path: PathBuf,
    /// Socket file permissions (Unix mode).
    pub permissions: u32,
}

impl Default for SocketServerConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from(DEFAULT_SOCKET_PATH),
            permissions: 0o660,
        }
    }
}

/// Unix Domain Socket server for JSON-RPC requests.
pub struct SocketServer {
    config: SocketServerConfig,
    state: Arc<AppState>,
}

impl SocketServer {
    /// Create a new socket server with the given configuration and state.
    pub fn new(config: SocketServerConfig, state: Arc<AppState>) -> Self {
        Self { config, state }
    }

    /// Start the socket server.
    ///
    /// This will:
    /// 1. Remove any existing socket file
    /// 2. Create the socket directory if needed
    /// 3. Bind the Unix listener
    /// 4. Set socket permissions
    /// 5. Accept connections in a loop
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let socket_path = &self.config.socket_path;

        // Ensure parent directory exists
        if let Some(parent) = socket_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Remove existing socket file if present
        if socket_path.exists() {
            tokio::fs::remove_file(socket_path).await?;
        }

        // Bind the listener
        let listener = UnixListener::bind(socket_path)?;

        // Set socket permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(self.config.permissions);
            std::fs::set_permissions(socket_path, perms)?;
        }

        info!(
            path = %socket_path.display(),
            permissions = format!("{:o}", self.config.permissions),
            "Unix socket server listening"
        );

        // Accept connections
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let state = Arc::clone(&self.state);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(state, stream).await {
                            warn!("connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("accept error: {}", e);
                    // Brief pause before retrying
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Get the socket path.
    pub fn socket_path(&self) -> &Path {
        &self.config.socket_path
    }
}

/// Handle a single client connection.
///
/// Reads newline-delimited JSON-RPC requests and writes responses.
async fn handle_connection(
    state: Arc<AppState>,
    stream: UnixStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    debug!("new socket connection");

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;

        if bytes_read == 0 {
            // EOF - client disconnected
            debug!("client disconnected");
            break;
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Parse the request
        let response = match serde_json::from_str::<JsonRpcRequest>(line) {
            Ok(request) => handle_request(&state, request).await,
            Err(e) => JsonRpcResponse::error(
                Value::Null,
                JsonRpcErrorCode::ParseError,
                format!("parse error: {}", e),
            ),
        };

        // Write response as newline-delimited JSON
        let response_json = serde_json::to_string(&response)?;
        writer.write_all(response_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}

/// Handle a single JSON-RPC request.
async fn handle_request(state: &AppState, request: JsonRpcRequest) -> JsonRpcResponse {
    // Validate JSON-RPC version
    if request.jsonrpc != "2.0" {
        return JsonRpcResponse::error(
            request.id,
            JsonRpcErrorCode::InvalidRequest,
            "invalid JSON-RPC version",
        );
    }

    let id = request.id.clone();

    // Extract auth token from meta
    let token = request
        .meta
        .authorization
        .as_deref()
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .unwrap_or("");

    // Route to appropriate handler
    match request.method.as_str() {
        "health" => handle_health(id),
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
    // If no auth is configured, allow all requests
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
    fn test_parse_json_rpc_request_with_meta() {
        let json = r#"{"jsonrpc":"2.0","method":"balance","params":{"address":"0x123","chain_id":8453},"id":"abc","meta":{"authorization":"Bearer clwt_xxx"}}"#;
        let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.method, "balance");
        assert_eq!(
            request.meta.authorization,
            Some("Bearer clwt_xxx".to_string())
        );
    }

    #[test]
    fn test_parse_json_rpc_request_no_meta() {
        let json = r#"{"jsonrpc":"2.0","method":"health","id":1}"#;
        let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert!(request.meta.authorization.is_none());
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
    fn test_method_routing_health() {
        // Health method should not require auth
        let json = r#"{"jsonrpc":"2.0","method":"health","id":1}"#;
        let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.method, "health");
    }

    #[test]
    fn test_method_routing_balance() {
        let json = r#"{"jsonrpc":"2.0","method":"balance","params":{"address":"0x742d35Cc6634C0532925a3b844Bc9e7595f2Bd77","chain_id":8453},"id":1,"meta":{"authorization":"Bearer clwt_test"}}"#;
        let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.method, "balance");

        let params: BalanceQuery = serde_json::from_value(request.params).unwrap();
        assert_eq!(params.chain_id, 8453);
        assert!(params.address.starts_with("0x"));
    }

    #[test]
    fn test_method_routing_transfer() {
        let json = r#"{"jsonrpc":"2.0","method":"transfer","params":{"to":"0x742d35Cc6634C0532925a3b844Bc9e7595f2Bd77","amount":"1.0","token":"ETH","chain_id":8453},"id":1}"#;
        let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.method, "transfer");

        let params: TransferRequest = serde_json::from_value(request.params).unwrap();
        assert_eq!(params.amount, "1.0");
        assert_eq!(params.token, "ETH");
    }

    #[test]
    fn test_method_routing_auth_grant() {
        let json = r#"{"jsonrpc":"2.0","method":"auth.grant","params":{"password":"secret","agent_id":"owlia","scope":"trade"},"id":1}"#;
        let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.method, "auth.grant");

        let params: AuthGrantRequest = serde_json::from_value(request.params).unwrap();
        assert_eq!(params.agent_id, "owlia");
        assert_eq!(params.scope, "trade");
    }

    #[test]
    fn test_extract_bearer_token() {
        let auth = Some("Bearer clwt_abcd1234".to_string());
        let token = auth
            .as_deref()
            .and_then(|a| a.strip_prefix("Bearer "))
            .unwrap_or("");
        assert_eq!(token, "clwt_abcd1234");
    }

    #[test]
    fn test_extract_bearer_token_missing() {
        let auth: Option<String> = None;
        let token = auth
            .as_deref()
            .and_then(|a| a.strip_prefix("Bearer "))
            .unwrap_or("");
        assert_eq!(token, "");
    }

    #[test]
    fn test_extract_bearer_token_wrong_format() {
        let auth = Some("Basic xyz".to_string());
        let token = auth
            .as_deref()
            .and_then(|a| a.strip_prefix("Bearer "))
            .unwrap_or("");
        assert_eq!(token, "");
    }
}
