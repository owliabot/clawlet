//! HTTP JSON-RPC server using jsonrpsee.
//!
//! Exposes a JSON-RPC 2.0 interface over HTTP at `127.0.0.1:9100` (configurable).
//!
//! # Protocol
//!
//! `POST /` with `Content-Type: application/json` and `Authorization: Bearer <token>` header.
//!
//! Request format:
//! ```json
//! {"jsonrpc":"2.0","method":"balance","params":{"address":"0x...","chain_id":8453},"id":1}
//! ```
//!
//! Success response:
//! ```json
//! {"jsonrpc":"2.0","result":{"eth":"1.5","tokens":[]},"id":1}
//! ```
//!
//! Error response:
//! ```json
//! {"jsonrpsee":"2.0","error":{"code":-32600,"message":"Unauthorized"},"id":1}
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::middleware::rpc::{RpcServiceBuilder, RpcServiceT};
use jsonrpsee::server::{MethodResponse, Server};
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
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
    AuthGrantRequest, AuthGrantResponse, AuthListRequest, AuthListResponse, AuthRevokeAllRequest,
    AuthRevokeAllResponse, AuthRevokeRequest, AuthRevokeResponse, AuthRevokeSessionRequest,
    AuthRevokeSessionResponse, SessionSummary,
};
use crate::handlers;
use crate::types::{
    BalanceQuery, ExecuteRequest, HandlerError, SendRawRequest, SignMessageRequest, TokenSpec,
    TransferRequest,
};

// ---- Daemon Readiness Signal ----

/// Signal daemon readiness by writing "ok\n" to the pipe fd and closing it.
///
/// This unblocks the parent process, which then exits successfully.
#[cfg(unix)]
fn signal_daemon_ready(fd: i32) {
    let msg = b"ok\n";
    let mut off = 0usize;
    while off < msg.len() {
        let n = unsafe {
            libc::write(
                fd,
                msg[off..].as_ptr().cast(),
                (msg.len() - off) as libc::size_t,
            )
        };
        if n > 0 {
            off += n as usize;
            continue;
        }
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        break;
    }
    unsafe { libc::close(fd) };
}

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

// ---- Auth Token Extension ----

/// Token extracted from Authorization header, stored in request extensions.
#[derive(Clone, Debug, Default)]
pub struct AuthToken(pub Option<String>);

// Task-local storage for per-request auth token (avoids race conditions)
tokio::task_local! {
    static REQUEST_AUTH_TOKEN: AuthToken;
}

/// RPC middleware that extracts auth token from HTTP extensions and sets task-local storage.
/// This ensures each RPC method call has access to its own request's token.
#[derive(Clone)]
struct AuthTokenMiddleware<S> {
    inner: S,
}

impl<'a, S> RpcServiceT<'a> for AuthTokenMiddleware<S>
where
    S: RpcServiceT<'a> + Send + Sync + Clone + 'a,
{
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = MethodResponse> + Send + 'a>>;

    fn call(&self, request: jsonrpsee::types::Request<'a>) -> Self::Future {
        // Extract auth token from HTTP request extensions (set by HTTP middleware)
        let token = request
            .extensions()
            .get::<AuthToken>()
            .cloned()
            .unwrap_or_default();

        let inner = self.inner.clone();
        Box::pin(async move {
            // Wrap the inner service call in a task-local scope with the per-request token
            REQUEST_AUTH_TOKEN.scope(token, inner.call(request)).await
        })
    }
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

// ---- Request types (auth token removed - now from header) ----

/// Balance query parameters.
#[derive(Debug, Deserialize, Serialize)]
pub struct BalanceRequest {
    /// The EVM address to query.
    pub address: alloy::primitives::Address,
    /// The chain ID to query against.
    pub chain_id: u64,
}

/// Transfer request parameters.
#[derive(Debug, Deserialize, Serialize)]
pub struct TransferRequestWithAuth {
    /// Recipient address.
    pub to: alloy::primitives::Address,
    /// Amount as a non-negative decimal string.
    pub amount: crate::types::Amount,
    /// Token to transfer.
    pub token_type: TokenSpec,
    /// Chain ID.
    pub chain_id: u64,
}

/// Skills request parameters (empty - auth from header).
#[derive(Debug, Deserialize, Serialize, Default)]
pub struct SkillsRequest {}

/// Execute request parameters.
#[derive(Debug, Deserialize, Serialize)]
pub struct ExecuteRequestWithAuth {
    /// Skill name.
    pub skill: String,
    /// Parameter values.
    #[serde(default)]
    pub params: HashMap<String, String>,
}

// ---- JSON-RPC API Definition ----

/// JSON-RPC API trait using jsonrpsee macros.
#[rpc(server)]
pub trait ClawletApi {
    /// Health check.
    #[method(name = "health")]
    async fn health(&self) -> Result<Value, ErrorObjectOwned>;

    /// List supported chains.
    #[method(name = "chains")]
    async fn chains(&self) -> Result<Value, ErrorObjectOwned>;

    /// Get wallet address.
    #[method(name = "address")]
    async fn address(&self) -> Result<Value, ErrorObjectOwned>;

    /// Query balance.
    #[method(name = "balance")]
    async fn balance(&self, params: BalanceRequest) -> Result<Value, ErrorObjectOwned>;

    /// Execute transfer.
    #[method(name = "transfer")]
    async fn transfer(&self, params: TransferRequestWithAuth) -> Result<Value, ErrorObjectOwned>;

    /// List available skills.
    #[method(name = "skills")]
    async fn skills(&self, params: SkillsRequest) -> Result<Value, ErrorObjectOwned>;

    /// Execute a skill.
    #[method(name = "execute")]
    async fn execute(&self, params: ExecuteRequestWithAuth) -> Result<Value, ErrorObjectOwned>;

    /// Send a raw transaction (bypasses policy engine).
    #[method(name = "send_raw")]
    async fn send_raw(&self, params: SendRawRequest) -> Result<Value, ErrorObjectOwned>;

    /// Sign a message using EIP-191 personal sign.
    #[method(name = "sign_message")]
    async fn sign_message(&self, params: SignMessageRequest) -> Result<Value, ErrorObjectOwned>;

    /// Grant a new session token.
    #[method(name = "auth.grant")]
    async fn auth_grant(&self, params: AuthGrantRequest) -> Result<Value, ErrorObjectOwned>;

    /// List all sessions (including expired ones still within the grace period).
    #[method(name = "auth.list")]
    async fn auth_list(&self, params: AuthListRequest) -> Result<Value, ErrorObjectOwned>;

    /// Revoke all sessions for an agent.
    #[method(name = "auth.revoke")]
    async fn auth_revoke(&self, params: AuthRevokeRequest) -> Result<Value, ErrorObjectOwned>;

    /// Revoke a single session by its session key.
    #[method(name = "auth.revoke_session")]
    async fn auth_revoke_session(
        &self,
        params: AuthRevokeSessionRequest,
    ) -> Result<Value, ErrorObjectOwned>;

    /// Revoke all sessions.
    #[method(name = "auth.revoke_all")]
    async fn auth_revoke_all(
        &self,
        params: AuthRevokeAllRequest,
    ) -> Result<Value, ErrorObjectOwned>;
}

/// RPC server implementation with per-request auth token via task-local storage.
pub struct RpcServerImpl {
    state: Arc<AppState>,
}

impl RpcServerImpl {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Get the auth token from task-local storage (set per-request by middleware).
    fn get_token() -> String {
        REQUEST_AUTH_TOKEN
            .try_with(|t| t.0.clone())
            .ok()
            .flatten()
            .unwrap_or_default()
    }
}

#[async_trait]
impl ClawletApiServer for RpcServerImpl {
    async fn health(&self) -> Result<Value, ErrorObjectOwned> {
        Ok(serde_json::json!({"status": "ok"}))
    }

    async fn chains(&self) -> Result<Value, ErrorObjectOwned> {
        match handlers::handle_chains(&self.state) {
            Ok(result) => serde_json::to_value(result).map_err(|e| {
                ErrorObjectOwned::owned(
                    error_code::INTERNAL_ERROR,
                    format!("serialization error: {e}"),
                    None::<()>,
                )
            }),
            Err(e) => Err(handler_error_to_rpc(e)),
        }
    }

    async fn address(&self) -> Result<Value, ErrorObjectOwned> {
        match handlers::handle_address(&self.state) {
            Ok(result) => serde_json::to_value(result).map_err(|e| {
                ErrorObjectOwned::owned(
                    error_code::INTERNAL_ERROR,
                    format!("serialization error: {e}"),
                    None::<()>,
                )
            }),
            Err(e) => Err(handler_error_to_rpc(e)),
        }
    }

    async fn balance(&self, params: BalanceRequest) -> Result<Value, ErrorObjectOwned> {
        // Check auth with token from task-local storage (set per-request by middleware)
        let token = Self::get_token();
        if let Err(e) = check_auth(&self.state, &token, TokenScope::Read) {
            return Err(auth_error_to_rpc(e));
        }

        let query = BalanceQuery {
            address: params.address,
            chain_id: params.chain_id,
        };

        match handlers::handle_balance(&self.state, query).await {
            Ok(result) => serde_json::to_value(result).map_err(|e| {
                ErrorObjectOwned::owned(
                    error_code::INTERNAL_ERROR,
                    format!("serialization error: {e}"),
                    None::<()>,
                )
            }),
            Err(e) => Err(handler_error_to_rpc(e)),
        }
    }

    async fn transfer(&self, params: TransferRequestWithAuth) -> Result<Value, ErrorObjectOwned> {
        let token = Self::get_token();
        if let Err(e) = check_auth(&self.state, &token, TokenScope::Trade) {
            return Err(auth_error_to_rpc(e));
        }

        let req = TransferRequest {
            to: params.to,
            amount: params.amount,
            token: params.token_type,
            chain_id: params.chain_id,
        };

        match handlers::handle_transfer(&self.state, req).await {
            Ok(result) => serde_json::to_value(result).map_err(|e| {
                ErrorObjectOwned::owned(
                    error_code::INTERNAL_ERROR,
                    format!("serialization error: {e}"),
                    None::<()>,
                )
            }),
            Err(e) => Err(handler_error_to_rpc(e)),
        }
    }

    async fn skills(&self, _params: SkillsRequest) -> Result<Value, ErrorObjectOwned> {
        let token = Self::get_token();
        if let Err(e) = check_auth(&self.state, &token, TokenScope::Read) {
            return Err(auth_error_to_rpc(e));
        }

        match handlers::handle_skills(&self.state) {
            Ok(result) => serde_json::to_value(result).map_err(|e| {
                ErrorObjectOwned::owned(
                    error_code::INTERNAL_ERROR,
                    format!("serialization error: {e}"),
                    None::<()>,
                )
            }),
            Err(e) => Err(handler_error_to_rpc(e)),
        }
    }

    async fn execute(&self, params: ExecuteRequestWithAuth) -> Result<Value, ErrorObjectOwned> {
        let token = Self::get_token();
        if let Err(e) = check_auth(&self.state, &token, TokenScope::Trade) {
            return Err(auth_error_to_rpc(e));
        }

        let req = ExecuteRequest {
            skill: params.skill,
            params: params.params,
        };

        match handlers::handle_execute(&self.state, req).await {
            Ok(result) => serde_json::to_value(result).map_err(|e| {
                ErrorObjectOwned::owned(
                    error_code::INTERNAL_ERROR,
                    format!("serialization error: {e}"),
                    None::<()>,
                )
            }),
            Err(e) => Err(handler_error_to_rpc(e)),
        }
    }

    async fn send_raw(&self, params: SendRawRequest) -> Result<Value, ErrorObjectOwned> {
        let token = Self::get_token();
        if let Err(e) = check_auth(&self.state, &token, TokenScope::Trade) {
            return Err(auth_error_to_rpc(e));
        }

        match handlers::handle_send_raw(&self.state, params).await {
            Ok(result) => serde_json::to_value(result).map_err(|e| {
                ErrorObjectOwned::owned(
                    error_code::INTERNAL_ERROR,
                    format!("serialization error: {e}"),
                    None::<()>,
                )
            }),
            Err(e) => Err(handler_error_to_rpc(e)),
        }
    }

    async fn sign_message(&self, params: SignMessageRequest) -> Result<Value, ErrorObjectOwned> {
        let token = Self::get_token();
        if let Err(e) = check_auth(&self.state, &token, TokenScope::Read) {
            return Err(auth_error_to_rpc(e));
        }

        match handlers::handle_sign_message(&self.state, params) {
            Ok(result) => serde_json::to_value(result).map_err(|e| {
                ErrorObjectOwned::owned(
                    error_code::INTERNAL_ERROR,
                    format!("serialization error: {e}"),
                    None::<()>,
                )
            }),
            Err(e) => Err(handler_error_to_rpc(e)),
        }
    }

    async fn auth_grant(&self, params: AuthGrantRequest) -> Result<Value, ErrorObjectOwned> {
        // Keystore must exist before granting tokens
        if !self.state.keystore_path.exists() {
            return Err(ErrorObjectOwned::owned(
                error_code::INVALID_REQUEST,
                "keystore directory does not exist — run `clawlet init` first",
                None::<()>,
            ));
        }

        // Verify password
        if let Err(e) = verify_admin_password(&self.state, &params.password) {
            return Err(auth_error_to_rpc(e));
        }

        // Parse scope
        let scope: TokenScope = params
            .scope
            .parse()
            .map_err(|e: AuthError| auth_error_to_rpc(e))?;

        // Calculate expiration (None = never expires)
        let expires_in = params.expires_hours.map(|h| Duration::from_secs(h * 3600));

        // Get current Unix UID
        #[cfg(unix)]
        let uid = unsafe { libc::getuid() };
        #[cfg(not(unix))]
        let uid = 0u32;

        // Grant the session
        let mut store = self.state.session_store.write().map_err(|_| {
            ErrorObjectOwned::owned(error_code::INTERNAL_ERROR, "lock error", None::<()>)
        })?;

        let grant = store.grant(&params.agent_id, scope, expires_in, uid);

        let response = AuthGrantResponse {
            token: grant.token,
            expires_at: grant
                .expires_at
                .map(|e| e.to_rfc3339())
                .unwrap_or_else(|| "never".to_string()),
        };

        serde_json::to_value(response).map_err(|e| {
            ErrorObjectOwned::owned(
                error_code::INTERNAL_ERROR,
                format!("serialization error: {e}"),
                None::<()>,
            )
        })
    }

    async fn auth_list(&self, params: AuthListRequest) -> Result<Value, ErrorObjectOwned> {
        if let Err(e) = verify_admin_password(&self.state, &params.password) {
            return Err(auth_error_to_rpc(e));
        }

        let store = self.state.session_store.read().map_err(|_| {
            ErrorObjectOwned::owned(error_code::INTERNAL_ERROR, "lock error", None::<()>)
        })?;

        let now = chrono::Utc::now();
        let sessions: Vec<_> = store
            .list()
            .into_iter()
            .map(|(key, s)| SessionSummary {
                session_key: key.to_string(),
                id: s.id.clone(),
                scope: s.scope.to_string(),
                created_at: s.created_at.to_rfc3339(),
                expires_at: s
                    .expires_at
                    .map(|e| e.to_rfc3339())
                    .unwrap_or_else(|| "never".to_string()),
                last_used_at: s.last_used_at.to_rfc3339(),
                request_count: s.request_count,
                is_expired: s.expires_at.is_some_and(|e| e < now),
            })
            .collect();

        serde_json::to_value(AuthListResponse { sessions }).map_err(|e| {
            ErrorObjectOwned::owned(
                error_code::INTERNAL_ERROR,
                format!("serialization error: {e}"),
                None::<()>,
            )
        })
    }

    async fn auth_revoke(&self, params: AuthRevokeRequest) -> Result<Value, ErrorObjectOwned> {
        if let Err(e) = verify_admin_password(&self.state, &params.password) {
            return Err(auth_error_to_rpc(e));
        }

        let mut store = self.state.session_store.write().map_err(|_| {
            ErrorObjectOwned::owned(error_code::INTERNAL_ERROR, "lock error", None::<()>)
        })?;

        let revoked = store.revoke(&params.agent_id);
        serde_json::to_value(AuthRevokeResponse { revoked }).map_err(|e| {
            ErrorObjectOwned::owned(
                error_code::INTERNAL_ERROR,
                format!("serialization error: {e}"),
                None::<()>,
            )
        })
    }

    async fn auth_revoke_session(
        &self,
        params: AuthRevokeSessionRequest,
    ) -> Result<Value, ErrorObjectOwned> {
        if let Err(e) = verify_admin_password(&self.state, &params.password) {
            return Err(auth_error_to_rpc(e));
        }

        let mut store = self.state.session_store.write().map_err(|_| {
            ErrorObjectOwned::owned(error_code::INTERNAL_ERROR, "lock error", None::<()>)
        })?;

        let revoked = store.revoke_by_key(&params.session_key);
        serde_json::to_value(AuthRevokeSessionResponse { revoked }).map_err(|e| {
            ErrorObjectOwned::owned(
                error_code::INTERNAL_ERROR,
                format!("serialization error: {e}"),
                None::<()>,
            )
        })
    }

    async fn auth_revoke_all(
        &self,
        params: AuthRevokeAllRequest,
    ) -> Result<Value, ErrorObjectOwned> {
        if let Err(e) = verify_admin_password(&self.state, &params.password) {
            return Err(auth_error_to_rpc(e));
        }

        let mut store = self.state.session_store.write().map_err(|_| {
            ErrorObjectOwned::owned(error_code::INTERNAL_ERROR, "lock error", None::<()>)
        })?;

        let count = store.revoke_all();
        serde_json::to_value(AuthRevokeAllResponse { count }).map_err(|e| {
            ErrorObjectOwned::owned(
                error_code::INTERNAL_ERROR,
                format!("serialization error: {e}"),
                None::<()>,
            )
        })
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
        Self::start_with_config_notify(config, signer, addr, None).await
    }

    /// Start the RPC server with optional ready notification fd.
    ///
    /// If `ready_fd` is provided, "ok\n" will be written to it after the server
    /// successfully binds, signaling daemon readiness to the parent process.
    pub async fn start_with_config_notify(
        config: &Config,
        signer: LocalSigner,
        addr: Option<SocketAddr>,
        ready_fd: Option<i32>,
    ) -> Result<(), ServerError> {
        // Load policy with spending persistence — use the audit log directory
        // (the writable data dir) rather than the policy directory, which may
        // be a read-only config location in some deployments.
        let spending_path = config
            .audit_log_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("spending.json");
        let policy = PolicyEngine::from_file_with_spending(&config.policy_path, spending_path)?;

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

        // Initialize session store with disk persistence
        let sessions_path = config
            .keystore_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("sessions.json");
        let session_store = SessionStore::with_persistence(sessions_path);

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
        server.run_notify(ready_fd).await
    }

    /// Start the RPC server with an externally provided [`SessionStore`].
    ///
    /// This is used by `clawlet start` which grants a token before the server
    /// boots.  Everything else (policy, audit, EVM adapters, middleware) is
    /// identical to [`start_with_config_notify`].
    pub async fn start_with_session_notify(
        config: &Config,
        signer: LocalSigner,
        session_store: SessionStore,
        addr: Option<SocketAddr>,
        ready_fd: Option<i32>,
    ) -> Result<(), ServerError> {
        let spending_path = config
            .audit_log_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("spending.json");
        let policy = PolicyEngine::from_file_with_spending(&config.policy_path, spending_path)?;

        if let Some(parent) = config.audit_log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let audit = AuditLogger::new(&config.audit_log_path)?;

        let mut adapters = HashMap::new();
        for (chain_id, rpc_url) in &config.chain_rpc_urls {
            let adapter =
                EvmAdapter::new(rpc_url).map_err(|e| ServerError::EvmAdapter(e.to_string()))?;
            adapters.insert(*chain_id, adapter);
        }

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
        server.run_notify(ready_fd).await
    }

    /// Run the HTTP server.
    pub async fn run(&self) -> Result<(), ServerError> {
        self.run_notify(None).await
    }

    /// Run the HTTP server with optional ready notification fd.
    ///
    /// If `ready_fd` is provided, "ok\n" will be written to it after the server
    /// successfully binds (after `.build()` succeeds), signaling daemon readiness
    /// to the parent process.
    pub async fn run_notify(&self, ready_fd: Option<i32>) -> Result<(), ServerError> {
        // Build HTTP middleware that extracts Authorization header into per-request extensions
        let http_middleware =
            tower::ServiceBuilder::new().map_request(move |mut req: http::Request<_>| {
                // Extract Bearer token from Authorization header
                let token = req
                    .headers()
                    .get(http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.strip_prefix("Bearer "))
                    .map(|s| s.to_string());

                // Store in per-request extensions for propagation to RPC layer
                req.extensions_mut().insert(AuthToken(token));
                req
            });

        // Build RPC middleware that extracts token from extensions and sets task-local storage.
        // This wraps each RPC method call in a task-local scope, ensuring each request
        // has its own isolated auth token - no race conditions between concurrent requests.
        let rpc_middleware =
            RpcServiceBuilder::new().layer_fn(|service| AuthTokenMiddleware { inner: service });

        let server = Server::builder()
            .set_http_middleware(http_middleware)
            .set_rpc_middleware(rpc_middleware)
            .build(self.config.addr)
            .await
            .map_err(|e| ServerError::Bind(e.to_string()))?;

        // Signal readiness after successful bind
        #[cfg(unix)]
        if let Some(fd) = ready_fd {
            signal_daemon_ready(fd);
        }

        // Create the RPC implementation (token accessed via task-local set by RPC middleware)
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
    // If no keystore exists, deny — clawlet must be initialized first
    if !state.keystore_path.exists() {
        return Err(AuthError::InvalidToken);
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

    let keystore_path = &keystores[0];
    match Keystore::unlock(keystore_path, password) {
        Ok(_mnemonic) => {
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
