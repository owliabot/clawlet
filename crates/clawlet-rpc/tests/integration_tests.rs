//! Integration tests for the HTTP JSON-RPC server.
//!
//! These tests start an actual HTTP server on a random port and make real
//! HTTP requests using reqwest to verify end-to-end behavior.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use jsonrpsee::server::ServerHandle;
use reqwest::Client;
use serde_json::{json, Value};
use tempfile::TempDir;

use clawlet_core::audit::AuditLogger;
use clawlet_core::auth::SessionStore;
use clawlet_core::config::AuthConfig;
use clawlet_core::policy::{Policy, PolicyEngine};
use clawlet_rpc::server::{AppState, RpcServer, ServerConfig};
use clawlet_signer::keystore::Keystore;
use clawlet_signer::signer::LocalSigner;

/// Test password used for keystore creation.
const TEST_PASSWORD: &str = "test-password-123";

/// Timeout for HTTP requests in tests.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Test harness that manages server lifecycle and provides test utilities.
struct TestHarness {
    /// HTTP client for making requests.
    client: Client,
    /// Base URL of the running server.
    base_url: String,
    /// Temporary directory containing test files.
    #[allow(dead_code)]
    temp_dir: TempDir,
    /// Server handle to keep the server alive for test lifetime.
    #[allow(dead_code)]
    server_handle: ServerHandle,
    /// Server address.
    addr: SocketAddr,
    /// Path to keystore directory.
    #[allow(dead_code)]
    keystore_path: PathBuf,
}

impl TestHarness {
    /// Create a new test harness with a running server.
    ///
    /// Sets up:
    /// - Temporary directory for keystore, config, and audit logs
    /// - A keystore with a test wallet
    /// - Policy engine with permissive defaults
    /// - HTTP server on a random available port
    async fn new() -> Self {
        Self::with_keystore(true).await
    }

    /// Create a new test harness optionally without a keystore.
    ///
    /// When `create_keystore` is false, the server runs in unauthenticated mode.
    async fn with_keystore(create_keystore: bool) -> Self {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let keystore_path = temp_dir.path().join("keystore");
        let audit_path = temp_dir.path().join("audit.jsonl");
        let policy_path = temp_dir.path().join("policy.yaml");
        let skills_path = temp_dir.path().join("skills");

        // Create directories - only create keystore dir if we're creating a keystore
        if create_keystore {
            std::fs::create_dir_all(&keystore_path).expect("failed to create keystore dir");
        }
        std::fs::create_dir_all(&skills_path).expect("failed to create skills dir");

        // Create keystore and signer
        let signer = if create_keystore {
            let (_, ks_file) =
                Keystore::create(&keystore_path, TEST_PASSWORD).expect("failed to create keystore");
            let signing_key =
                Keystore::unlock(&ks_file, TEST_PASSWORD).expect("failed to unlock keystore");
            LocalSigner::new(signing_key)
        } else {
            // Create a signer without a keystore file
            let key_bytes = [1u8; 32];
            LocalSigner::from_bytes(&key_bytes).expect("failed to create signer")
        };

        // Create minimal policy
        let policy_yaml = r#"
daily_transfer_limit_usd: 10000.0
per_tx_limit_usd: 5000.0
allowed_tokens: []
allowed_chains: []
"#;
        std::fs::write(&policy_path, policy_yaml).expect("failed to write policy");

        // Build application state
        let policy =
            PolicyEngine::new(Policy::from_yaml(policy_yaml).expect("failed to parse policy"));
        let audit = AuditLogger::new(&audit_path).expect("failed to create audit logger");

        // Create mock EVM adapters (empty - we won't actually call RPCs in these tests)
        let adapters = HashMap::new();

        let state = Arc::new(AppState {
            policy: Arc::new(policy),
            audit: Arc::new(Mutex::new(audit)),
            adapters: Arc::new(adapters),
            session_store: Arc::new(RwLock::new(SessionStore::new())),
            auth_config: AuthConfig::default(),
            signer: Arc::new(signer),
            skills_dir: skills_path,
            keystore_path: keystore_path.clone(),
        });

        let server_config = ServerConfig {
            addr: "127.0.0.1:0".parse().expect("failed to parse addr"),
        };
        let server = RpcServer::new(server_config, Arc::clone(&state));
        let (addr, server_handle) = server.start().await.expect("failed to start server");

        // Wait for server to be ready
        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .expect("failed to create client");

        let base_url = format!("http://{}", addr);

        // Poll until server is ready
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(5) {
                panic!("Server failed to start within timeout");
            }

            let result = client
                .post(&base_url)
                .json(&json!({
                    "jsonrpc": "2.0",
                    "method": "health",
                    "params": {},
                    "id": 1
                }))
                .send()
                .await;

            if result.is_ok() {
                break;
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        Self {
            client,
            base_url,
            temp_dir,
            server_handle,
            addr,
            keystore_path,
        }
    }

    /// Make a JSON-RPC request to the server.
    ///
    /// Note: jsonrpsee methods expect params to be wrapped with the Rust parameter name.
    /// Most methods use `params: SomeType`, so we wrap accordingly.
    async fn rpc_call(&self, method: &str, params: Value) -> Result<Value, reqwest::Error> {
        // For methods with no params or empty params, send empty object
        let wrapped_params = if params.is_null() || params == json!({}) {
            json!({})
        } else {
            // Wrap params with the Rust parameter name "params" as jsonrpsee expects
            json!({ "params": params })
        };

        let response = self
            .client
            .post(&self.base_url)
            .json(&json!({
                "jsonrpc": "2.0",
                "method": method,
                "params": wrapped_params,
                "id": 1
            }))
            .send()
            .await?
            .json::<Value>()
            .await?;

        Ok(response)
    }

    /// Grant a session token with the given scope.
    async fn grant_token(&self, agent_id: &str, scope: &str) -> String {
        let response = self
            .rpc_call(
                "auth.grant",
                json!({
                    "password": TEST_PASSWORD,
                    "agent_id": agent_id,
                    "scope": scope
                }),
            )
            .await
            .expect("failed to grant token");

        response["result"]["token"]
            .as_str()
            .expect("token not in response")
            .to_string()
    }
}

// ============================================================================
// Server Lifecycle Tests
// ============================================================================

#[tokio::test]
async fn test_server_starts_and_responds_to_health() {
    let harness = TestHarness::new().await;

    let response = harness.rpc_call("health", json!({})).await.unwrap();

    assert_eq!(response["result"]["status"], "ok");
    assert!(response.get("error").is_none());
}

#[tokio::test]
async fn test_server_on_random_port() {
    let harness = TestHarness::new().await;

    // Verify port is non-zero and different from default
    assert_ne!(harness.addr.port(), 0);
    assert_ne!(harness.addr.port(), 9100);
}

#[tokio::test]
async fn test_multiple_concurrent_requests() {
    let harness = TestHarness::new().await;

    // Send multiple requests concurrently
    let request_futures: Vec<_> = (0..10)
        .map(|_| harness.rpc_call("health", json!({})))
        .collect();

    let results: Vec<Result<Value, reqwest::Error>> =
        futures::future::join_all(request_futures).await;

    for result in results {
        let response = result.expect("request failed");
        assert_eq!(response["result"]["status"], "ok");
    }
}

// ============================================================================
// Public Endpoints (No Auth Required)
// ============================================================================

#[tokio::test]
async fn test_health_returns_status_ok() {
    let harness = TestHarness::new().await;

    let response = harness.rpc_call("health", json!({})).await.unwrap();

    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert_eq!(response["result"]["status"], "ok");
}

#[tokio::test]
async fn test_address_returns_wallet_address() {
    let harness = TestHarness::new().await;

    let response = harness.rpc_call("address", json!({})).await.unwrap();

    let address = response["result"]["address"]
        .as_str()
        .expect("address should be a string");

    // Should be a valid Ethereum address format
    assert!(address.starts_with("0x"), "address should start with 0x");
    assert_eq!(address.len(), 42, "address should be 42 characters");
}

#[tokio::test]
async fn test_address_is_consistent() {
    let harness = TestHarness::new().await;

    let response1 = harness.rpc_call("address", json!({})).await.unwrap();
    let response2 = harness.rpc_call("address", json!({})).await.unwrap();

    assert_eq!(
        response1["result"]["address"], response2["result"]["address"],
        "address should be consistent across calls"
    );
}

// ============================================================================
// Read-Scope Endpoints (balance)
// ============================================================================

#[tokio::test]
async fn test_balance_without_token_returns_401() {
    let harness = TestHarness::new().await;

    let response = harness
        .rpc_call(
            "balance",
            json!({
                "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2",
                "chain_id": 1
            }),
        )
        .await
        .unwrap();

    // Should return an error since no token provided
    assert!(response.get("error").is_some(), "should return error");
    let error = &response["error"];
    assert_eq!(error["code"], -32001, "should be unauthorized error code");
}

#[tokio::test]
async fn test_balance_with_invalid_token_returns_401() {
    let harness = TestHarness::new().await;

    let response = harness
        .rpc_call(
            "balance",
            json!({
                "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2",
                "chain_id": 1,
                "token": "invalid_token_12345"
            }),
        )
        .await
        .unwrap();

    assert!(response.get("error").is_some(), "should return error");
    let error = &response["error"];
    assert_eq!(error["code"], -32001, "should be unauthorized error code");
}

#[tokio::test]
async fn test_balance_with_valid_read_token() {
    let harness = TestHarness::new().await;

    // Grant a read-scope token
    let token = harness.grant_token("test-agent", "read").await;

    // Balance requires an adapter for the chain, which we don't have in tests
    // But we should get past the auth check and fail on chain_id instead
    let response = harness
        .rpc_call(
            "balance",
            json!({
                "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2",
                "chain_id": 1,
                "token": token
            }),
        )
        .await
        .unwrap();

    // Should fail with "unsupported chain_id" not "unauthorized"
    if let Some(error) = response.get("error") {
        let msg = error["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("unsupported chain_id") || msg.contains("chain"),
            "should fail on chain_id, not auth: {}",
            msg
        );
        // Invalid params error code, not unauthorized
        assert_ne!(
            error["code"], -32001,
            "should not be unauthorized error code"
        );
    }
}

#[tokio::test]
async fn test_balance_with_trade_token_also_works() {
    let harness = TestHarness::new().await;

    // Trade scope includes read access
    let token = harness.grant_token("trade-agent", "trade").await;

    let response = harness
        .rpc_call(
            "balance",
            json!({
                "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2",
                "chain_id": 1,
                "token": token
            }),
        )
        .await
        .unwrap();

    // Should get past auth (fail on chain, not auth)
    if let Some(error) = response.get("error") {
        assert_ne!(
            error["code"], -32001,
            "should not be unauthorized with trade token"
        );
    }
}

// ============================================================================
// Trade-Scope Endpoints (transfer)
// ============================================================================

#[tokio::test]
async fn test_transfer_without_token_returns_401() {
    let harness = TestHarness::new().await;

    let response = harness
        .rpc_call(
            "transfer",
            json!({
                "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2",
                "amount": "1.0",
                "token_type": "ETH",
                "chain_id": 1
            }),
        )
        .await
        .unwrap();

    assert!(response.get("error").is_some(), "should return error");
    assert_eq!(response["error"]["code"], -32001);
}

#[tokio::test]
async fn test_transfer_with_read_token_returns_403() {
    let harness = TestHarness::new().await;

    // Grant a read-only token
    let token = harness.grant_token("read-agent", "read").await;

    let response = harness
        .rpc_call(
            "transfer",
            json!({
                "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2",
                "amount": "1.0",
                "token_type": "ETH",
                "chain_id": 1,
                "auth_token": token
            }),
        )
        .await
        .unwrap();

    // Should fail with insufficient scope
    assert!(response.get("error").is_some(), "should return error");
    let error_msg = response["error"]["message"].as_str().unwrap_or("");
    assert!(
        error_msg.contains("insufficient scope") || error_msg.contains("scope"),
        "should fail on scope: {}",
        error_msg
    );
}

#[tokio::test]
async fn test_transfer_with_trade_token_succeeds() {
    let harness = TestHarness::new().await;

    // Grant a trade-scope token
    let token = harness.grant_token("trade-agent", "trade").await;

    let response = harness
        .rpc_call(
            "transfer",
            json!({
                "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2",
                "amount": "1.0",
                "token_type": "ETH",
                "chain_id": 1,
                "auth_token": token
            }),
        )
        .await
        .unwrap();

    // Transfer should succeed (policy allows it, actual tx is mocked)
    let result = &response["result"];
    assert_eq!(result["status"], "success");
    assert!(result["tx_hash"].is_string());
    assert!(result["audit_id"].is_string());
}

#[tokio::test]
async fn test_transfer_policy_denial() {
    let harness = TestHarness::new().await;

    let token = harness.grant_token("trade-agent", "trade").await;

    // Try to transfer more than the per-tx limit (5000)
    let response = harness
        .rpc_call(
            "transfer",
            json!({
                "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2",
                "amount": "6000.0",
                "token_type": "ETH",
                "chain_id": 1,
                "auth_token": token
            }),
        )
        .await
        .unwrap();

    // Should be denied by policy
    let result = &response["result"];
    assert_eq!(result["status"], "denied");
    assert!(result["reason"].is_string());
}

// ============================================================================
// Auth Endpoints
// ============================================================================

#[tokio::test]
async fn test_auth_grant_with_correct_password() {
    let harness = TestHarness::new().await;

    let response = harness
        .rpc_call(
            "auth.grant",
            json!({
                "password": TEST_PASSWORD,
                "agent_id": "new-agent",
                "scope": "read"
            }),
        )
        .await
        .unwrap();

    assert!(
        response.get("error").is_none(),
        "should not return error: {:?}",
        response
    );
    let result = &response["result"];
    let token = result["token"].as_str().expect("token should be string");
    assert!(
        token.starts_with("clwt_"),
        "token should have correct prefix"
    );
    assert!(result["expires_at"].is_string());
}

#[tokio::test]
async fn test_auth_grant_with_wrong_password() {
    let harness = TestHarness::new().await;

    let response = harness
        .rpc_call(
            "auth.grant",
            json!({
                "password": "wrong-password",
                "agent_id": "new-agent",
                "scope": "read"
            }),
        )
        .await
        .unwrap();

    assert!(response.get("error").is_some(), "should return error");
    let error = &response["error"];
    assert_eq!(error["code"], -32001, "should be unauthorized");
}

#[tokio::test]
async fn test_auth_grant_different_scopes() {
    let harness = TestHarness::new().await;

    for scope in ["read", "trade", "admin"] {
        let response = harness
            .rpc_call(
                "auth.grant",
                json!({
                    "password": TEST_PASSWORD,
                    "agent_id": format!("{}-agent", scope),
                    "scope": scope
                }),
            )
            .await
            .unwrap();

        assert!(
            response.get("error").is_none(),
            "should grant {} scope: {:?}",
            scope,
            response
        );
    }
}

#[tokio::test]
async fn test_auth_grant_with_custom_expiry() {
    let harness = TestHarness::new().await;

    let response = harness
        .rpc_call(
            "auth.grant",
            json!({
                "password": TEST_PASSWORD,
                "agent_id": "short-lived-agent",
                "scope": "read",
                "expires_hours": 1
            }),
        )
        .await
        .unwrap();

    assert!(response.get("error").is_none());
    // Token should be valid but expire sooner
    let token = response["result"]["token"]
        .as_str()
        .expect("token should exist");
    assert!(token.starts_with("clwt_"));
}

#[tokio::test]
async fn test_auth_list_returns_sessions() {
    let harness = TestHarness::new().await;

    // Grant some sessions first
    harness.grant_token("agent-1", "read").await;
    harness.grant_token("agent-2", "trade").await;

    let response = harness
        .rpc_call(
            "auth.list",
            json!({
                "password": TEST_PASSWORD
            }),
        )
        .await
        .unwrap();

    assert!(response.get("error").is_none());
    let sessions = response["result"]["sessions"]
        .as_array()
        .expect("sessions should be array");

    assert_eq!(sessions.len(), 2);

    // Check session structure
    let session = &sessions[0];
    assert!(session["id"].is_string());
    assert!(session["scope"].is_string());
    assert!(session["created_at"].is_string());
    assert!(session["expires_at"].is_string());
    assert!(session["last_used_at"].is_string());
    assert!(session["request_count"].is_number());
}

#[tokio::test]
async fn test_auth_list_with_wrong_password() {
    let harness = TestHarness::new().await;

    let response = harness
        .rpc_call(
            "auth.list",
            json!({
                "password": "wrong-password"
            }),
        )
        .await
        .unwrap();

    assert!(response.get("error").is_some());
    assert_eq!(response["error"]["code"], -32001);
}

#[tokio::test]
async fn test_auth_revoke_session() {
    let harness = TestHarness::new().await;

    // Grant a session
    let token = harness.grant_token("revoke-test-agent", "read").await;

    // Verify token works
    let response = harness
        .rpc_call(
            "balance",
            json!({
                "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2",
                "chain_id": 1,
                "token": token.clone()
            }),
        )
        .await
        .unwrap();

    // Should fail on chain_id, not auth
    if let Some(error) = response.get("error") {
        assert_ne!(error["code"], -32001, "token should work before revoke");
    }

    // Revoke the session
    let revoke_response = harness
        .rpc_call(
            "auth.revoke",
            json!({
                "password": TEST_PASSWORD,
                "agent_id": "revoke-test-agent"
            }),
        )
        .await
        .unwrap();

    assert!(revoke_response.get("error").is_none());
    assert_eq!(revoke_response["result"]["revoked"], true);

    // Token should no longer work
    let response = harness
        .rpc_call(
            "balance",
            json!({
                "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2",
                "chain_id": 1,
                "token": token
            }),
        )
        .await
        .unwrap();

    assert!(response.get("error").is_some());
    assert_eq!(
        response["error"]["code"], -32001,
        "token should be invalid after revoke"
    );
}

#[tokio::test]
async fn test_auth_revoke_nonexistent_session() {
    let harness = TestHarness::new().await;

    let response = harness
        .rpc_call(
            "auth.revoke",
            json!({
                "password": TEST_PASSWORD,
                "agent_id": "nonexistent-agent"
            }),
        )
        .await
        .unwrap();

    assert!(response.get("error").is_none());
    assert_eq!(response["result"]["revoked"], false);
}

#[tokio::test]
async fn test_auth_revoke_all_sessions() {
    let harness = TestHarness::new().await;

    // Grant multiple sessions
    let token1 = harness.grant_token("agent-1", "read").await;
    let token2 = harness.grant_token("agent-2", "trade").await;
    let _token3 = harness.grant_token("agent-3", "admin").await;

    // Revoke all
    let response = harness
        .rpc_call(
            "auth.revoke_all",
            json!({
                "password": TEST_PASSWORD
            }),
        )
        .await
        .unwrap();

    assert!(response.get("error").is_none());
    assert_eq!(response["result"]["count"], 3);

    // Verify all tokens are invalid
    for token in [token1, token2] {
        let response = harness
            .rpc_call(
                "balance",
                json!({
                    "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2",
                    "chain_id": 1,
                    "token": token
                }),
            )
            .await
            .unwrap();

        assert!(response.get("error").is_some());
        assert_eq!(response["error"]["code"], -32001);
    }
}

#[tokio::test]
async fn test_auth_revoke_all_with_wrong_password() {
    let harness = TestHarness::new().await;

    let response = harness
        .rpc_call(
            "auth.revoke_all",
            json!({
                "password": "wrong-password"
            }),
        )
        .await
        .unwrap();

    assert!(response.get("error").is_some());
    assert_eq!(response["error"]["code"], -32001);
}

// ============================================================================
// Unauthenticated Mode (No Keystore)
// ============================================================================

#[tokio::test]
async fn test_unauthenticated_mode_allows_all_requests() {
    // Create harness without keystore
    let harness = TestHarness::with_keystore(false).await;

    // Public endpoints should work
    let response = harness.rpc_call("health", json!({})).await.unwrap();
    assert_eq!(response["result"]["status"], "ok");

    // Balance without token should work (no keystore means no auth required)
    // Will fail on chain_id, not auth
    let response = harness
        .rpc_call(
            "balance",
            json!({
                "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2",
                "chain_id": 1
            }),
        )
        .await
        .unwrap();

    // Should fail on missing adapter, not auth
    if let Some(error) = response.get("error") {
        let msg = error["message"].as_str().unwrap_or("");
        assert!(
            msg.contains("chain") || msg.contains("adapter"),
            "should fail on chain, not auth: {}",
            msg
        );
    }
}

// ============================================================================
// JSON-RPC Protocol Compliance
// ============================================================================

#[tokio::test]
async fn test_jsonrpc_response_format() {
    let harness = TestHarness::new().await;

    let response = harness.rpc_call("health", json!({})).await.unwrap();

    // Must have jsonrpc version
    assert_eq!(response["jsonrpc"], "2.0");

    // Must echo back id
    assert_eq!(response["id"], 1);

    // Must have result or error, not both
    let has_result = response.get("result").is_some();
    let has_error = response.get("error").is_some();
    assert!(
        has_result ^ has_error,
        "response must have either result or error, not both"
    );
}

#[tokio::test]
async fn test_unknown_method_returns_error() {
    let harness = TestHarness::new().await;

    let response = harness
        .rpc_call("nonexistent_method", json!({}))
        .await
        .unwrap();

    assert!(response.get("error").is_some());
    // Method not found is -32601
    let error_code = response["error"]["code"].as_i64().unwrap();
    assert!(
        error_code == -32601 || error_code == -32602,
        "should be method not found or invalid params: {}",
        error_code
    );
}

#[tokio::test]
async fn test_error_response_format() {
    let harness = TestHarness::new().await;

    // Trigger an error by omitting token for authenticated endpoint
    let response = harness
        .rpc_call(
            "balance",
            json!({
                "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2",
                "chain_id": 1
            }),
        )
        .await
        .unwrap();

    let error = response.get("error").expect("should have error");

    // Error must have code and message
    assert!(error.get("code").is_some(), "error must have code");
    assert!(error.get("message").is_some(), "error must have message");
    assert!(
        error["code"].is_number(),
        "error code must be a number: {:?}",
        error
    );
    assert!(
        error["message"].is_string(),
        "error message must be a string: {:?}",
        error
    );
}

// ============================================================================
// Token Lifecycle Tests
// ============================================================================

#[tokio::test]
async fn test_token_prefix_format() {
    let harness = TestHarness::new().await;

    let token = harness.grant_token("prefix-test", "read").await;

    assert!(
        token.starts_with("clwt_"),
        "token should start with clwt_ prefix"
    );
    // Token should be prefix + base64url encoded bytes
    let suffix = &token[5..];
    assert!(
        suffix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "token suffix should be base64url encoded"
    );
}

#[tokio::test]
async fn test_request_count_increments() {
    let harness = TestHarness::new().await;

    // Grant token
    let token = harness.grant_token("counter-agent", "read").await;

    // Make a few requests with the token that actually use it
    // balance endpoint uses token auth and will increment the request count
    for _ in 0..3 {
        harness
            .rpc_call(
                "balance",
                json!({
                    "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2",
                    "chain_id": 1,
                    "token": token
                }),
            )
            .await
            .unwrap();
    }

    // Check request count in list
    let response = harness
        .rpc_call(
            "auth.list",
            json!({
                "password": TEST_PASSWORD
            }),
        )
        .await
        .unwrap();

    let sessions = response["result"]["sessions"].as_array().unwrap();
    let agent_session = sessions
        .iter()
        .find(|s| s["id"] == "counter-agent")
        .expect("should find agent session");

    // The session was used 3 times in the balance calls
    let count = agent_session["request_count"].as_u64().unwrap();
    assert!(
        count >= 3,
        "request count should be at least 3, got {}",
        count
    );
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

#[tokio::test]
async fn test_empty_params() {
    let harness = TestHarness::new().await;

    // Health works with empty params
    let response = harness.rpc_call("health", json!({})).await.unwrap();
    assert!(response.get("error").is_none());

    // Address works with empty params
    let response = harness.rpc_call("address", json!({})).await.unwrap();
    assert!(response.get("error").is_none());
}

#[tokio::test]
async fn test_invalid_address_format() {
    let harness = TestHarness::new().await;

    let token = harness.grant_token("test-agent", "read").await;

    // The address validation happens after auth, so we need a valid token
    // But since we don't have an adapter, this will fail on chain_id first
    let response = harness
        .rpc_call(
            "balance",
            json!({
                "address": "not-a-valid-address",
                "chain_id": 1,
                "token": token
            }),
        )
        .await
        .unwrap();

    // Will fail, but not on the address format since chain_id check comes first
    assert!(response.get("error").is_some());
}

#[tokio::test]
async fn test_scope_hierarchy() {
    let harness = TestHarness::new().await;

    // Admin scope should have access to everything
    let admin_token = harness.grant_token("admin-test", "admin").await;

    // Should work for read endpoints
    let response = harness
        .rpc_call(
            "balance",
            json!({
                "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2",
                "chain_id": 1,
                "token": admin_token.clone()
            }),
        )
        .await
        .unwrap();

    // Should not fail on auth
    if let Some(error) = response.get("error") {
        assert_ne!(
            error["code"], -32001,
            "admin should have read access: {:?}",
            error
        );
    }

    // Should work for trade endpoints
    let response = harness
        .rpc_call(
            "transfer",
            json!({
                "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2",
                "amount": "1.0",
                "token_type": "ETH",
                "chain_id": 1,
                "auth_token": admin_token
            }),
        )
        .await
        .unwrap();

    // Should succeed (policy allows, tx is mocked)
    assert!(
        response.get("error").is_none(),
        "admin should have trade access: {:?}",
        response
    );
}
