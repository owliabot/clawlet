//! Tests for the dispatch layer.
//!
//! These tests create a minimal AppState and verify that dispatch
//! correctly routes requests and enforces auth.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use clawlet_core::audit::AuditLogger;
use clawlet_core::auth::{SessionStore, TokenScope};
use clawlet_core::config::AuthConfig;
use clawlet_core::policy::{Policy, PolicyEngine};
use clawlet_ipc::dispatch::dispatch;
use clawlet_ipc::server::AppState;
use clawlet_ipc::types::{RpcMethod, RpcRequest, RpcStatus};

/// Build a minimal AppState for testing (no real EVM adapters or signer).
/// Returns (AppState, token, _tmp_guard) — keep the guard alive so tempdir isn't deleted.
fn test_state_with_auth(with_password: bool) -> (AppState, Option<String>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let audit_path = tmp.path().join("audit.jsonl");
    let skills_dir = tmp.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();

    let policy = Policy {
        daily_transfer_limit_usd: 10_000.0,
        per_tx_limit_usd: 5_000.0,
        allowed_tokens: vec![],
        allowed_chains: vec![],
        require_approval_above_usd: None,
    };

    // Create a dummy signer (Anvil account 0)
    let key_bytes =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let signer =
        clawlet_signer::signer::LocalSigner::from_bytes(&key_bytes.try_into().expect("32 bytes"))
            .unwrap();

    let mut session_store = SessionStore::new();

    // Optionally set up auth with password
    let (auth_config, token) = if with_password {
        let password_hash = clawlet_core::auth::hash_password("test_password").unwrap();
        let config = AuthConfig {
            password_hash: Some(password_hash),
            default_session_ttl_hours: 24,
            max_failed_attempts: 5,
            lockout_minutes: 15,
        };
        // Grant a session token for tests
        let token = session_store.grant(
            "test-agent",
            TokenScope::Admin,
            Duration::from_secs(3600),
            0,
        );
        (config, Some(token))
    } else {
        (AuthConfig::default(), None)
    };

    let state = AppState {
        policy: Arc::new(PolicyEngine::new(policy)),
        audit: Arc::new(Mutex::new(AuditLogger::new(&audit_path).unwrap())),
        adapters: Arc::new(HashMap::new()),
        session_store: Arc::new(RwLock::new(session_store)),
        auth_config,
        signer: Arc::new(signer),
        skills_dir,
    };
    (state, token, tmp)
}

#[test]
fn dispatch_health_no_auth_required() {
    let (state, _token, _tmp) = test_state_with_auth(true);
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Health should work without auth token
    let req = RpcRequest::new(RpcMethod::Health, "", b"{}");
    let resp = dispatch(&state, &req, rt.handle());

    assert!(resp.is_ok());
    let body: serde_json::Value = serde_json::from_slice(resp.payload_bytes()).unwrap();
    assert_eq!(body["status"], "ok");
}

#[test]
fn dispatch_protected_route_unauthorized() {
    let (state, _token, _tmp) = test_state_with_auth(true);
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Balance without correct token should fail
    let payload = br#"{"address":"0xabc","chain_id":1}"#;
    let req = RpcRequest::new(RpcMethod::Balance, "wrong-token", payload);
    let resp = dispatch(&state, &req, rt.handle());

    assert_eq!(resp.status, RpcStatus::Unauthorized as u32);
    assert!(!resp.is_ok());
}

#[test]
fn dispatch_protected_route_no_auth_configured() {
    // When server has no password hash configured, all requests pass
    let (state, _, _tmp) = test_state_with_auth(false);
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Balance with no auth configured should pass auth (but may fail on missing adapter)
    let payload = br#"{"address":"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266","chain_id":1}"#;
    let req = RpcRequest::new(RpcMethod::Balance, "", payload);
    let resp = dispatch(&state, &req, rt.handle());

    // Should get BadRequest (unsupported chain_id) not Unauthorized
    assert_eq!(resp.status, RpcStatus::BadRequest as u32);
    let body: serde_json::Value = serde_json::from_slice(resp.payload_bytes()).unwrap();
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("unsupported chain_id"));
}

#[test]
fn dispatch_transfer_policy_allowed() {
    let (state, token, _tmp) = test_state_with_auth(true);
    let token = token.unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();

    let payload = serde_json::to_vec(&serde_json::json!({
        "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "amount": "100.0",
        "token": "ETH",
        "chain_id": 1
    }))
    .unwrap();

    let req = RpcRequest::new(RpcMethod::Transfer, &token, &payload);
    let resp = dispatch(&state, &req, rt.handle());

    assert!(resp.is_ok());
    let body: clawlet_ipc::handlers::TransferResponse =
        serde_json::from_slice(resp.payload_bytes()).unwrap();
    assert_eq!(body.status, "success");
    assert!(body.tx_hash.is_some());
}

#[test]
fn dispatch_transfer_policy_denied() {
    let (state, token, _tmp) = test_state_with_auth(true);
    let token = token.unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Amount exceeds per_tx_limit_usd of 5000
    let payload = serde_json::to_vec(&serde_json::json!({
        "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "amount": "6000.0",
        "token": "ETH",
        "chain_id": 1
    }))
    .unwrap();

    let req = RpcRequest::new(RpcMethod::Transfer, &token, &payload);
    let resp = dispatch(&state, &req, rt.handle());

    assert!(resp.is_ok()); // HTTP-wise ok, but status field says "denied"
    let body: clawlet_ipc::handlers::TransferResponse =
        serde_json::from_slice(resp.payload_bytes()).unwrap();
    assert_eq!(body.status, "denied");
    assert!(body.reason.is_some());
}

#[test]
fn dispatch_skills_empty_dir() {
    let (state, token, _tmp) = test_state_with_auth(true);
    let token = token.unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();

    let req = RpcRequest::new(RpcMethod::Skills, &token, b"{}");
    let resp = dispatch(&state, &req, rt.handle());

    assert!(resp.is_ok());
    let body: clawlet_ipc::handlers::SkillsResponse =
        serde_json::from_slice(resp.payload_bytes()).unwrap();
    assert!(body.skills.is_empty());
}

#[test]
fn dispatch_unknown_method() {
    let (state, _, _tmp) = test_state_with_auth(false);
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut req = RpcRequest::default();
    req.method = 255; // invalid
    let resp = dispatch(&state, &req, rt.handle());

    assert_eq!(resp.status, RpcStatus::BadRequest as u32);
}

#[test]
fn dispatch_invalid_payload_json() {
    let (state, _, _tmp) = test_state_with_auth(false);
    let rt = tokio::runtime::Runtime::new().unwrap();

    let req = RpcRequest::new(RpcMethod::Balance, "", b"not json at all");
    let resp = dispatch(&state, &req, rt.handle());

    assert_eq!(resp.status, RpcStatus::BadRequest as u32);
}

#[test]
fn dispatch_execute_skill_not_found() {
    let (state, token, _tmp) = test_state_with_auth(true);
    let token = token.unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();

    let payload = serde_json::to_vec(&serde_json::json!({
        "skill": "nonexistent_skill",
        "params": {}
    }))
    .unwrap();

    let req = RpcRequest::new(RpcMethod::Execute, &token, &payload);
    let resp = dispatch(&state, &req, rt.handle());

    assert_eq!(resp.status, RpcStatus::NotFound as u32);
}

#[test]
fn dispatch_execute_path_traversal_rejected() {
    let (state, token, _tmp) = test_state_with_auth(true);
    let token = token.unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Attempt path traversal with ../
    let payload = serde_json::to_vec(&serde_json::json!({
        "skill": "../../../etc/passwd",
        "params": {}
    }))
    .unwrap();

    let req = RpcRequest::new(RpcMethod::Execute, &token, &payload);
    let resp = dispatch(&state, &req, rt.handle());

    // Should be rejected as BadRequest, not NotFound (which would mean it tried to access the path)
    assert_eq!(resp.status, RpcStatus::BadRequest as u32);
    let body: serde_json::Value = serde_json::from_slice(resp.payload_bytes()).unwrap();
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("invalid skill name"));
}

#[test]
fn dispatch_execute_path_separator_rejected() {
    let (state, token, _tmp) = test_state_with_auth(true);
    let token = token.unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Attempt with forward slash
    let payload = serde_json::to_vec(&serde_json::json!({
        "skill": "foo/bar",
        "params": {}
    }))
    .unwrap();

    let req = RpcRequest::new(RpcMethod::Execute, &token, &payload);
    let resp = dispatch(&state, &req, rt.handle());

    assert_eq!(resp.status, RpcStatus::BadRequest as u32);
}

#[test]
fn dispatch_execute_empty_skill_rejected() {
    let (state, token, _tmp) = test_state_with_auth(true);
    let token = token.unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();

    let payload = serde_json::to_vec(&serde_json::json!({
        "skill": "",
        "params": {}
    }))
    .unwrap();

    let req = RpcRequest::new(RpcMethod::Execute, &token, &payload);
    let resp = dispatch(&state, &req, rt.handle());

    assert_eq!(resp.status, RpcStatus::BadRequest as u32);
}

#[test]
fn dispatch_execute_valid_skill_name_format() {
    let (state, token, _tmp) = test_state_with_auth(true);
    let token = token.unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Valid format but skill doesn't exist - should get NotFound, not BadRequest
    let payload = serde_json::to_vec(&serde_json::json!({
        "skill": "valid_skill-name123",
        "params": {}
    }))
    .unwrap();

    let req = RpcRequest::new(RpcMethod::Execute, &token, &payload);
    let resp = dispatch(&state, &req, rt.handle());

    // NotFound means the name validation passed but file doesn't exist
    assert_eq!(resp.status, RpcStatus::NotFound as u32);
}

#[cfg(unix)]
#[test]
fn dispatch_execute_symlink_escape_rejected() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let skills_dir = tmp.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();

    // Create a file outside skills dir
    let outside_file = tmp.path().join("secret.yaml");
    std::fs::write(
        &outside_file,
        "name: secret\nprotocol: hack\nchain_id: 1\nactions: []",
    )
    .unwrap();

    // Create a symlink inside skills dir pointing outside
    let symlink_path = skills_dir.join("escape.yaml");
    symlink(&outside_file, &symlink_path).unwrap();

    // Build state with this skills_dir
    let audit_path = tmp.path().join("audit.jsonl");
    let policy = clawlet_core::policy::Policy {
        daily_transfer_limit_usd: 10_000.0,
        per_tx_limit_usd: 5_000.0,
        allowed_tokens: vec![],
        allowed_chains: vec![],
        require_approval_above_usd: None,
    };
    let key_bytes =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let signer =
        clawlet_signer::signer::LocalSigner::from_bytes(&key_bytes.try_into().expect("32 bytes"))
            .unwrap();

    // Set up auth with a session token
    let password_hash = clawlet_core::auth::hash_password("test").unwrap();
    let mut session_store = SessionStore::new();
    let token = session_store.grant(
        "test-agent",
        TokenScope::Admin,
        Duration::from_secs(3600),
        0,
    );

    let state = clawlet_ipc::server::AppState {
        policy: Arc::new(clawlet_core::policy::PolicyEngine::new(policy)),
        audit: Arc::new(Mutex::new(
            clawlet_core::audit::AuditLogger::new(&audit_path).unwrap(),
        )),
        adapters: Arc::new(HashMap::new()),
        session_store: Arc::new(RwLock::new(session_store)),
        auth_config: AuthConfig {
            password_hash: Some(password_hash),
            default_session_ttl_hours: 24,
            max_failed_attempts: 5,
            lockout_minutes: 15,
        },
        signer: Arc::new(signer),
        skills_dir,
    };

    let rt = tokio::runtime::Runtime::new().unwrap();

    // Try to execute the symlinked skill
    let payload = serde_json::to_vec(&serde_json::json!({
        "skill": "escape",
        "params": {}
    }))
    .unwrap();

    let req = RpcRequest::new(RpcMethod::Execute, &token, &payload);
    let resp = dispatch(&state, &req, rt.handle());

    // Should be rejected because canonical path escapes skills_dir
    assert_eq!(resp.status, RpcStatus::BadRequest as u32);
    let body: serde_json::Value = serde_json::from_slice(resp.payload_bytes()).unwrap();
    assert!(body["error"].as_str().unwrap().contains("escapes"));
}

// Auth-specific tests
#[test]
fn dispatch_insufficient_scope_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let audit_path = tmp.path().join("audit.jsonl");
    let skills_dir = tmp.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();

    let policy = Policy {
        daily_transfer_limit_usd: 10_000.0,
        per_tx_limit_usd: 5_000.0,
        allowed_tokens: vec![],
        allowed_chains: vec![],
        require_approval_above_usd: None,
    };

    let key_bytes =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let signer =
        clawlet_signer::signer::LocalSigner::from_bytes(&key_bytes.try_into().expect("32 bytes"))
            .unwrap();

    let password_hash = clawlet_core::auth::hash_password("test").unwrap();
    let mut session_store = SessionStore::new();
    // Grant a READ-only token
    let token = session_store.grant("read-agent", TokenScope::Read, Duration::from_secs(3600), 0);

    let state = AppState {
        policy: Arc::new(PolicyEngine::new(policy)),
        audit: Arc::new(Mutex::new(AuditLogger::new(&audit_path).unwrap())),
        adapters: Arc::new(HashMap::new()),
        session_store: Arc::new(RwLock::new(session_store)),
        auth_config: AuthConfig {
            password_hash: Some(password_hash),
            default_session_ttl_hours: 24,
            max_failed_attempts: 5,
            lockout_minutes: 15,
        },
        signer: Arc::new(signer),
        skills_dir,
    };

    let rt = tokio::runtime::Runtime::new().unwrap();

    // Try to execute a transfer with a READ-only token (requires TRADE scope)
    let payload = serde_json::to_vec(&serde_json::json!({
        "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "amount": "100.0",
        "token": "ETH",
        "chain_id": 1
    }))
    .unwrap();

    let req = RpcRequest::new(RpcMethod::Transfer, &token, &payload);
    let resp = dispatch(&state, &req, rt.handle());

    // Should be unauthorized due to insufficient scope
    assert_eq!(resp.status, RpcStatus::Unauthorized as u32);
    let body: serde_json::Value = serde_json::from_slice(resp.payload_bytes()).unwrap();
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("insufficient scope"));
}

// ============================================================================
// Auth endpoint tests (AuthGrant, AuthList, AuthRevoke, AuthRevokeAll)
// These test the actual auth flow without pre-granting tokens
// ============================================================================

/// Helper to create AppState with password auth enabled but NO pre-granted tokens.
fn test_state_auth_only() -> (AppState, String, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let audit_path = tmp.path().join("audit.jsonl");
    let skills_dir = tmp.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();

    let policy = Policy {
        daily_transfer_limit_usd: 10_000.0,
        per_tx_limit_usd: 5_000.0,
        allowed_tokens: vec![],
        allowed_chains: vec![],
        require_approval_above_usd: None,
    };

    let key_bytes =
        hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80").unwrap();
    let signer =
        clawlet_signer::signer::LocalSigner::from_bytes(&key_bytes.try_into().expect("32 bytes"))
            .unwrap();

    let password = "test_password_123";
    let password_hash = clawlet_core::auth::hash_password(password).unwrap();
    let session_store = SessionStore::new(); // Empty - no pre-granted tokens!

    let state = AppState {
        policy: Arc::new(PolicyEngine::new(policy)),
        audit: Arc::new(Mutex::new(AuditLogger::new(&audit_path).unwrap())),
        adapters: Arc::new(HashMap::new()),
        session_store: Arc::new(RwLock::new(session_store)),
        auth_config: AuthConfig {
            password_hash: Some(password_hash),
            default_session_ttl_hours: 24,
            max_failed_attempts: 5,
            lockout_minutes: 15,
        },
        signer: Arc::new(signer),
        skills_dir,
    };
    (state, password.to_string(), tmp)
}

#[test]
fn dispatch_auth_grant_success() {
    let (state, password, _tmp) = test_state_auth_only();
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Grant a new session with password (no token required!)
    let payload = serde_json::to_vec(&serde_json::json!({
        "password": password,
        "agent_id": "my-agent",
        "scope": "trade"
    }))
    .unwrap();

    let req = RpcRequest::new(RpcMethod::AuthGrant, "", &payload);
    let resp = dispatch(&state, &req, rt.handle());

    assert!(resp.is_ok(), "AuthGrant should succeed");
    let body: serde_json::Value = serde_json::from_slice(resp.payload_bytes()).unwrap();
    assert!(body["token"].as_str().is_some(), "Should return a token");
    assert!(
        body["token"].as_str().unwrap().starts_with("clwt_"),
        "Token should have correct prefix"
    );
    assert!(body["expires_at"].as_str().is_some());
}

#[test]
fn dispatch_auth_grant_wrong_password() {
    let (state, _password, _tmp) = test_state_auth_only();
    let rt = tokio::runtime::Runtime::new().unwrap();

    let payload = serde_json::to_vec(&serde_json::json!({
        "password": "wrong_password",
        "agent_id": "my-agent",
        "scope": "trade"
    }))
    .unwrap();

    let req = RpcRequest::new(RpcMethod::AuthGrant, "", &payload);
    let resp = dispatch(&state, &req, rt.handle());

    assert_eq!(resp.status, RpcStatus::Unauthorized as u32);
}

#[test]
fn dispatch_auth_grant_then_use_token() {
    let (state, password, _tmp) = test_state_auth_only();
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Step 1: Grant a session
    let grant_payload = serde_json::to_vec(&serde_json::json!({
        "password": password,
        "agent_id": "my-agent",
        "scope": "read"
    }))
    .unwrap();

    let grant_req = RpcRequest::new(RpcMethod::AuthGrant, "", &grant_payload);
    let grant_resp = dispatch(&state, &grant_req, rt.handle());
    assert!(grant_resp.is_ok());

    let grant_body: serde_json::Value =
        serde_json::from_slice(grant_resp.payload_bytes()).unwrap();
    let token = grant_body["token"].as_str().unwrap();

    // Step 2: Use the token to call a protected endpoint
    let skills_payload = b"{}";
    let skills_req = RpcRequest::new(RpcMethod::Skills, token, skills_payload);
    let skills_resp = dispatch(&state, &skills_req, rt.handle());

    assert!(skills_resp.is_ok(), "Should be able to use granted token");
}

#[test]
fn dispatch_auth_list_success() {
    let (state, password, _tmp) = test_state_auth_only();
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Grant two sessions first
    for agent in &["agent-1", "agent-2"] {
        let payload = serde_json::to_vec(&serde_json::json!({
            "password": password,
            "agent_id": agent,
            "scope": "read"
        }))
        .unwrap();
        let req = RpcRequest::new(RpcMethod::AuthGrant, "", &payload);
        let resp = dispatch(&state, &req, rt.handle());
        assert!(resp.is_ok());
    }

    // List sessions
    let list_payload = serde_json::to_vec(&serde_json::json!({
        "password": password
    }))
    .unwrap();

    let list_req = RpcRequest::new(RpcMethod::AuthList, "", &list_payload);
    let list_resp = dispatch(&state, &list_req, rt.handle());

    assert!(list_resp.is_ok());
    let body: serde_json::Value = serde_json::from_slice(list_resp.payload_bytes()).unwrap();
    let sessions = body["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 2, "Should list both sessions");
}

#[test]
fn dispatch_auth_revoke_success() {
    let (state, password, _tmp) = test_state_auth_only();
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Grant a session
    let grant_payload = serde_json::to_vec(&serde_json::json!({
        "password": password,
        "agent_id": "agent-to-revoke",
        "scope": "read"
    }))
    .unwrap();
    let grant_req = RpcRequest::new(RpcMethod::AuthGrant, "", &grant_payload);
    let grant_resp = dispatch(&state, &grant_req, rt.handle());
    assert!(grant_resp.is_ok());

    let grant_body: serde_json::Value =
        serde_json::from_slice(grant_resp.payload_bytes()).unwrap();
    let token = grant_body["token"].as_str().unwrap().to_string();

    // Revoke the session
    let revoke_payload = serde_json::to_vec(&serde_json::json!({
        "password": password,
        "agent_id": "agent-to-revoke"
    }))
    .unwrap();
    let revoke_req = RpcRequest::new(RpcMethod::AuthRevoke, "", &revoke_payload);
    let revoke_resp = dispatch(&state, &revoke_req, rt.handle());

    assert!(revoke_resp.is_ok());
    let revoke_body: serde_json::Value =
        serde_json::from_slice(revoke_resp.payload_bytes()).unwrap();
    assert!(revoke_body["revoked"].as_bool().unwrap());

    // Verify the token no longer works
    let skills_req = RpcRequest::new(RpcMethod::Skills, &token, b"{}");
    let skills_resp = dispatch(&state, &skills_req, rt.handle());
    assert_eq!(
        skills_resp.status,
        RpcStatus::Unauthorized as u32,
        "Revoked token should not work"
    );
}

#[test]
fn dispatch_auth_revoke_all_success() {
    let (state, password, _tmp) = test_state_auth_only();
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Grant multiple sessions
    let mut tokens = Vec::new();
    for i in 0..3 {
        let payload = serde_json::to_vec(&serde_json::json!({
            "password": password,
            "agent_id": format!("agent-{}", i),
            "scope": "read"
        }))
        .unwrap();
        let req = RpcRequest::new(RpcMethod::AuthGrant, "", &payload);
        let resp = dispatch(&state, &req, rt.handle());
        assert!(resp.is_ok());

        let body: serde_json::Value = serde_json::from_slice(resp.payload_bytes()).unwrap();
        tokens.push(body["token"].as_str().unwrap().to_string());
    }

    // Revoke all
    let revoke_all_payload = serde_json::to_vec(&serde_json::json!({
        "password": password
    }))
    .unwrap();
    let revoke_all_req = RpcRequest::new(RpcMethod::AuthRevokeAll, "", &revoke_all_payload);
    let revoke_all_resp = dispatch(&state, &revoke_all_req, rt.handle());

    assert!(revoke_all_resp.is_ok());
    let body: serde_json::Value = serde_json::from_slice(revoke_all_resp.payload_bytes()).unwrap();
    assert_eq!(body["count"].as_u64().unwrap(), 3);

    // Verify all tokens are invalid
    for token in &tokens {
        let skills_req = RpcRequest::new(RpcMethod::Skills, token, b"{}");
        let skills_resp = dispatch(&state, &skills_req, rt.handle());
        assert_eq!(
            skills_resp.status,
            RpcStatus::Unauthorized as u32,
            "All tokens should be revoked"
        );
    }
}

#[test]
fn dispatch_auth_grant_bootstrap_from_zero() {
    // This is the critical test: can we grant the FIRST token when auth is enabled?
    let (state, password, _tmp) = test_state_auth_only();
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Verify no tokens exist
    let list_payload = serde_json::to_vec(&serde_json::json!({
        "password": password
    }))
    .unwrap();
    let list_req = RpcRequest::new(RpcMethod::AuthList, "", &list_payload);
    let list_resp = dispatch(&state, &list_req, rt.handle());
    assert!(list_resp.is_ok());
    let list_body: serde_json::Value = serde_json::from_slice(list_resp.payload_bytes()).unwrap();
    assert_eq!(
        list_body["sessions"].as_array().unwrap().len(),
        0,
        "Should start with no sessions"
    );

    // Grant the first token (the bootstrap case!)
    let grant_payload = serde_json::to_vec(&serde_json::json!({
        "password": password,
        "agent_id": "first-agent",
        "scope": "admin"
    }))
    .unwrap();
    let grant_req = RpcRequest::new(RpcMethod::AuthGrant, "", &grant_payload);
    let grant_resp = dispatch(&state, &grant_req, rt.handle());

    assert!(
        grant_resp.is_ok(),
        "CRITICAL: Must be able to grant first token without existing token!"
    );

    let grant_body: serde_json::Value =
        serde_json::from_slice(grant_resp.payload_bytes()).unwrap();
    let token = grant_body["token"].as_str().unwrap();

    // Use the bootstrapped token
    let skills_req = RpcRequest::new(RpcMethod::Skills, token, b"{}");
    let skills_resp = dispatch(&state, &skills_req, rt.handle());
    assert!(skills_resp.is_ok(), "Bootstrapped token should work");
}
