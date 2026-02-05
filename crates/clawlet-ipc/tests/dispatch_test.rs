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
