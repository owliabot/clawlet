//! Tests for the dispatch layer.
//!
//! These tests create a minimal AppState and verify that dispatch
//! correctly routes requests and enforces auth.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use clawlet_core::audit::AuditLogger;
use clawlet_core::policy::{Policy, PolicyEngine};
use clawlet_rpc::dispatch::dispatch;
use clawlet_rpc::server::AppState;
use clawlet_rpc::types::{RpcMethod, RpcRequest, RpcStatus};

/// Build a minimal AppState for testing (no real EVM adapters or signer).
/// Returns (AppState, _tmp_guard) — keep the guard alive so tempdir isn't deleted.
fn test_state(auth_token: &str) -> (AppState, tempfile::TempDir) {
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

    let state = AppState {
        policy: Arc::new(PolicyEngine::new(policy)),
        audit: Arc::new(Mutex::new(AuditLogger::new(&audit_path).unwrap())),
        adapters: Arc::new(HashMap::new()),
        auth_token: auth_token.to_string(),
        signer: Arc::new(signer),
        skills_dir,
    };
    (state, tmp)
}

#[test]
fn dispatch_health_no_auth_required() {
    let (state, _tmp) = test_state("secret");
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
    let (state, _tmp) = test_state("secret");
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Balance without correct token should fail
    let payload = br#"{"address":"0xabc","chain_id":1}"#;
    let req = RpcRequest::new(RpcMethod::Balance, "wrong-token", payload);
    let resp = dispatch(&state, &req, rt.handle());

    assert_eq!(resp.status, RpcStatus::Unauthorized as u32);
    assert!(!resp.is_ok());
}

#[test]
fn dispatch_protected_route_no_token_configured() {
    // When server has no auth token, all requests pass
    let (state, _tmp) = test_state("");
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Balance with empty server token should pass auth (but may fail on missing adapter)
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
    let (state, _tmp) = test_state("tok");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let payload = serde_json::to_vec(&serde_json::json!({
        "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "amount": "100.0",
        "token": "ETH",
        "chain_id": 1
    }))
    .unwrap();

    let req = RpcRequest::new(RpcMethod::Transfer, "tok", &payload);
    let resp = dispatch(&state, &req, rt.handle());

    assert!(resp.is_ok());
    let body: clawlet_rpc::handlers::TransferResponse =
        serde_json::from_slice(resp.payload_bytes()).unwrap();
    assert_eq!(body.status, "success");
    assert!(body.tx_hash.is_some());
}

#[test]
fn dispatch_transfer_policy_denied() {
    let (state, _tmp) = test_state("tok");
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Amount exceeds per_tx_limit_usd of 5000
    let payload = serde_json::to_vec(&serde_json::json!({
        "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "amount": "6000.0",
        "token": "ETH",
        "chain_id": 1
    }))
    .unwrap();

    let req = RpcRequest::new(RpcMethod::Transfer, "tok", &payload);
    let resp = dispatch(&state, &req, rt.handle());

    assert!(resp.is_ok()); // HTTP-wise ok, but status field says "denied"
    let body: clawlet_rpc::handlers::TransferResponse =
        serde_json::from_slice(resp.payload_bytes()).unwrap();
    assert_eq!(body.status, "denied");
    assert!(body.reason.is_some());
}

#[test]
fn dispatch_skills_empty_dir() {
    let (state, _tmp) = test_state("tok");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let req = RpcRequest::new(RpcMethod::Skills, "tok", b"{}");
    let resp = dispatch(&state, &req, rt.handle());

    assert!(resp.is_ok());
    let body: clawlet_rpc::handlers::SkillsResponse =
        serde_json::from_slice(resp.payload_bytes()).unwrap();
    assert!(body.skills.is_empty());
}

#[test]
fn dispatch_unknown_method() {
    let (state, _tmp) = test_state("");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut req = RpcRequest::default();
    req.method = 255; // invalid
    let resp = dispatch(&state, &req, rt.handle());

    assert_eq!(resp.status, RpcStatus::BadRequest as u32);
}

#[test]
fn dispatch_invalid_payload_json() {
    let (state, _tmp) = test_state("");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let req = RpcRequest::new(RpcMethod::Balance, "", b"not json at all");
    let resp = dispatch(&state, &req, rt.handle());

    assert_eq!(resp.status, RpcStatus::BadRequest as u32);
}

#[test]
fn dispatch_execute_skill_not_found() {
    let (state, _tmp) = test_state("tok");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let payload = serde_json::to_vec(&serde_json::json!({
        "skill": "nonexistent_skill",
        "params": {}
    }))
    .unwrap();

    let req = RpcRequest::new(RpcMethod::Execute, "tok", &payload);
    let resp = dispatch(&state, &req, rt.handle());

    assert_eq!(resp.status, RpcStatus::NotFound as u32);
}

#[test]
fn dispatch_execute_path_traversal_rejected() {
    let (state, _tmp) = test_state("tok");
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Attempt path traversal with ../
    let payload = serde_json::to_vec(&serde_json::json!({
        "skill": "../../../etc/passwd",
        "params": {}
    }))
    .unwrap();

    let req = RpcRequest::new(RpcMethod::Execute, "tok", &payload);
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
    let (state, _tmp) = test_state("tok");
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Attempt with forward slash
    let payload = serde_json::to_vec(&serde_json::json!({
        "skill": "foo/bar",
        "params": {}
    }))
    .unwrap();

    let req = RpcRequest::new(RpcMethod::Execute, "tok", &payload);
    let resp = dispatch(&state, &req, rt.handle());

    assert_eq!(resp.status, RpcStatus::BadRequest as u32);
}

#[test]
fn dispatch_execute_empty_skill_rejected() {
    let (state, _tmp) = test_state("tok");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let payload = serde_json::to_vec(&serde_json::json!({
        "skill": "",
        "params": {}
    }))
    .unwrap();

    let req = RpcRequest::new(RpcMethod::Execute, "tok", &payload);
    let resp = dispatch(&state, &req, rt.handle());

    assert_eq!(resp.status, RpcStatus::BadRequest as u32);
}

#[test]
fn dispatch_execute_valid_skill_name_format() {
    let (state, _tmp) = test_state("tok");
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Valid format but skill doesn't exist - should get NotFound, not BadRequest
    let payload = serde_json::to_vec(&serde_json::json!({
        "skill": "valid_skill-name123",
        "params": {}
    }))
    .unwrap();

    let req = RpcRequest::new(RpcMethod::Execute, "tok", &payload);
    let resp = dispatch(&state, &req, rt.handle());

    // NotFound means the name validation passed but file doesn't exist
    assert_eq!(resp.status, RpcStatus::NotFound as u32);
}
