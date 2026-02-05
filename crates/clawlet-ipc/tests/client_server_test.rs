//! Integration test: client ↔ server round-trip via iceoryx2.
//!
//! Each test uses a unique service name to avoid iceoryx2 shared-memory
//! collisions when tests run in parallel.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use iceoryx2::prelude::*;

use clawlet_core::audit::AuditLogger;
use clawlet_core::auth::{SessionStore, TokenScope};
use clawlet_core::config::AuthConfig;
use clawlet_core::policy::{Policy, PolicyEngine};
use clawlet_ipc::dispatch;
use clawlet_ipc::server::AppState;
use clawlet_ipc::types::{RpcMethod, RpcRequest, RpcResponse, RpcStatus};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Generate a unique service name for each test.
fn unique_service_name() -> String {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("clawlet/test/{}/{}", std::process::id(), id)
}

/// Build a minimal AppState for testing.
/// Returns (AppState, Option<token>) - token is present if auth is enabled.
fn test_state(with_auth: bool, skills_dir: PathBuf) -> (AppState, Option<String>) {
    let tmp = tempfile::tempdir().unwrap();
    let audit_path = tmp.path().join("audit.jsonl");

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

    let mut session_store = SessionStore::new();
    let (auth_config, token) = if with_auth {
        let password_hash = clawlet_core::auth::hash_password("test_password").unwrap();
        let config = AuthConfig {
            password_hash: Some(password_hash),
            default_session_ttl_hours: 24,
            max_failed_attempts: 5,
            lockout_minutes: 15,
        };
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
    (state, token)
}

/// Start an iceoryx2 server with the given service name in a background thread.
fn start_server(service_name: &str, state: AppState) -> std::thread::JoinHandle<()> {
    let svc_name = service_name.to_string();
    let rt = tokio::runtime::Runtime::new().unwrap();

    std::thread::spawn(move || {
        let node = NodeBuilder::new()
            .create::<ipc::Service>()
            .expect("create node");

        let service = node
            .service_builder(&svc_name.as_str().try_into().expect("valid service name"))
            .request_response::<RpcRequest, RpcResponse>()
            .open_or_create()
            .expect("create service");

        let server = service.server_builder().create().expect("create server");

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if node.wait(Duration::from_millis(5)).is_err() {
                break;
            }
            while let Ok(Some(active_request)) = server.receive() {
                let response = dispatch::dispatch(&state, &*active_request, rt.handle());
                if let Ok(slot) = active_request.loan_uninit() {
                    let _ = slot.write_payload(response).send();
                }
            }
        }
    })
}

/// Create an RpcClient-like caller for a specific service name.
/// (We can't use RpcClient directly since it hardcodes SERVICE_NAME,
/// so we build the low-level call inline.)
fn call_raw(
    service_name: &str,
    method: RpcMethod,
    auth_token: &str,
    payload: &[u8],
) -> Result<RpcResponse, String> {
    let node = NodeBuilder::new()
        .create::<ipc::Service>()
        .map_err(|e| format!("node: {e:?}"))?;

    let service = node
        .service_builder(
            &service_name
                .try_into()
                .map_err(|e| format!("name: {e:?}"))?,
        )
        .request_response::<RpcRequest, RpcResponse>()
        .open()
        .map_err(|e| format!("open: {e:?}"))?;

    let client = service
        .client_builder()
        .create()
        .map_err(|e| format!("client: {e:?}"))?;

    let envelope = RpcRequest::new(method, auth_token, payload);
    let pending = client
        .send_copy(envelope)
        .map_err(|e| format!("send: {e:?}"))?;

    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(response) = pending.receive().map_err(|e| format!("recv: {e:?}"))? {
            return Ok(RpcResponse {
                status: response.status,
                payload_len: response.payload_len,
                payload: response.payload,
            });
        }
        if std::time::Instant::now() >= deadline {
            return Err("timeout".into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

// ---- Tests ----

#[test]
fn client_server_health() {
    let svc = unique_service_name();
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = test_state(false, tmp.path().to_path_buf());
    let _server = start_server(&svc, state);
    std::thread::sleep(Duration::from_millis(200));

    let resp = call_raw(&svc, RpcMethod::Health, "", b"{}").expect("call failed");
    assert!(resp.is_ok());
    let body: serde_json::Value = serde_json::from_slice(resp.payload_bytes()).unwrap();
    assert_eq!(body["status"], "ok");
}

#[test]
fn client_server_health_with_auth() {
    let svc = unique_service_name();
    let tmp = tempfile::tempdir().unwrap();
    let (state, _token) = test_state(true, tmp.path().to_path_buf());
    let _server = start_server(&svc, state);
    std::thread::sleep(Duration::from_millis(200));

    // Health works without auth
    let resp = call_raw(&svc, RpcMethod::Health, "", b"{}").expect("call failed");
    assert!(resp.is_ok());
}

#[test]
fn client_server_transfer_success() {
    let svc = unique_service_name();
    let tmp = tempfile::tempdir().unwrap();
    let (state, token) = test_state(true, tmp.path().to_path_buf());
    let token = token.unwrap();
    let _server = start_server(&svc, state);
    std::thread::sleep(Duration::from_millis(200));

    let payload = serde_json::to_vec(&serde_json::json!({
        "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "amount": "100.0",
        "token": "ETH",
        "chain_id": 1
    }))
    .unwrap();

    let resp = call_raw(&svc, RpcMethod::Transfer, &token, &payload).expect("call failed");
    assert!(resp.is_ok());
    let body: clawlet_ipc::handlers::TransferResponse =
        serde_json::from_slice(resp.payload_bytes()).unwrap();
    assert_eq!(body.status, "success");
    assert!(body.tx_hash.is_some());
}

#[test]
fn client_server_transfer_denied_by_policy() {
    let svc = unique_service_name();
    let tmp = tempfile::tempdir().unwrap();
    let (state, token) = test_state(true, tmp.path().to_path_buf());
    let token = token.unwrap();
    let _server = start_server(&svc, state);
    std::thread::sleep(Duration::from_millis(200));

    // Amount 6000 exceeds per_tx_limit of 5000
    let payload = serde_json::to_vec(&serde_json::json!({
        "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "amount": "6000.0",
        "token": "ETH",
        "chain_id": 1
    }))
    .unwrap();

    let resp = call_raw(&svc, RpcMethod::Transfer, &token, &payload).expect("call failed");
    assert!(resp.is_ok());
    let body: clawlet_ipc::handlers::TransferResponse =
        serde_json::from_slice(resp.payload_bytes()).unwrap();
    assert_eq!(body.status, "denied");
    assert!(body.reason.is_some());
}

#[test]
fn client_server_unauthorized() {
    let svc = unique_service_name();
    let tmp = tempfile::tempdir().unwrap();
    let (state, _token) = test_state(true, tmp.path().to_path_buf());
    let _server = start_server(&svc, state);
    std::thread::sleep(Duration::from_millis(200));

    let payload = serde_json::to_vec(&serde_json::json!({
        "to": "0xabc",
        "amount": "1.0",
        "token": "ETH",
        "chain_id": 1
    }))
    .unwrap();

    // Use a wrong token (not the one returned from test_state)
    let resp = call_raw(&svc, RpcMethod::Transfer, "wrong-token", &payload).expect("call failed");
    assert_eq!(resp.status, RpcStatus::Unauthorized as u32);
    assert!(!resp.is_ok());
}

#[test]
fn client_server_skills_empty() {
    let svc = unique_service_name();
    let tmp = tempfile::tempdir().unwrap();
    let skills_dir = tmp.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();

    let (state, token) = test_state(true, skills_dir);
    let token = token.unwrap();
    let _server = start_server(&svc, state);
    std::thread::sleep(Duration::from_millis(200));

    let resp = call_raw(&svc, RpcMethod::Skills, &token, b"{}").expect("call failed");
    assert!(resp.is_ok());
    let body: clawlet_ipc::handlers::SkillsResponse =
        serde_json::from_slice(resp.payload_bytes()).unwrap();
    assert!(body.skills.is_empty());
}

#[test]
fn client_server_execute_not_found() {
    let svc = unique_service_name();
    let tmp = tempfile::tempdir().unwrap();
    let skills_dir = tmp.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();

    let (state, token) = test_state(true, skills_dir);
    let token = token.unwrap();
    let _server = start_server(&svc, state);
    std::thread::sleep(Duration::from_millis(200));

    let payload = serde_json::to_vec(&serde_json::json!({
        "skill": "ghost_skill",
        "params": {}
    }))
    .unwrap();

    let resp = call_raw(&svc, RpcMethod::Execute, &token, &payload).expect("call failed");
    assert_eq!(resp.status, RpcStatus::NotFound as u32);
}

#[test]
fn client_server_balance_no_adapter() {
    let svc = unique_service_name();
    let tmp = tempfile::tempdir().unwrap();
    let (state, token) = test_state(true, tmp.path().to_path_buf());
    let token = token.unwrap();
    let _server = start_server(&svc, state);
    std::thread::sleep(Duration::from_millis(200));

    let payload = serde_json::to_vec(&serde_json::json!({
        "address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "chain_id": 1
    }))
    .unwrap();

    let resp = call_raw(&svc, RpcMethod::Balance, &token, &payload).expect("call failed");
    assert_eq!(resp.status, RpcStatus::BadRequest as u32);
    let body: serde_json::Value = serde_json::from_slice(resp.payload_bytes()).unwrap();
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("unsupported chain_id"));
}

#[test]
fn client_server_no_auth_configured() {
    // When no auth is configured, all requests should pass auth check
    let svc = unique_service_name();
    let tmp = tempfile::tempdir().unwrap();
    let (state, _) = test_state(false, tmp.path().to_path_buf()); // No auth
    let _server = start_server(&svc, state);
    std::thread::sleep(Duration::from_millis(200));

    let payload = serde_json::to_vec(&serde_json::json!({
        "address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "chain_id": 1
    }))
    .unwrap();

    // Should pass auth (but fail on missing adapter)
    let resp = call_raw(&svc, RpcMethod::Balance, "", &payload).expect("call failed");
    // BadRequest for missing adapter, not Unauthorized
    assert_eq!(resp.status, RpcStatus::BadRequest as u32);
}
