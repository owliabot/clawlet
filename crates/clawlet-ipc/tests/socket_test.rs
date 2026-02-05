//! Integration tests for Unix domain socket server.
//!
//! These tests verify the full JSON-RPC flow over Unix sockets.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use clawlet_core::audit::AuditLogger;
use clawlet_core::auth::SessionStore;
use clawlet_core::config::AuthConfig;
use clawlet_core::policy::PolicyEngine;
use clawlet_ipc::server::AppState;
use clawlet_ipc::socket::{SocketServer, SocketServerConfig};
use clawlet_signer::signer::LocalSigner;
use tempfile::TempDir;

/// Create a minimal test AppState.
fn create_test_state(temp_dir: &TempDir) -> AppState {
    let policy_yaml = r#"
per_tx_limit_usd: 1000.0
daily_limit_usd: 5000.0
allowed_tokens: []
allowed_chains: []
"#;
    let policy_path = temp_dir.path().join("policy.yaml");
    std::fs::write(&policy_path, policy_yaml).unwrap();

    let policy = PolicyEngine::from_file(&policy_path).unwrap();

    let audit_path = temp_dir.path().join("audit.log");
    let audit = AuditLogger::new(&audit_path).unwrap();

    let adapters = HashMap::new();
    let session_store = SessionStore::new();
    let skills_dir = temp_dir.path().join("skills");
    std::fs::create_dir_all(&skills_dir).unwrap();

    // Create a dummy signer
    let key_bytes = [1u8; 32];
    let signer = LocalSigner::from_bytes(&key_bytes).unwrap();

    AppState {
        policy: Arc::new(policy),
        audit: Arc::new(Mutex::new(audit)),
        adapters: Arc::new(adapters),
        session_store: Arc::new(RwLock::new(session_store)),
        auth_config: AuthConfig::default(),
        signer: Arc::new(signer),
        skills_dir,
    }
}

/// Send a JSON-RPC request and receive response.
fn send_request(stream: &mut UnixStream, request: &str) -> String {
    writeln!(stream, "{}", request).unwrap();
    stream.flush().unwrap();

    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut response = String::new();
    reader.read_line(&mut response).unwrap();
    response
}

#[tokio::test]
#[ignore] // Requires runtime to spawn server
async fn test_socket_health_check() {
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("test.sock");

    let state = Arc::new(create_test_state(&temp_dir));

    let config = SocketServerConfig {
        socket_path: socket_path.clone(),
        permissions: 0o660,
    };

    let server = SocketServer::new(config, state);

    // Spawn server in background
    let server_handle = tokio::spawn(async move {
        let _ = server.start().await;
    });

    // Wait for server to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect and send health check
    let mut stream = UnixStream::connect(&socket_path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let response = send_request(&mut stream, r#"{"jsonrpc":"2.0","method":"health","id":1}"#);

    assert!(response.contains("\"result\""));
    assert!(response.contains("\"status\":\"ok\""));
    assert!(response.contains("\"id\":1"));

    // Cleanup
    server_handle.abort();
}

#[tokio::test]
#[ignore] // Requires runtime to spawn server
async fn test_socket_unauthorized_request() {
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("test.sock");

    // Create state with auth configured
    let mut state = create_test_state(&temp_dir);
    state.auth_config.password_hash = Some(clawlet_core::auth::hash_password("testpass").unwrap());
    let state = Arc::new(state);

    let config = SocketServerConfig {
        socket_path: socket_path.clone(),
        permissions: 0o660,
    };

    let server = SocketServer::new(config, state);

    // Spawn server in background
    let server_handle = tokio::spawn(async move {
        let _ = server.start().await;
    });

    // Wait for server to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect and send unauthorized request
    let mut stream = UnixStream::connect(&socket_path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // Balance requires auth
    let response = send_request(
        &mut stream,
        r#"{"jsonrpc":"2.0","method":"balance","params":{"address":"0x1234","chain_id":1},"id":2}"#,
    );

    assert!(response.contains("\"error\""));
    assert!(response.contains("-32001")); // Unauthorized error code
    assert!(response.contains("\"id\":2"));

    // Cleanup
    server_handle.abort();
}

#[tokio::test]
#[ignore] // Requires runtime to spawn server
async fn test_socket_method_not_found() {
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("test.sock");

    let state = Arc::new(create_test_state(&temp_dir));

    let config = SocketServerConfig {
        socket_path: socket_path.clone(),
        permissions: 0o660,
    };

    let server = SocketServer::new(config, state);

    // Spawn server in background
    let server_handle = tokio::spawn(async move {
        let _ = server.start().await;
    });

    // Wait for server to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect and send unknown method
    let mut stream = UnixStream::connect(&socket_path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let response = send_request(
        &mut stream,
        r#"{"jsonrpc":"2.0","method":"unknown_method","id":3}"#,
    );

    assert!(response.contains("\"error\""));
    assert!(response.contains("-32601")); // Method not found error code
    assert!(response.contains("\"id\":3"));

    // Cleanup
    server_handle.abort();
}

#[tokio::test]
#[ignore] // Requires runtime to spawn server
async fn test_socket_invalid_json() {
    let temp_dir = TempDir::new().unwrap();
    let socket_path = temp_dir.path().join("test.sock");

    let state = Arc::new(create_test_state(&temp_dir));

    let config = SocketServerConfig {
        socket_path: socket_path.clone(),
        permissions: 0o660,
    };

    let server = SocketServer::new(config, state);

    // Spawn server in background
    let server_handle = tokio::spawn(async move {
        let _ = server.start().await;
    });

    // Wait for server to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect and send invalid JSON
    let mut stream = UnixStream::connect(&socket_path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let response = send_request(&mut stream, r#"not valid json"#);

    assert!(response.contains("\"error\""));
    assert!(response.contains("-32700")); // Parse error code

    // Cleanup
    server_handle.abort();
}

#[test]
fn test_socket_config_default() {
    let config = SocketServerConfig::default();
    assert_eq!(
        config.socket_path,
        PathBuf::from("/run/clawlet/clawlet.sock")
    );
    assert_eq!(config.permissions, 0o660);
}
