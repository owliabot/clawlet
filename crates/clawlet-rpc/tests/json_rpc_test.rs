//! Unit tests for JSON-RPC types and server functionality.
//!
//! Tests the HTTP JSON-RPC implementation using axum.

use clawlet_rpc::server::{JsonRpcErrorCode, JsonRpcRequest, JsonRpcResponse, DEFAULT_ADDR};
use serde_json::json;

#[test]
fn parse_json_rpc_request() {
    let json = r#"{"jsonrpc":"2.0","method":"health","params":{},"id":1}"#;
    let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.jsonrpc, "2.0");
    assert_eq!(request.method, "health");
    assert_eq!(request.id, json!(1));
}

#[test]
fn parse_json_rpc_request_with_auth_in_params() {
    // Authorization is now passed via HTTP header, not in the request body
    let json = r#"{"jsonrpc":"2.0","method":"balance","params":{"address":"0x123","chain_id":8453},"id":"abc"}"#;
    let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.method, "balance");
    assert_eq!(request.id, json!("abc"));
}

#[test]
fn json_rpc_success_response() {
    let response = JsonRpcResponse::success(json!(1), json!({"status": "ok"}));
    let serialized = serde_json::to_string(&response).unwrap();
    assert!(serialized.contains("\"jsonrpc\":\"2.0\""));
    assert!(serialized.contains("\"result\":"));
    assert!(!serialized.contains("\"error\":"));
}

#[test]
fn json_rpc_error_response() {
    let response =
        JsonRpcResponse::error(json!(1), JsonRpcErrorCode::Unauthorized, "invalid token");
    let serialized = serde_json::to_string(&response).unwrap();
    assert!(serialized.contains("\"jsonrpc\":\"2.0\""));
    assert!(serialized.contains("\"error\":"));
    assert!(serialized.contains("\"code\":-32001"));
    assert!(serialized.contains("\"message\":\"invalid token\""));
    assert!(!serialized.contains("\"result\":"));
}

#[test]
fn json_rpc_null_id() {
    let json = r#"{"jsonrpc":"2.0","method":"health","id":null}"#;
    let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
    assert!(request.id.is_null());
}

#[test]
fn json_rpc_string_id() {
    let json = r#"{"jsonrpc":"2.0","method":"health","id":"request-123"}"#;
    let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.id, json!("request-123"));
}

#[test]
fn extract_bearer_token() {
    // Simulating how we extract token from Authorization header
    let auth = Some("Bearer clwt_abcd1234".to_string());
    let token = auth
        .as_deref()
        .and_then(|a| a.strip_prefix("Bearer "))
        .unwrap_or("");
    assert_eq!(token, "clwt_abcd1234");
}

#[test]
fn extract_bearer_token_missing() {
    let auth: Option<String> = None;
    let token = auth
        .as_deref()
        .and_then(|a| a.strip_prefix("Bearer "))
        .unwrap_or("");
    assert_eq!(token, "");
}

#[test]
fn extract_bearer_token_wrong_format() {
    let auth = Some("Basic xyz".to_string());
    let token = auth
        .as_deref()
        .and_then(|a| a.strip_prefix("Bearer "))
        .unwrap_or("");
    assert_eq!(token, "");
}

#[test]
fn default_addr_is_localhost() {
    assert_eq!(DEFAULT_ADDR, "127.0.0.1:9100");
}

#[test]
fn rpc_method_parse_and_roundtrip() {
    use clawlet_rpc::types::RpcMethod;

    let methods = [
        ("health", RpcMethod::Health),
        ("address", RpcMethod::Address),
        ("balance", RpcMethod::Balance),
        ("transfer", RpcMethod::Transfer),
        ("skills", RpcMethod::Skills),
        ("execute", RpcMethod::Execute),
        ("auth.grant", RpcMethod::AuthGrant),
        ("auth.list", RpcMethod::AuthList),
        ("auth.revoke", RpcMethod::AuthRevoke),
        ("auth.revoke_all", RpcMethod::AuthRevokeAll),
    ];

    for (name, expected) in methods {
        let parsed = RpcMethod::parse_method(name);
        assert_eq!(parsed, Some(expected), "parse failed for {name}");

        let back = expected.as_str();
        assert_eq!(back, name, "as_str failed for {name}");
    }

    assert_eq!(RpcMethod::parse_method("unknown"), None);
}

#[test]
fn rpc_method_required_scope() {
    use clawlet_core::auth::TokenScope;
    use clawlet_rpc::types::RpcMethod;

    // Public endpoints
    assert_eq!(RpcMethod::Health.required_scope(), None);
    assert_eq!(RpcMethod::Address.required_scope(), None);

    // Read scope
    assert_eq!(RpcMethod::Balance.required_scope(), Some(TokenScope::Read));
    assert_eq!(RpcMethod::Skills.required_scope(), Some(TokenScope::Read));

    // Trade scope
    assert_eq!(
        RpcMethod::Transfer.required_scope(),
        Some(TokenScope::Trade)
    );
    assert_eq!(RpcMethod::Execute.required_scope(), Some(TokenScope::Trade));

    // Auth methods use password, not token
    assert_eq!(RpcMethod::AuthGrant.required_scope(), None);
    assert_eq!(RpcMethod::AuthList.required_scope(), None);
    assert_eq!(RpcMethod::AuthRevoke.required_scope(), None);
    assert_eq!(RpcMethod::AuthRevokeAll.required_scope(), None);
}
