//! Unit tests for IPC message types.

use clawlet_rpc::types::{
    RpcMethod, RpcRequest, RpcResponse, RpcStatus, AUTH_TOKEN_SIZE, PAYLOAD_BUF_SIZE,
};

#[test]
fn rpc_method_round_trip() {
    assert_eq!(RpcMethod::from_u32(0), Some(RpcMethod::Health));
    assert_eq!(RpcMethod::from_u32(1), Some(RpcMethod::Balance));
    assert_eq!(RpcMethod::from_u32(2), Some(RpcMethod::Transfer));
    assert_eq!(RpcMethod::from_u32(3), Some(RpcMethod::Skills));
    assert_eq!(RpcMethod::from_u32(4), Some(RpcMethod::Execute));
    assert_eq!(RpcMethod::from_u32(99), None);
}

#[test]
fn rpc_request_new_and_accessors() {
    let payload = br#"{"address":"0xabc","chain_id":1}"#;
    let req = RpcRequest::new(RpcMethod::Balance, "my-secret-token", payload);

    assert_eq!(req.method, RpcMethod::Balance as u32);
    assert_eq!(req.rpc_method(), Some(RpcMethod::Balance));
    assert_eq!(req.token_str(), "my-secret-token");
    assert_eq!(req.payload_bytes(), payload.as_slice());
    assert_eq!(req.payload_len, payload.len() as u32);
}

#[test]
fn rpc_request_empty_token() {
    let req = RpcRequest::new(RpcMethod::Health, "", b"{}");
    assert_eq!(req.token_str(), "");
}

#[test]
fn rpc_request_max_token_truncated() {
    let long_token = "A".repeat(AUTH_TOKEN_SIZE + 50);
    let req = RpcRequest::new(RpcMethod::Health, &long_token, b"{}");
    assert_eq!(req.token_str().len(), AUTH_TOKEN_SIZE);
}

#[test]
fn rpc_request_max_payload_truncated() {
    let big_payload = vec![b'x'; PAYLOAD_BUF_SIZE + 100];
    let req = RpcRequest::new(RpcMethod::Execute, "t", &big_payload);
    assert_eq!(req.payload_len as usize, PAYLOAD_BUF_SIZE);
    assert_eq!(req.payload_bytes().len(), PAYLOAD_BUF_SIZE);
}

#[test]
fn rpc_request_default() {
    let req = RpcRequest::default();
    assert_eq!(req.method, 0);
    assert_eq!(req.payload_len, 0);
    assert_eq!(req.token_str(), "");
    assert_eq!(req.payload_bytes(), &[] as &[u8]);
}

#[test]
fn rpc_response_ok() {
    let json = br#"{"status":"ok"}"#;
    let resp = RpcResponse::ok(json);
    assert!(resp.is_ok());
    assert_eq!(resp.status, RpcStatus::Ok as u32);
    assert_eq!(resp.payload_bytes(), json.as_slice());
}

#[test]
fn rpc_response_error() {
    let resp = RpcResponse::error(RpcStatus::Unauthorized, "bad token");
    assert!(!resp.is_ok());
    assert_eq!(resp.status, RpcStatus::Unauthorized as u32);
    let body: serde_json::Value = serde_json::from_slice(resp.payload_bytes()).unwrap();
    assert_eq!(body["error"], "bad token");
}

#[test]
fn rpc_response_error_variants() {
    for (status, code) in [
        (RpcStatus::BadRequest, 2),
        (RpcStatus::NotFound, 3),
        (RpcStatus::InternalError, 4),
    ] {
        let resp = RpcResponse::error(status, "msg");
        assert_eq!(resp.status, code);
        assert!(!resp.is_ok());
    }
}

#[test]
fn rpc_response_default() {
    let resp = RpcResponse::default();
    assert!(resp.is_ok()); // status 0 = Ok
    assert_eq!(resp.payload_len, 0);
}

#[test]
fn rpc_request_repr_c_size() {
    // Ensure the struct sizes are reasonable and stable
    let req_size = std::mem::size_of::<RpcRequest>();
    let resp_size = std::mem::size_of::<RpcResponse>();

    // method(4) + auth_token(256) + payload_len(4) + payload(65536) = 65800
    assert_eq!(req_size, 65800, "RpcRequest size should be 65800 bytes");
    // status(4) + payload_len(4) + payload(65536) = 65544
    assert_eq!(resp_size, 65544, "RpcResponse size should be 65544 bytes");
}

#[test]
fn rpc_request_malformed_payload_len_no_panic() {
    // Simulate a malicious request with payload_len > buffer size
    let mut req = RpcRequest::default();
    req.payload_len = (PAYLOAD_BUF_SIZE + 10000) as u32; // Way over buffer

    // Should NOT panic, should clamp to buffer size
    let bytes = req.payload_bytes();
    assert_eq!(bytes.len(), PAYLOAD_BUF_SIZE);
}

#[test]
fn rpc_response_malformed_payload_len_no_panic() {
    // Simulate a malicious response with payload_len > buffer size
    let mut resp = RpcResponse::default();
    resp.payload_len = u32::MAX; // Extremely malicious value

    // Should NOT panic, should clamp to buffer size
    let bytes = resp.payload_bytes();
    assert_eq!(bytes.len(), PAYLOAD_BUF_SIZE);
}

#[test]
fn rpc_request_payload_len_at_boundary() {
    let mut req = RpcRequest::default();

    // Exactly at buffer size
    req.payload_len = PAYLOAD_BUF_SIZE as u32;
    assert_eq!(req.payload_bytes().len(), PAYLOAD_BUF_SIZE);

    // One over
    req.payload_len = (PAYLOAD_BUF_SIZE + 1) as u32;
    assert_eq!(req.payload_bytes().len(), PAYLOAD_BUF_SIZE);
}
