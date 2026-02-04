//! Shared IPC message types for iceoryx2 request-response communication.
//!
//! Uses fixed-size `#[repr(C)]` envelopes with embedded JSON payloads for flexibility.

use iceoryx2::prelude::*;

/// Maximum size of the JSON payload buffer (64 KiB).
pub const PAYLOAD_BUF_SIZE: usize = 65536;

/// Maximum size of the auth token field.
pub const AUTH_TOKEN_SIZE: usize = 256;

/// RPC method discriminant — maps to the five endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RpcMethod {
    Health = 0,
    Balance = 1,
    Transfer = 2,
    Skills = 3,
    Execute = 4,
}

impl RpcMethod {
    /// Try to convert a raw `u32` into an [`RpcMethod`].
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Health),
            1 => Some(Self::Balance),
            2 => Some(Self::Transfer),
            3 => Some(Self::Skills),
            4 => Some(Self::Execute),
            _ => None,
        }
    }
}

/// Response status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RpcStatus {
    Ok = 0,
    Unauthorized = 1,
    BadRequest = 2,
    NotFound = 3,
    InternalError = 4,
}

/// Fixed-size request envelope sent from client → server.
///
/// Layout: `[method: u32][auth_token: [u8; 256]][payload_len: u32][payload: [u8; 65536]]`
#[repr(C)]
#[derive(Debug)]
pub struct RpcRequest {
    /// Which RPC method to invoke.
    pub method: u32,
    /// Bearer-style auth token (null-padded).
    pub auth_token: [u8; AUTH_TOKEN_SIZE],
    /// Number of valid bytes in `payload`.
    pub payload_len: u32,
    /// JSON-serialized request body.
    pub payload: [u8; PAYLOAD_BUF_SIZE],
}

// SAFETY: RpcRequest is #[repr(C)] with only primitive fields (u32, [u8; N]).
// No pointers, references, or heap allocations. Safe for zero-copy IPC.
unsafe impl ZeroCopySend for RpcRequest {}

impl Default for RpcRequest {
    fn default() -> Self {
        Self {
            method: 0,
            auth_token: [0u8; AUTH_TOKEN_SIZE],
            payload_len: 0,
            payload: [0u8; PAYLOAD_BUF_SIZE],
        }
    }
}

impl RpcRequest {
    /// Create a new request with the given method, token, and JSON payload bytes.
    pub fn new(method: RpcMethod, token: &str, json_payload: &[u8]) -> Self {
        let mut req = Self {
            method: method as u32,
            ..Default::default()
        };

        let token_bytes = token.as_bytes();
        let token_len = token_bytes.len().min(AUTH_TOKEN_SIZE);
        req.auth_token[..token_len].copy_from_slice(&token_bytes[..token_len]);

        let payload_len = json_payload.len().min(PAYLOAD_BUF_SIZE);
        req.payload[..payload_len].copy_from_slice(&json_payload[..payload_len]);
        req.payload_len = payload_len as u32;

        req
    }

    /// Extract the auth token as a UTF-8 string (trimmed of null padding).
    pub fn token_str(&self) -> &str {
        let end = self
            .auth_token
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(AUTH_TOKEN_SIZE);
        std::str::from_utf8(&self.auth_token[..end]).unwrap_or("")
    }

    /// Extract the payload slice.
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload[..self.payload_len as usize]
    }

    /// Get the parsed [`RpcMethod`].
    pub fn rpc_method(&self) -> Option<RpcMethod> {
        RpcMethod::from_u32(self.method)
    }
}

/// Fixed-size response envelope sent from server → client.
///
/// Layout: `[status: u32][payload_len: u32][payload: [u8; 65536]]`
#[repr(C)]
#[derive(Debug)]
pub struct RpcResponse {
    /// Status code (see [`RpcStatus`]).
    pub status: u32,
    /// Number of valid bytes in `payload`.
    pub payload_len: u32,
    /// JSON-serialized response body.
    pub payload: [u8; PAYLOAD_BUF_SIZE],
}

// SAFETY: RpcResponse is #[repr(C)] with only primitive fields (u32, [u8; N]).
// No pointers, references, or heap allocations. Safe for zero-copy IPC.
unsafe impl ZeroCopySend for RpcResponse {}

impl Default for RpcResponse {
    fn default() -> Self {
        Self {
            status: 0,
            payload_len: 0,
            payload: [0u8; PAYLOAD_BUF_SIZE],
        }
    }
}

impl RpcResponse {
    /// Create a successful response with the given JSON payload.
    pub fn ok(json_payload: &[u8]) -> Self {
        let mut resp = Self {
            status: RpcStatus::Ok as u32,
            ..Default::default()
        };
        let len = json_payload.len().min(PAYLOAD_BUF_SIZE);
        resp.payload[..len].copy_from_slice(&json_payload[..len]);
        resp.payload_len = len as u32;
        resp
    }

    /// Create an error response with the given status and message.
    pub fn error(status: RpcStatus, message: &str) -> Self {
        let json = serde_json::json!({ "error": message }).to_string();
        let json_bytes = json.as_bytes();
        let mut resp = Self {
            status: status as u32,
            ..Default::default()
        };
        let len = json_bytes.len().min(PAYLOAD_BUF_SIZE);
        resp.payload[..len].copy_from_slice(&json_bytes[..len]);
        resp.payload_len = len as u32;
        resp
    }

    /// Extract the payload slice.
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload[..self.payload_len as usize]
    }

    /// Check if the response is successful.
    pub fn is_ok(&self) -> bool {
        self.status == RpcStatus::Ok as u32
    }
}
