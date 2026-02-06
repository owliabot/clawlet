//! # clawlet-ipc
//!
//! HTTP JSON-RPC server exposing wallet operations.
//!
//! Uses JSON-RPC 2.0 protocol over HTTP powered by `axum`.
//! This provides cross-language compatibility for non-Rust clients (Node.js, Python, etc.).

pub mod client;
pub mod dispatch;
pub mod handlers;
pub mod server;
pub mod types;

// Re-export commonly used types
pub use client::{ClientError, RpcClient};
pub use server::{
    AppState, JsonRpcRequest, JsonRpcResponse, RpcServer, ServerConfig, ServerError, DEFAULT_ADDR,
};
pub use types::RpcMethod;
