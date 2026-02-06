//! # clawlet-ipc
//!
//! IPC RPC server exposing wallet operations via Unix domain sockets.
//!
//! Uses JSON-RPC 2.0 protocol over local sockets powered by the `interprocess` crate.
//! This provides cross-language compatibility for non-Rust clients (Node.js, Python, etc.).

pub mod client;
pub mod dispatch;
pub mod handlers;
pub mod server;
pub mod types;

// Re-export commonly used types
pub use client::{ClientError, RpcClient};
pub use server::{AppState, JsonRpcRequest, JsonRpcResponse, RpcServer, ServerConfig};
pub use types::RpcMethod;
