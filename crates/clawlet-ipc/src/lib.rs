//! # clawlet-ipc
//!
//! IPC RPC server exposing wallet operations via iceoryx2 request-response
//! and Unix domain sockets (for non-Rust clients).

pub mod client;
pub mod dispatch;
pub mod handlers;
pub mod server;
pub mod socket;
pub mod types;
