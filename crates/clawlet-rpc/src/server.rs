//! HTTP server powered by axum.
//!
//! Binds to `127.0.0.1:9100` and serves the Clawlet API.

/// Server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Bind address (default: 127.0.0.1).
    pub host: String,
    /// Bind port (default: 9100).
    pub port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 9100,
        }
    }
}

/// Starts the RPC server.
///
/// # Panics
/// Not yet implemented.
pub fn start(_config: ServerConfig) {
    todo!("M1-7: implement axum HTTP server")
}
