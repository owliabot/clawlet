//! Client-side helper for connecting to the clawlet-ipc Unix socket server.
//!
//! Provides a typed API that serializes requests to JSON-RPC format
//! and deserializes responses.

use std::path::{Path, PathBuf};
use std::time::Duration;

use interprocess::local_socket::{
    tokio::{prelude::*, Stream},
    GenericFilePath,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::handlers::{
    BalanceQuery, BalanceResponse, ExecuteRequest, ExecuteResponse, SkillsResponse,
    TransferRequest, TransferResponse,
};
use crate::server::{default_socket_path, JsonRpcRequest, JsonRpcResponse, RequestMeta};

/// Error type for RPC client operations.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("connection error: {0}")]
    Connection(String),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("timeout waiting for response")]
    Timeout,
    #[error("server returned error: {message} (code {code})")]
    Server { code: i32, message: String },
}

/// Client for the clawlet-ipc Unix socket server.
pub struct RpcClient {
    /// Path to the Unix socket.
    socket_path: PathBuf,
    /// Auth token to include in every request.
    auth_token: String,
    /// Timeout for operations.
    timeout: Duration,
}

impl Default for RpcClient {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            auth_token: String::new(),
            timeout: Duration::from_secs(5),
        }
    }
}

impl RpcClient {
    /// Create a new client connecting to the default socket path.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new client connecting to a specific socket path.
    pub fn with_path(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            ..Default::default()
        }
    }

    /// Set the auth token for all requests.
    pub fn with_token(mut self, auth_token: impl Into<String>) -> Self {
        self.auth_token = auth_token.into();
        self
    }

    /// Set the timeout for operations.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Get the socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Perform a health check.
    pub async fn health(&self) -> Result<serde_json::Value, ClientError> {
        self.call("health", serde_json::json!({})).await
    }

    /// Query ETH balance.
    pub async fn balance(&self, query: BalanceQuery) -> Result<BalanceResponse, ClientError> {
        self.call("balance", query).await
    }

    /// Execute a transfer.
    pub async fn transfer(&self, req: TransferRequest) -> Result<TransferResponse, ClientError> {
        self.call("transfer", req).await
    }

    /// List available skills.
    pub async fn skills(&self) -> Result<SkillsResponse, ClientError> {
        self.call("skills", serde_json::json!({})).await
    }

    /// Execute a skill.
    pub async fn execute(&self, req: ExecuteRequest) -> Result<ExecuteResponse, ClientError> {
        self.call("execute", req).await
    }

    /// Send a raw JSON-RPC request and get the raw response.
    pub async fn call_raw(
        &self,
        method: &str,
        params: Value,
    ) -> Result<JsonRpcResponse, ClientError> {
        self.send_request(method, params, &self.auth_token).await
    }

    /// Send a typed JSON-RPC request.
    async fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R, ClientError> {
        let params = serde_json::to_value(params)?;
        let response = self.send_request(method, params, &self.auth_token).await?;

        if let Some(error) = response.error {
            return Err(ClientError::Server {
                code: error.code,
                message: error.message,
            });
        }

        let result = response.result.unwrap_or(Value::Null);
        serde_json::from_value(result).map_err(ClientError::from)
    }

    /// Low-level: connect, send request, read response.
    async fn send_request(
        &self,
        method: &str,
        params: Value,
        token: &str,
    ) -> Result<JsonRpcResponse, ClientError> {
        // Connect to the socket
        let name = self
            .socket_path
            .clone()
            .to_fs_name::<GenericFilePath>()
            .map_err(|e| ClientError::Connection(format!("invalid socket path: {e}")))?;

        let stream = Stream::connect(name)
            .await
            .map_err(|e| ClientError::Connection(format!("failed to connect: {e}")))?;

        // Split into read/write halves - interprocess's tokio types directly implement tokio's traits
        let (reader, mut writer) = stream.split();

        // Build the request
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id: Value::Number(1.into()),
            meta: RequestMeta {
                authorization: if token.is_empty() {
                    None
                } else {
                    Some(format!("Bearer {}", token))
                },
            },
        };

        // Serialize and send
        let request_json = serde_json::to_string(&request)?;
        writer.write_all(request_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        // Read response line
        let reader = BufReader::new(reader);
        let mut lines = reader.lines();
        let response_line = lines
            .next_line()
            .await?
            .ok_or_else(|| ClientError::Connection("connection closed".to_string()))?;

        // Parse response
        let response: JsonRpcResponse = serde_json::from_str(&response_line)?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_default() {
        let client = RpcClient::new();
        assert!(client.auth_token.is_empty());
        assert_eq!(client.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_client_with_token() {
        let client = RpcClient::new().with_token("test_token");
        assert_eq!(client.auth_token, "test_token");
    }

    #[test]
    fn test_client_with_path() {
        let client = RpcClient::with_path("/tmp/test.sock");
        assert_eq!(client.socket_path, PathBuf::from("/tmp/test.sock"));
    }

    #[test]
    fn test_client_with_timeout() {
        let client = RpcClient::new().with_timeout(Duration::from_secs(10));
        assert_eq!(client.timeout, Duration::from_secs(10));
    }
}
