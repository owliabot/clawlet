//! HTTP client for connecting to the clawlet-ipc HTTP JSON-RPC server.
//!
//! Provides a typed API that serializes requests to JSON-RPC format
//! and deserializes responses.

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

use crate::handlers::{
    BalanceQuery, BalanceResponse, ExecuteRequest, ExecuteResponse, SkillsResponse,
    TransferRequest, TransferResponse,
};
use crate::server::{JsonRpcRequest, JsonRpcResponse, DEFAULT_ADDR};

/// Error type for RPC client operations.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("connection error: {0}")]
    Connection(String),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("timeout waiting for response")]
    Timeout,
    #[error("server returned error: {message} (code {code})")]
    Server { code: i32, message: String },
}

/// Client for the clawlet-ipc HTTP JSON-RPC server.
pub struct RpcClient {
    /// Base URL of the server.
    base_url: String,
    /// Auth token to include in every request.
    auth_token: String,
    /// HTTP client.
    client: reqwest::Client,
}

impl Default for RpcClient {
    fn default() -> Self {
        Self {
            base_url: format!("http://{}", DEFAULT_ADDR),
            auth_token: String::new(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("failed to build HTTP client"),
        }
    }
}

impl RpcClient {
    /// Create a new client connecting to the default address.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new client connecting to a specific address.
    pub fn with_addr(addr: &str) -> Self {
        Self {
            base_url: format!("http://{}", addr),
            ..Default::default()
        }
    }

    /// Create a new client with a full URL (including scheme).
    pub fn with_url(url: impl Into<String>) -> Self {
        Self {
            base_url: url.into(),
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
        self.client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("failed to build HTTP client");
        self
    }

    /// Get the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Perform a health check.
    pub async fn health(&self) -> Result<serde_json::Value, ClientError> {
        self.call("health", serde_json::json!({})).await
    }

    /// Query wallet address.
    pub async fn address(&self) -> Result<serde_json::Value, ClientError> {
        self.call("address", serde_json::json!({})).await
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

    /// Low-level: send HTTP request.
    async fn send_request(
        &self,
        method: &str,
        params: Value,
        token: &str,
    ) -> Result<JsonRpcResponse, ClientError> {
        // Build the request
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id: Value::Number(1.into()),
        };

        // Build headers
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if !token.is_empty() {
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", token))
                    .map_err(|e| ClientError::Connection(e.to_string()))?,
            );
        }

        // Send the request
        let url = format!("{}/rpc", self.base_url);
        let response = self
            .client
            .post(&url)
            .headers(headers)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    ClientError::Timeout
                } else if e.is_connect() {
                    ClientError::Connection(e.to_string())
                } else {
                    ClientError::Http(e)
                }
            })?;

        // Parse response
        let response: JsonRpcResponse = response.json().await?;
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
        assert_eq!(client.base_url, format!("http://{}", DEFAULT_ADDR));
    }

    #[test]
    fn test_client_with_token() {
        let client = RpcClient::new().with_token("test_token");
        assert_eq!(client.auth_token, "test_token");
    }

    #[test]
    fn test_client_with_addr() {
        let client = RpcClient::with_addr("192.168.1.1:8080");
        assert_eq!(client.base_url, "http://192.168.1.1:8080");
    }

    #[test]
    fn test_client_with_url() {
        let client = RpcClient::with_url("https://wallet.example.com");
        assert_eq!(client.base_url, "https://wallet.example.com");
    }

    #[test]
    fn test_client_with_timeout() {
        let client = RpcClient::new().with_timeout(Duration::from_secs(10));
        // Just ensure it doesn't panic
        assert!(client.auth_token.is_empty());
    }
}
