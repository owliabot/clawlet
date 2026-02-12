//! HTTP client for connecting to the clawlet-rpc HTTP JSON-RPC server.
//!
//! Provides a typed API using jsonrpsee client.
//!
//! Authentication is sent via the `Authorization: Bearer <token>` HTTP header.

use std::collections::HashMap;
use std::time::Duration;

use http::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::server::DEFAULT_ADDR;
use crate::types::{
    BalanceResponse, ChainsResponse, ExecuteResponse, SendRawResponse, SkillsResponse,
    TransferResponse,
};

/// Error type for RPC client operations.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("connection error: {0}")]
    Connection(String),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("RPC error: {0}")]
    Rpc(#[from] jsonrpsee::core::ClientError),
    #[error("timeout waiting for response")]
    Timeout,
    #[error("server returned error: {message} (code {code})")]
    Server { code: i32, message: String },
}

/// Balance query parameters.
#[derive(Debug, Serialize, Deserialize)]
pub struct BalanceQuery {
    /// The EVM address to query.
    pub address: String,
    /// The chain ID to query against.
    pub chain_id: u64,
}

/// Transfer request parameters.
#[derive(Debug, Serialize, Deserialize)]
pub struct TransferRequest {
    /// Recipient address.
    pub to: String,
    /// Amount as a decimal string.
    pub amount: String,
    /// Token to transfer ("ETH" or contract address).
    pub token_type: String,
    /// Chain ID.
    pub chain_id: u64,
}

/// Skills request parameters (empty - auth via header).
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SkillsRequest {}

/// Execute request parameters.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecuteRequest {
    /// Skill name.
    pub skill: String,
    /// Parameter values.
    #[serde(default)]
    pub params: HashMap<String, String>,
}

/// Client for the clawlet-rpc HTTP JSON-RPC server.
pub struct RpcClient {
    /// Base URL of the server.
    base_url: String,
    /// Auth token to include in Authorization header.
    auth_token: String,
    /// Request timeout.
    timeout: Duration,
}

impl Default for RpcClient {
    fn default() -> Self {
        Self {
            base_url: format!("http://{}", DEFAULT_ADDR),
            auth_token: String::new(),
            timeout: Duration::from_secs(30),
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

    /// Set the auth token for all requests (sent via Authorization header).
    pub fn with_token(mut self, auth_token: impl Into<String>) -> Self {
        self.auth_token = auth_token.into();
        self
    }

    /// Set the timeout for operations.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Get the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Build the HTTP client with Authorization header if token is set.
    fn build_client(&self) -> Result<HttpClient, ClientError> {
        let mut builder = HttpClientBuilder::default().request_timeout(self.timeout);

        // Add Authorization header if token is set
        if !self.auth_token.is_empty() {
            let mut headers = HeaderMap::new();
            let auth_value = format!("Bearer {}", self.auth_token);
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&auth_value)
                    .map_err(|e| ClientError::Connection(e.to_string()))?,
            );
            builder = builder.set_headers(headers);
        }

        builder
            .build(&self.base_url)
            .map_err(|e| ClientError::Connection(e.to_string()))
    }

    /// Perform a health check.
    pub async fn health(&self) -> Result<Value, ClientError> {
        let client = self.build_client()?;
        let result: Value = client.request("health", rpc_params![]).await?;
        Ok(result)
    }

    /// List supported chains.
    pub async fn chains(&self) -> Result<ChainsResponse, ClientError> {
        let client = self.build_client()?;
        let result: ChainsResponse = client.request("chains", rpc_params![]).await?;
        Ok(result)
    }

    /// Query wallet address.
    pub async fn address(&self) -> Result<Value, ClientError> {
        let client = self.build_client()?;
        let result: Value = client.request("address", rpc_params![]).await?;
        Ok(result)
    }

    /// Query ETH balance.
    pub async fn balance(
        &self,
        address: &str,
        chain_id: u64,
    ) -> Result<BalanceResponse, ClientError> {
        let client = self.build_client()?;
        let query = BalanceQuery {
            address: address.to_string(),
            chain_id,
        };
        let result: BalanceResponse = client.request("balance", rpc_params![query]).await?;
        Ok(result)
    }

    /// Execute a transfer.
    pub async fn transfer(
        &self,
        to: &str,
        amount: &str,
        token_type: &str,
        chain_id: u64,
    ) -> Result<TransferResponse, ClientError> {
        let client = self.build_client()?;
        let req = TransferRequest {
            to: to.to_string(),
            amount: amount.to_string(),
            token_type: token_type.to_string(),
            chain_id,
        };
        let result: TransferResponse = client.request("transfer", rpc_params![req]).await?;
        Ok(result)
    }

    /// List available skills.
    pub async fn skills(&self) -> Result<SkillsResponse, ClientError> {
        let client = self.build_client()?;
        let req = SkillsRequest::default();
        let result: SkillsResponse = client.request("skills", rpc_params![req]).await?;
        Ok(result)
    }

    /// Execute a skill.
    pub async fn execute(
        &self,
        skill: &str,
        params: HashMap<String, String>,
    ) -> Result<ExecuteResponse, ClientError> {
        let client = self.build_client()?;
        let req = ExecuteRequest {
            skill: skill.to_string(),
            params,
        };
        let result: ExecuteResponse = client.request("execute", rpc_params![req]).await?;
        Ok(result)
    }

    /// Send a raw transaction (bypasses policy engine).
    pub async fn send_raw(
        &self,
        to: alloy::primitives::Address,
        value: Option<alloy::primitives::U256>,
        data: Option<alloy::primitives::Bytes>,
        chain_id: u64,
        gas_limit: Option<u64>,
    ) -> Result<SendRawResponse, ClientError> {
        let client = self.build_client()?;
        let req = serde_json::json!({
            "to": to.to_string(),
            "value": value,
            "data": data,
            "chain_id": chain_id,
            "gas_limit": gas_limit,
        });
        let result: SendRawResponse = client.request("send_raw", rpc_params![req]).await?;
        Ok(result)
    }

    /// Sign a message using EIP-191 personal sign.
    ///
    /// `encoding` should be `"utf8"` or `"hex"`. If `None`, defaults to `"utf8"`.
    pub async fn sign_message(
        &self,
        message: &str,
        encoding: Option<&str>,
    ) -> Result<crate::types::SignMessageResponse, ClientError> {
        let client = self.build_client()?;
        let mut req = serde_json::json!({ "message": message });
        if let Some(enc) = encoding {
            req["encoding"] = serde_json::Value::String(enc.to_string());
        }
        let result: crate::types::SignMessageResponse =
            client.request("sign_message", rpc_params![req]).await?;
        Ok(result)
    }

    /// Send a raw JSON-RPC request.
    pub async fn call_raw(&self, method: &str, params: Value) -> Result<Value, ClientError> {
        let client = self.build_client()?;
        // Convert Value to ArrayParams
        let params_array = if params.is_array() {
            params.as_array().unwrap().clone()
        } else if params.is_object() {
            vec![params]
        } else {
            vec![]
        };
        let result: Value = client.request(method, params_array).await?;
        Ok(result)
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
        assert_eq!(client.timeout, Duration::from_secs(10));
    }
}
