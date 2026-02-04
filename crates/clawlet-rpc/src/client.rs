//! Client-side helper for connecting to the clawlet-rpc iceoryx2 service.
//!
//! Provides a typed API that serializes requests into the IPC envelope format
//! and deserializes responses.

use std::time::{Duration, Instant};

use iceoryx2::prelude::*;

use crate::handlers::{
    BalanceQuery, BalanceResponse, ExecuteRequest, ExecuteResponse, SkillsResponse,
    TransferRequest, TransferResponse,
};
use crate::server::SERVICE_NAME;
use crate::types::{RpcMethod, RpcRequest, RpcResponse, RpcStatus};

/// Default timeout for waiting on a response.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Polling interval while waiting for a response.
const POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Error type for RPC client operations.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("iceoryx2 error: {0}")]
    Ipc(String),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("timeout waiting for response")]
    Timeout,
    #[error("server returned unauthorized")]
    Unauthorized,
    #[error("server error ({status}): {message}")]
    Server { status: u32, message: String },
}

/// Client for the clawlet-rpc iceoryx2 service.
pub struct RpcClient {
    /// Auth token to include in every request.
    auth_token: String,
    /// Timeout for waiting on responses.
    timeout: Duration,
}

impl RpcClient {
    /// Create a new client with the given auth token.
    pub fn new(auth_token: impl Into<String>) -> Self {
        Self {
            auth_token: auth_token.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Set the response timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Perform a health check.
    pub fn health(&self) -> Result<serde_json::Value, ClientError> {
        let resp = self.call(RpcMethod::Health, &())?;
        let value: serde_json::Value = serde_json::from_slice(resp.payload_bytes())?;
        Ok(value)
    }

    /// Query ETH balance.
    pub fn balance(&self, query: BalanceQuery) -> Result<BalanceResponse, ClientError> {
        let resp = self.call(RpcMethod::Balance, &query)?;
        let result: BalanceResponse = serde_json::from_slice(resp.payload_bytes())?;
        Ok(result)
    }

    /// Execute a transfer.
    pub fn transfer(&self, req: TransferRequest) -> Result<TransferResponse, ClientError> {
        let resp = self.call(RpcMethod::Transfer, &req)?;
        let result: TransferResponse = serde_json::from_slice(resp.payload_bytes())?;
        Ok(result)
    }

    /// List available skills.
    pub fn skills(&self) -> Result<SkillsResponse, ClientError> {
        let resp = self.call(RpcMethod::Skills, &())?;
        let result: SkillsResponse = serde_json::from_slice(resp.payload_bytes())?;
        Ok(result)
    }

    /// Execute a skill.
    pub fn execute(&self, req: ExecuteRequest) -> Result<ExecuteResponse, ClientError> {
        let resp = self.call(RpcMethod::Execute, &req)?;
        let result: ExecuteResponse = serde_json::from_slice(resp.payload_bytes())?;
        Ok(result)
    }

    /// Low-level: serialize, send, wait for response, check status.
    fn call<T: serde::Serialize>(
        &self,
        method: RpcMethod,
        payload: &T,
    ) -> Result<RpcResponse, ClientError> {
        let node = NodeBuilder::new()
            .create::<ipc::Service>()
            .map_err(|e| ClientError::Ipc(format!("failed to create node: {e:?}")))?;

        let service = node
            .service_builder(
                &SERVICE_NAME
                    .try_into()
                    .map_err(|e| ClientError::Ipc(format!("invalid service name: {e:?}")))?,
            )
            .request_response::<RpcRequest, RpcResponse>()
            .open()
            .map_err(|e| ClientError::Ipc(format!("failed to open service: {e:?}")))?;

        let client = service
            .client_builder()
            .create()
            .map_err(|e| ClientError::Ipc(format!("failed to create client: {e:?}")))?;

        // Serialize the payload to JSON
        let json_bytes = serde_json::to_vec(payload)?;

        // Build the envelope
        let envelope = RpcRequest::new(method, &self.auth_token, &json_bytes);

        // Send using copy API for simplicity
        let pending = client
            .send_copy(envelope)
            .map_err(|e| ClientError::Ipc(format!("send failed: {e:?}")))?;

        // Poll for response with timeout
        let deadline = Instant::now() + self.timeout;
        loop {
            if let Some(response) = pending
                .receive()
                .map_err(|e| ClientError::Ipc(format!("receive failed: {e:?}")))?
            {
                // Copy the response out before the sample is dropped
                let result = RpcResponse {
                    status: response.status,
                    payload_len: response.payload_len,
                    payload: response.payload,
                };

                // Check status
                if result.status == RpcStatus::Unauthorized as u32 {
                    return Err(ClientError::Unauthorized);
                }
                if !result.is_ok() {
                    let msg = String::from_utf8_lossy(result.payload_bytes()).to_string();
                    return Err(ClientError::Server {
                        status: result.status,
                        message: msg,
                    });
                }

                return Ok(result);
            }

            if Instant::now() >= deadline {
                return Err(ClientError::Timeout);
            }

            std::thread::sleep(POLL_INTERVAL);
        }
    }
}
