//! OKX DEX Aggregator API client.
//!
//! Implements signed requests to the OKX DEX Aggregator v5 API
//! for token swap quotes and transaction data.

use base64::Engine;
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

/// ETH native token address used by OKX DEX API.
pub const ETH_NATIVE_ADDRESS: &str = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";

/// OKX API base URL.
const OKX_BASE_URL: &str = "https://www.okx.com";

/// Errors from OKX DEX operations.
#[derive(Debug, Error)]
pub enum OkxError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("API error: code={code}, msg={msg}")]
    Api { code: String, msg: String },
    #[error("no route data returned")]
    NoRouteData,
    #[error("HMAC error")]
    Hmac,
}

/// OKX DEX API client with signed request support.
#[derive(Clone)]
pub struct OkxDexClient {
    api_key: String,
    secret_key: String,
    passphrase: String,
    project_id: String,
    client: Client,
}

/// Parameters for a swap quote/transaction request.
#[derive(Debug, Serialize)]
pub struct SwapParams {
    /// Chain ID (e.g., "1" for Ethereum mainnet).
    pub chain_id: String,
    /// Source token address.
    pub from_token_address: String,
    /// Destination token address.
    pub to_token_address: String,
    /// Amount in smallest units (wei for ETH).
    pub amount: String,
    /// Slippage tolerance (e.g., "0.5" for 0.5%).
    pub slippage: String,
    /// User wallet address (for swap transaction).
    pub user_wallet_address: String,
}

/// Top-level OKX API response envelope.
#[derive(Debug, Deserialize)]
pub struct OkxResponse<T> {
    pub code: String,
    #[serde(default)]
    pub msg: String,
    pub data: Option<Vec<T>>,
}

/// Swap transaction data returned by the OKX DEX API.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SwapData {
    /// Router result with amounts.
    pub router_result: RouterResult,
    /// Transaction data to sign and broadcast.
    pub tx: Option<SwapTx>,
}

/// Router result containing swap amounts.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouterResult {
    /// Amount of source token (in smallest units).
    pub from_token_amount: String,
    /// Amount of destination token (in smallest units).
    pub to_token_amount: String,
}

/// Transaction data for the swap.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SwapTx {
    /// Contract address to call.
    pub to: String,
    /// Calldata.
    pub data: String,
    /// Value in wei (for native token swaps).
    pub value: String,
    /// Gas limit.
    pub gas_limit: String,
}

impl OkxDexClient {
    /// Create a new OKX DEX client.
    pub fn new(
        api_key: String,
        secret_key: String,
        passphrase: String,
        project_id: String,
    ) -> Self {
        Self {
            api_key,
            secret_key,
            passphrase,
            project_id,
            client: Client::new(),
        }
    }

    /// Generate the HMAC-SHA256 signature for OKX API authentication.
    fn sign(&self, timestamp: &str, method: &str, request_path: &str) -> Result<String, OkxError> {
        let prehash = format!("{timestamp}{method}{request_path}");
        let mut mac = Hmac::<Sha256>::new_from_slice(self.secret_key.as_bytes())
            .map_err(|_| OkxError::Hmac)?;
        mac.update(prehash.as_bytes());
        let result = mac.finalize();
        Ok(base64::engine::general_purpose::STANDARD.encode(result.into_bytes()))
    }

    /// Get the current ISO 8601 timestamp.
    fn timestamp() -> String {
        chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string()
    }

    /// Get swap transaction data from the OKX DEX aggregator.
    ///
    /// This calls the `/api/v5/dex/aggregator/swap` endpoint which returns
    /// both the quote and the transaction data to execute.
    pub async fn get_swap(&self, params: &SwapParams) -> Result<SwapData, OkxError> {
        let query = format!(
            "chainId={}&fromTokenAddress={}&toTokenAddress={}&amount={}&slippage={}&userWalletAddress={}",
            params.chain_id,
            params.from_token_address,
            params.to_token_address,
            params.amount,
            params.slippage,
            params.user_wallet_address,
        );
        let request_path = format!("/api/v5/dex/aggregator/swap?{query}");
        let timestamp = Self::timestamp();
        let signature = self.sign(&timestamp, "GET", &request_path)?;

        let url = format!("{OKX_BASE_URL}{request_path}");
        let resp = self
            .client
            .get(&url)
            .header("OK-ACCESS-KEY", &self.api_key)
            .header("OK-ACCESS-SIGN", &signature)
            .header("OK-ACCESS-TIMESTAMP", &timestamp)
            .header("OK-ACCESS-PASSPHRASE", &self.passphrase)
            .header("OK-ACCESS-PROJECT", &self.project_id)
            .send()
            .await?
            .json::<OkxResponse<SwapData>>()
            .await?;

        if resp.code != "0" {
            return Err(OkxError::Api {
                code: resp.code,
                msg: resp.msg,
            });
        }

        resp.data
            .and_then(|mut v| {
                if v.is_empty() {
                    None
                } else {
                    Some(v.remove(0))
                }
            })
            .ok_or(OkxError::NoRouteData)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_produces_base64() {
        let client = OkxDexClient::new("key".into(), "secret".into(), "pass".into(), "proj".into());
        let sig = client
            .sign("2024-01-01T00:00:00.000Z", "GET", "/api/v5/test")
            .unwrap();
        // Should be valid base64
        assert!(base64::engine::general_purpose::STANDARD
            .decode(&sig)
            .is_ok());
    }

    #[test]
    fn eth_native_address_constant() {
        assert_eq!(
            ETH_NATIVE_ADDRESS,
            "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"
        );
    }
}
