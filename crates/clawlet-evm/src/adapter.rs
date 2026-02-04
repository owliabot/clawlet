//! Chain adapter implementation.
//!
//! Connects to an EVM-compatible JSON-RPC endpoint and provides
//! high-level methods for balance queries and transaction submission.

use alloy::network::Ethereum;
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::sol_types::SolCall;
use thiserror::Error;

use crate::abi::IERC20;

/// Information about an ERC-20 token.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenInfo {
    /// Token name (e.g., "USD Coin").
    pub name: String,
    /// Token symbol (e.g., "USDC").
    pub symbol: String,
    /// Number of decimals.
    pub decimals: u8,
}

/// Errors from EVM adapter operations.
#[derive(Debug, Error)]
pub enum EvmAdapterError {
    #[error("RPC error: {0}")]
    Rpc(String),
    #[error("URL parse error: {0}")]
    UrlParse(String),
    #[error("ABI decode error: {0}")]
    AbiDecode(String),
}

/// Result alias for adapter operations.
pub type Result<T> = std::result::Result<T, EvmAdapterError>;

/// An EVM chain adapter connected to a specific RPC endpoint.
pub struct EvmAdapter {
    provider: DynProvider<Ethereum>,
    rpc_url: String,
}

impl std::fmt::Debug for EvmAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvmAdapter")
            .field("rpc_url", &self.rpc_url)
            .finish()
    }
}

impl EvmAdapter {
    /// Creates a new adapter for the given RPC URL.
    pub fn new(rpc_url: &str) -> Result<Self> {
        let url: alloy::transports::http::reqwest::Url = rpc_url
            .parse()
            .map_err(|e| EvmAdapterError::UrlParse(format!("{e}")))?;

        let provider = ProviderBuilder::new().connect_http(url).erased();

        Ok(Self {
            provider,
            rpc_url: rpc_url.to_string(),
        })
    }

    /// Returns a reference to the underlying provider.
    pub fn provider(&self) -> &DynProvider<Ethereum> {
        &self.provider
    }

    /// Returns the RPC URL.
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// Queries the native (ETH) balance for an address.
    pub async fn get_eth_balance(&self, address: Address) -> Result<U256> {
        self.provider
            .get_balance(address)
            .await
            .map_err(|e| EvmAdapterError::Rpc(e.to_string()))
    }

    /// Queries the ERC-20 token balance for an owner address.
    pub async fn get_erc20_balance(&self, token_address: Address, owner: Address) -> Result<U256> {
        let call = IERC20::balanceOfCall { owner };
        let data = call.abi_encode();

        let result: Bytes = self
            .provider
            .call(
                TransactionRequest::default()
                    .to(token_address)
                    .input(data.into()),
            )
            .await
            .map_err(|e| EvmAdapterError::Rpc(e.to_string()))?;

        let decoded = <IERC20::balanceOfCall as SolCall>::abi_decode_returns(&result)
            .map_err(|e| EvmAdapterError::AbiDecode(e.to_string()))?;

        Ok(decoded)
    }

    /// Gets ERC-20 token metadata (name, symbol, decimals).
    pub async fn get_erc20_info(&self, token_address: Address) -> Result<TokenInfo> {
        // Fetch name
        let name_data = IERC20::nameCall {}.abi_encode();
        let name_result: Bytes = self
            .provider
            .call(
                TransactionRequest::default()
                    .to(token_address)
                    .input(name_data.into()),
            )
            .await
            .map_err(|e| EvmAdapterError::Rpc(e.to_string()))?;
        let name: String = <IERC20::nameCall as SolCall>::abi_decode_returns(&name_result)
            .map_err(|e| EvmAdapterError::AbiDecode(e.to_string()))?;

        // Fetch symbol
        let symbol_data = IERC20::symbolCall {}.abi_encode();
        let symbol_result: Bytes = self
            .provider
            .call(
                TransactionRequest::default()
                    .to(token_address)
                    .input(symbol_data.into()),
            )
            .await
            .map_err(|e| EvmAdapterError::Rpc(e.to_string()))?;
        let symbol: String = <IERC20::symbolCall as SolCall>::abi_decode_returns(&symbol_result)
            .map_err(|e| EvmAdapterError::AbiDecode(e.to_string()))?;

        // Fetch decimals
        let decimals_data = IERC20::decimalsCall {}.abi_encode();
        let decimals_result: Bytes = self
            .provider
            .call(
                TransactionRequest::default()
                    .to(token_address)
                    .input(decimals_data.into()),
            )
            .await
            .map_err(|e| EvmAdapterError::Rpc(e.to_string()))?;
        let decimals: u8 = <IERC20::decimalsCall as SolCall>::abi_decode_returns(&decimals_result)
            .map_err(|e| EvmAdapterError::AbiDecode(e.to_string()))?;

        Ok(TokenInfo {
            name,
            symbol,
            decimals,
        })
    }

    /// Gets the chain ID from the connected node.
    pub async fn get_chain_id(&self) -> Result<u64> {
        self.provider
            .get_chain_id()
            .await
            .map_err(|e| EvmAdapterError::Rpc(e.to_string()))
    }
}

/// Convert a `clawlet_core::types::Address` to an alloy `Address`.
pub fn core_address_to_alloy(addr: &clawlet_core::types::Address) -> Address {
    Address::from(addr.0)
}

/// Convert an alloy `Address` to a `clawlet_core::types::Address`.
pub fn alloy_address_to_core(addr: &Address) -> clawlet_core::types::Address {
    clawlet_core::types::Address(addr.0 .0)
}

/// Convert an alloy `B256` to a `clawlet_core::types::TxHash`.
pub fn alloy_b256_to_tx_hash(hash: &alloy::primitives::B256) -> clawlet_core::types::TxHash {
    clawlet_core::types::TxHash(hash.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_address_roundtrip() {
        let core_addr = clawlet_core::types::Address([0xab; 20]);
        let alloy_addr = core_address_to_alloy(&core_addr);
        let back = alloy_address_to_core(&alloy_addr);
        assert_eq!(core_addr, back);
    }

    #[test]
    fn adapter_debug_display() {
        let adapter = EvmAdapter::new("http://localhost:8545").unwrap();
        let debug = format!("{adapter:?}");
        assert!(debug.contains("localhost:8545"));
    }

    #[test]
    fn invalid_url_returns_error() {
        let result = EvmAdapter::new("not a valid url");
        assert!(result.is_err());
    }

    #[test]
    fn token_info_serde() {
        let info = TokenInfo {
            name: "USD Coin".into(),
            symbol: "USDC".into(),
            decimals: 6,
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: TokenInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "USD Coin");
        assert_eq!(parsed.symbol, "USDC");
        assert_eq!(parsed.decimals, 6);
    }
}
