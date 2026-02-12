//! Solana chain adapter implementation.
//!
//! Connects to a Solana RPC endpoint and provides high-level methods
//! for balance queries, token info, and transaction submission.

use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_sdk::transaction::Transaction;
use spl_associated_token_account::get_associated_token_address;
use thiserror::Error;

/// Information about an SPL token mint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenInfo {
    /// Mint address.
    pub mint: String,
    /// Number of decimals.
    pub decimals: u8,
    /// Token supply (raw).
    pub supply: u64,
}

/// Errors from Solana adapter operations.
#[derive(Debug, Error)]
pub enum SolanaAdapterError {
    #[error("RPC error: {0}")]
    Rpc(String),
    #[error("Invalid pubkey: {0}")]
    InvalidPubkey(String),
    #[error("Account not found")]
    AccountNotFound,
    #[error("Token account not found")]
    TokenAccountNotFound,
}

/// Result alias for adapter operations.
pub type Result<T> = std::result::Result<T, SolanaAdapterError>;

/// A Solana chain adapter connected to a specific RPC endpoint.
pub struct SolanaAdapter {
    client: RpcClient,
    rpc_url: String,
}

impl std::fmt::Debug for SolanaAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SolanaAdapter")
            .field("rpc_url", &self.rpc_url)
            .finish()
    }
}

impl SolanaAdapter {
    /// Creates a new adapter for the given RPC URL.
    pub fn new(rpc_url: &str) -> Result<Self> {
        let client =
            RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
        Ok(Self {
            client,
            rpc_url: rpc_url.to_string(),
        })
    }

    /// Returns the RPC URL.
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// Returns a reference to the underlying RPC client.
    pub fn client(&self) -> &RpcClient {
        &self.client
    }

    /// Queries the SOL balance for a pubkey, in lamports.
    pub async fn get_sol_balance(&self, pubkey: &Pubkey) -> Result<u64> {
        self.client
            .get_balance(pubkey)
            .map_err(|e| SolanaAdapterError::Rpc(e.to_string()))
    }

    /// Queries the SPL token balance for an owner + mint.
    pub async fn get_spl_token_balance(&self, owner: &Pubkey, mint: &Pubkey) -> Result<u64> {
        let ata = get_associated_token_address(owner, mint);
        let balance = self
            .client
            .get_token_account_balance(&ata)
            .map_err(|e| SolanaAdapterError::Rpc(e.to_string()))?;
        let amount: u64 = balance
            .amount
            .parse()
            .map_err(|e: std::num::ParseIntError| SolanaAdapterError::Rpc(e.to_string()))?;
        Ok(amount)
    }

    /// Gets SPL token mint info (decimals, supply).
    pub async fn get_token_info(&self, mint: &Pubkey) -> Result<TokenInfo> {
        let account = self
            .client
            .get_account(mint)
            .map_err(|e| SolanaAdapterError::Rpc(e.to_string()))?;

        // SPL token mint layout: decimals at offset 44 (1 byte), supply at offset 36 (8 bytes LE)
        let data = &account.data;
        if data.len() < 82 {
            return Err(SolanaAdapterError::AccountNotFound);
        }

        let supply = u64::from_le_bytes(
            data[36..44]
                .try_into()
                .map_err(|_| SolanaAdapterError::AccountNotFound)?,
        );
        let decimals = data[44];

        Ok(TokenInfo {
            mint: mint.to_string(),
            decimals,
            supply,
        })
    }

    /// Sends a signed transaction and returns the signature.
    pub async fn send_transaction(&self, tx: &Transaction) -> Result<Signature> {
        self.client
            .send_and_confirm_transaction(tx)
            .map_err(|e| SolanaAdapterError::Rpc(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_debug_display() {
        let adapter = SolanaAdapter::new("https://api.devnet.solana.com").unwrap();
        let debug = format!("{adapter:?}");
        assert!(debug.contains("devnet.solana.com"));
    }

    #[test]
    fn token_info_serde() {
        let info = TokenInfo {
            mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
            decimals: 6,
            supply: 1_000_000_000,
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: TokenInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.decimals, 6);
        assert_eq!(parsed.supply, 1_000_000_000);
    }
}
