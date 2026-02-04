//! Chain adapter implementation.
//!
//! Connects to an EVM-compatible JSON-RPC endpoint and provides
//! high-level methods for balance queries and transaction submission.

/// An EVM chain adapter connected to a specific RPC endpoint.
#[derive(Debug)]
pub struct EvmAdapter {
    /// The JSON-RPC endpoint URL.
    pub rpc_url: String,
    /// Chain ID.
    pub chain_id: u64,
}

impl EvmAdapter {
    /// Creates a new adapter for the given RPC URL.
    pub fn new(rpc_url: String, chain_id: u64) -> Self {
        Self { rpc_url, chain_id }
    }

    /// Queries the native (ETH) balance for an address.
    ///
    /// # Panics
    /// Not yet implemented.
    pub fn get_balance(&self, _address: &clawlet_core::types::Address) -> clawlet_core::types::TokenAmount {
        todo!("M1-5: implement ETH balance query")
    }
}
