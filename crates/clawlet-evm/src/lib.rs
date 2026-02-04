//! # clawlet-evm
//!
//! EVM chain adapter — balance queries, transaction building, and broadcasting.
//!
//! ## Modules
//!
//! - [`abi`] — ERC-20 ABI definitions using alloy's `sol!` macro
//! - [`adapter`] — JSON-RPC adapter for querying chain state
//! - [`tx`] — Transaction building and broadcasting

pub mod abi;
pub mod adapter;
pub mod tx;

// Re-export key types for convenience.
pub use adapter::{EvmAdapter, EvmAdapterError, TokenInfo};
pub use tx::{TransferRequest, TxError};

// Re-export alloy primitives used in the public API.
pub use alloy::primitives::{Address, U256};
