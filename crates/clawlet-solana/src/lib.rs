//! # clawlet-solana
//!
//! Solana chain adapter — balance queries, transaction building, and broadcasting.
//!
//! ## Modules
//!
//! - [`adapter`] — RPC adapter for querying Solana chain state
//! - [`tx`] — Transaction building for SOL and SPL token transfers
//! - [`signer`] — Solana Ed25519 signer with HD derivation support

pub mod adapter;
pub mod signer;
pub mod tx;

// Re-export key types for convenience.
pub use adapter::{SolanaAdapter, SolanaAdapterError, TokenInfo};
pub use signer::SolanaSigner;
pub use solana_sdk::pubkey::Pubkey;
pub use solana_sdk::signature::Signature;
