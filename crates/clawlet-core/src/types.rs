//! Common types shared across Clawlet crates.

/// Represents a token amount with decimals.
#[derive(Debug, Clone)]
pub struct TokenAmount {
    /// Raw amount as a string to avoid precision loss.
    pub raw: String,
    /// Number of decimals for this token.
    pub decimals: u8,
}

/// A 20-byte EVM address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address(pub [u8; 20]);
