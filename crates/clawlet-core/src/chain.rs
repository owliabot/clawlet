//! Supported chain identifiers.
//!
//! Only chains with verified UniswapV3 SwapRouter deployments are included.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Chains supported by clawlet for swap operations.
///
/// Each variant carries its well-known numeric chain ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub enum SupportedChainId {
    /// Ethereum mainnet
    Ethereum = 1,
    /// Optimism
    Optimism = 10,
    /// BNB Chain
    Bnb = 56,
    /// Polygon
    Polygon = 137,
    /// Base
    Base = 8453,
    /// Arbitrum
    Arbitrum = 42161,
}

impl SupportedChainId {
    /// All supported chain IDs.
    pub const ALL: [SupportedChainId; 6] = [
        Self::Ethereum,
        Self::Optimism,
        Self::Bnb,
        Self::Polygon,
        Self::Base,
        Self::Arbitrum,
    ];

    /// Returns the numeric chain ID.
    pub const fn as_u64(self) -> u64 {
        self as u64
    }

    /// Human-readable chain name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ethereum => "Ethereum",
            Self::Optimism => "Optimism",
            Self::Bnb => "BNB Chain",
            Self::Polygon => "Polygon",
            Self::Base => "Base",
            Self::Arbitrum => "Arbitrum",
        }
    }

    /// Whether this is a testnet (none of the supported chains are).
    pub const fn is_testnet(self) -> bool {
        false
    }
}

impl TryFrom<u64> for SupportedChainId {
    type Error = UnsupportedChainError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Ethereum),
            10 => Ok(Self::Optimism),
            56 => Ok(Self::Bnb),
            137 => Ok(Self::Polygon),
            8453 => Ok(Self::Base),
            42161 => Ok(Self::Arbitrum),
            _ => Err(UnsupportedChainError(value)),
        }
    }
}

impl From<SupportedChainId> for u64 {
    fn from(chain: SupportedChainId) -> u64 {
        chain.as_u64()
    }
}

impl fmt::Display for SupportedChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.as_u64())
    }
}

/// Error when a chain ID is not in the supported set.
#[derive(Debug, Clone)]
pub struct UnsupportedChainError(pub u64);

impl fmt::Display for UnsupportedChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unsupported chain_id {}; supported chains: {}",
            self.0,
            SupportedChainId::ALL
                .iter()
                .map(|c| format!("{} ({})", c.as_u64(), c.name()))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

impl std::error::Error for UnsupportedChainError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_chains() {
        for chain in SupportedChainId::ALL {
            let id = chain.as_u64();
            let back = SupportedChainId::try_from(id).unwrap();
            assert_eq!(chain, back);
        }
    }

    #[test]
    fn unknown_chain_rejected() {
        assert!(SupportedChainId::try_from(999u64).is_err());
        assert!(SupportedChainId::try_from(43114u64).is_err()); // Avalanche
        assert!(SupportedChainId::try_from(0u64).is_err());
    }

    #[test]
    fn display_includes_name_and_id() {
        let s = format!("{}", SupportedChainId::Ethereum);
        assert!(s.contains("Ethereum"));
        assert!(s.contains("1"));
    }

    #[test]
    fn error_message_lists_supported() {
        let err = UnsupportedChainError(999);
        let msg = err.to_string();
        assert!(msg.contains("999"));
        assert!(msg.contains("Ethereum"));
        assert!(msg.contains("Base"));
    }

    #[test]
    fn serde_roundtrip() {
        let chain = SupportedChainId::Base;
        let json = serde_json::to_string(&chain).unwrap();
        assert_eq!(json, "8453");
        let back: SupportedChainId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, chain);
    }

    #[test]
    fn serde_invalid_rejected() {
        let result = serde_json::from_str::<SupportedChainId>("999");
        assert!(result.is_err());
    }
}
