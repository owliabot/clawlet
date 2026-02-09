//! Shared IPC message types for JSON-RPC communication.
//!
//! This module provides common types and constants used across the IPC layer,
//! including strongly-typed wrappers for RPC parameters with custom serde
//! deserialization that validates input at the parsing stage.

use std::fmt;
use std::str::FromStr;

use clawlet_core::auth::TokenScope;
use clawlet_evm::Address;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// ---- Strongly-typed RPC parameter wrappers ----

/// A validated EVM address wrapper.
///
/// Deserializes from a `"0x..."`-prefixed 40 hex-char string and validates it
/// as a proper EVM address. Serializes back to checksum format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmAddress(pub Address);

impl EvmAddress {
    /// Get the inner `alloy_primitives::Address`.
    pub fn inner(&self) -> Address {
        self.0
    }
}

impl fmt::Display for EvmAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for EvmAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for EvmAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EvmAddressVisitor;

        impl<'de> Visitor<'de> for EvmAddressVisitor {
            type Value = EvmAddress;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a 0x-prefixed 40 hex char EVM address")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<EvmAddress, E> {
                let v = v.trim();
                if !v.starts_with("0x") && !v.starts_with("0X") {
                    return Err(E::custom(
                        "invalid EVM address: expected 0x-prefixed 40 hex chars",
                    ));
                }
                if v.len() != 42 {
                    return Err(E::custom(
                        "invalid EVM address: expected 0x-prefixed 40 hex chars",
                    ));
                }
                let addr: Address = v.parse().map_err(|_| {
                    E::custom("invalid EVM address: expected 0x-prefixed 40 hex chars")
                })?;
                Ok(EvmAddress(addr))
            }
        }

        deserializer.deserialize_str(EvmAddressVisitor)
    }
}

/// A validated decimal token amount.
///
/// Deserializes from a string, validates it's a non-negative decimal number.
/// Rejects negative numbers, non-numeric strings, and empty strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenAmount(pub String);

impl TokenAmount {
    /// Get the validated amount string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TokenAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validate that a string is a valid non-negative decimal number.
fn validate_decimal(s: &str) -> Result<(), String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty amount".to_string());
    }
    if s.starts_with('-') {
        return Err("negative amounts not allowed".to_string());
    }
    // Must match: digits, optionally followed by one dot and more digits
    let mut saw_dot = false;
    let mut saw_digit = false;
    for c in s.chars() {
        if c == '.' {
            if saw_dot {
                return Err("invalid decimal: multiple decimal points".to_string());
            }
            saw_dot = true;
        } else if c.is_ascii_digit() {
            saw_digit = true;
        } else {
            return Err(format!("invalid decimal: unexpected character '{c}'"));
        }
    }
    if !saw_digit {
        return Err("invalid decimal: no digits".to_string());
    }
    Ok(())
}

impl Serialize for TokenAmount {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TokenAmount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TokenAmountVisitor;

        impl<'de> Visitor<'de> for TokenAmountVisitor {
            type Value = TokenAmount;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a non-negative decimal number string")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<TokenAmount, E> {
                validate_decimal(v).map_err(E::custom)?;
                Ok(TokenAmount(v.trim().to_string()))
            }
        }

        deserializer.deserialize_str(TokenAmountVisitor)
    }
}

/// A chain ID that accepts both number and string in JSON.
///
/// Deserializes from `8453` or `"8453"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainId(pub u64);

impl ChainId {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for ChainId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for ChainId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ChainIdVisitor;

        impl<'de> Visitor<'de> for ChainIdVisitor {
            type Value = ChainId;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a chain ID as number or string")
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<ChainId, E> {
                Ok(ChainId(v))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<ChainId, E> {
                if v < 0 {
                    return Err(E::custom("chain_id must be non-negative"));
                }
                Ok(ChainId(v as u64))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<ChainId, E> {
                let v = v.trim();
                u64::from_str(v)
                    .map(ChainId)
                    .map_err(|_| E::custom(format!("invalid chain_id: '{v}' is not a valid u64")))
            }
        }

        deserializer.deserialize_any(ChainIdVisitor)
    }
}

/// Token specifier: either native ETH or an ERC-20 contract address.
///
/// Deserializes from `"ETH"` (case-insensitive) for native, or a valid
/// `"0x..."`-prefixed address for ERC-20.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSpec {
    /// Native ETH.
    Native,
    /// ERC-20 token by contract address.
    Erc20(EvmAddress),
}

impl fmt::Display for TokenSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenSpec::Native => write!(f, "ETH"),
            TokenSpec::Erc20(addr) => write!(f, "{addr}"),
        }
    }
}

impl Serialize for TokenSpec {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            TokenSpec::Native => serializer.serialize_str("ETH"),
            TokenSpec::Erc20(addr) => addr.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for TokenSpec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TokenSpecVisitor;

        impl<'de> Visitor<'de> for TokenSpecVisitor {
            type Value = TokenSpec;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("\"ETH\" or a 0x-prefixed ERC-20 contract address")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<TokenSpec, E> {
                let v = v.trim();
                if v.eq_ignore_ascii_case("ETH") {
                    return Ok(TokenSpec::Native);
                }
                // Try to parse as address
                let addr: EvmAddress = serde_json::from_value(serde_json::Value::String(v.to_string()))
                    .map_err(|_| E::custom(format!(
                        "invalid token: expected \"ETH\" or a valid 0x-prefixed contract address, got \"{v}\""
                    )))?;
                Ok(TokenSpec::Erc20(addr))
            }
        }

        deserializer.deserialize_str(TokenSpecVisitor)
    }
}

impl TokenSpec {
    /// Returns true if this is native ETH.
    pub fn is_native(&self) -> bool {
        matches!(self, TokenSpec::Native)
    }

    /// Returns the string representation used for policy checks.
    pub fn policy_str(&self) -> String {
        match self {
            TokenSpec::Native => "ETH".to_string(),
            TokenSpec::Erc20(addr) => addr.to_string(),
        }
    }
}

// ---- RPC Method enum (unchanged) ----

/// RPC method discriminant — maps to the endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcMethod {
    Health,
    /// Query wallet address (no auth required).
    Address,
    Balance,
    Transfer,
    Skills,
    Execute,
    /// Grant a new session token (Admin only).
    AuthGrant,
    /// List all active sessions (Admin only).
    AuthList,
    /// Revoke a session by agent ID (Admin only).
    AuthRevoke,
    /// Revoke all sessions (Admin only).
    AuthRevokeAll,
}

impl RpcMethod {
    /// Parse a method name string into an RpcMethod.
    pub fn parse_method(s: &str) -> Option<Self> {
        match s {
            "health" => Some(Self::Health),
            "address" => Some(Self::Address),
            "balance" => Some(Self::Balance),
            "transfer" => Some(Self::Transfer),
            "skills" => Some(Self::Skills),
            "execute" => Some(Self::Execute),
            "auth.grant" => Some(Self::AuthGrant),
            "auth.list" => Some(Self::AuthList),
            "auth.revoke" => Some(Self::AuthRevoke),
            "auth.revoke_all" => Some(Self::AuthRevokeAll),
            _ => None,
        }
    }

    /// Get the method name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Health => "health",
            Self::Address => "address",
            Self::Balance => "balance",
            Self::Transfer => "transfer",
            Self::Skills => "skills",
            Self::Execute => "execute",
            Self::AuthGrant => "auth.grant",
            Self::AuthList => "auth.list",
            Self::AuthRevoke => "auth.revoke",
            Self::AuthRevokeAll => "auth.revoke_all",
        }
    }

    /// Get the required scope for this method (token-based auth).
    ///
    /// Returns `None` for methods that don't require token auth:
    /// - `Health`: public endpoint
    /// - `Address`: public endpoint
    /// - `Auth*`: use password-based auth instead (handled in their handlers)
    pub fn required_scope(&self) -> Option<TokenScope> {
        match self {
            RpcMethod::Health | RpcMethod::Address => None,
            RpcMethod::Balance | RpcMethod::Skills => Some(TokenScope::Read),
            RpcMethod::Transfer | RpcMethod::Execute => Some(TokenScope::Trade),
            RpcMethod::AuthGrant
            | RpcMethod::AuthList
            | RpcMethod::AuthRevoke
            | RpcMethod::AuthRevokeAll => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- EvmAddress tests ----

    #[test]
    fn evm_address_valid() {
        let json = r#""0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2""#;
        let addr: EvmAddress = serde_json::from_str(json).unwrap();
        assert_eq!(
            addr.inner(),
            "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2"
                .parse::<Address>()
                .unwrap()
        );
    }

    #[test]
    fn evm_address_lowercase_valid() {
        let json = r#""0x742d35cc6634c0532925a3b844bc9e7595f5b5e2""#;
        let addr: EvmAddress = serde_json::from_str(json).unwrap();
        assert!(!addr.inner().is_zero());
    }

    #[test]
    fn evm_address_missing_0x() {
        let json = r#""742d35Cc6634C0532925a3b844Bc9e7595f5b5e2""#;
        let result = serde_json::from_str::<EvmAddress>(json);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid EVM address"));
    }

    #[test]
    fn evm_address_too_short() {
        let json = r#""0x742d35""#;
        let result = serde_json::from_str::<EvmAddress>(json);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid EVM address"));
    }

    #[test]
    fn evm_address_not_hex() {
        let json = r#""0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ""#;
        let result = serde_json::from_str::<EvmAddress>(json);
        assert!(result.is_err());
    }

    #[test]
    fn evm_address_roundtrip() {
        let json = r#""0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2""#;
        let addr: EvmAddress = serde_json::from_str(json).unwrap();
        let serialized = serde_json::to_string(&addr).unwrap();
        // Re-parse to verify roundtrip
        let addr2: EvmAddress = serde_json::from_str(&serialized).unwrap();
        assert_eq!(addr, addr2);
    }

    // ---- TokenAmount tests ----

    #[test]
    fn token_amount_integer() {
        let json = r#""100""#;
        let amt: TokenAmount = serde_json::from_str(json).unwrap();
        assert_eq!(amt.as_str(), "100");
    }

    #[test]
    fn token_amount_decimal() {
        let json = r#""1.5""#;
        let amt: TokenAmount = serde_json::from_str(json).unwrap();
        assert_eq!(amt.as_str(), "1.5");
    }

    #[test]
    fn token_amount_small() {
        let json = r#""0.001""#;
        let amt: TokenAmount = serde_json::from_str(json).unwrap();
        assert_eq!(amt.as_str(), "0.001");
    }

    #[test]
    fn token_amount_zero() {
        let json = r#""0""#;
        let amt: TokenAmount = serde_json::from_str(json).unwrap();
        assert_eq!(amt.as_str(), "0");
    }

    #[test]
    fn token_amount_empty_rejected() {
        let json = r#""""#;
        assert!(serde_json::from_str::<TokenAmount>(json).is_err());
    }

    #[test]
    fn token_amount_negative_rejected() {
        let json = r#""-1""#;
        let err = serde_json::from_str::<TokenAmount>(json).unwrap_err();
        assert!(err.to_string().contains("negative"));
    }

    #[test]
    fn token_amount_non_numeric_rejected() {
        let json = r#""abc""#;
        assert!(serde_json::from_str::<TokenAmount>(json).is_err());
    }

    #[test]
    fn token_amount_multiple_dots_rejected() {
        let json = r#""1.2.3""#;
        let err = serde_json::from_str::<TokenAmount>(json).unwrap_err();
        assert!(err.to_string().contains("multiple decimal"));
    }

    // ---- ChainId tests ----

    #[test]
    fn chain_id_from_number() {
        let json = r#"8453"#;
        let cid: ChainId = serde_json::from_str(json).unwrap();
        assert_eq!(cid.as_u64(), 8453);
    }

    #[test]
    fn chain_id_from_string() {
        let json = r#""8453""#;
        let cid: ChainId = serde_json::from_str(json).unwrap();
        assert_eq!(cid.as_u64(), 8453);
    }

    #[test]
    fn chain_id_invalid_string() {
        let json = r#""abc""#;
        assert!(serde_json::from_str::<ChainId>(json).is_err());
    }

    // ---- TokenSpec tests ----

    #[test]
    fn token_spec_eth_upper() {
        let json = r#""ETH""#;
        let spec: TokenSpec = serde_json::from_str(json).unwrap();
        assert_eq!(spec, TokenSpec::Native);
    }

    #[test]
    fn token_spec_eth_lower() {
        let json = r#""eth""#;
        let spec: TokenSpec = serde_json::from_str(json).unwrap();
        assert_eq!(spec, TokenSpec::Native);
    }

    #[test]
    fn token_spec_erc20() {
        let json = r#""0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2""#;
        let spec: TokenSpec = serde_json::from_str(json).unwrap();
        assert!(matches!(spec, TokenSpec::Erc20(_)));
    }

    #[test]
    fn token_spec_invalid() {
        let json = r#""USDC""#;
        let result = serde_json::from_str::<TokenSpec>(json);
        assert!(result.is_err());
    }

    #[test]
    fn token_spec_roundtrip_native() {
        let spec = TokenSpec::Native;
        let json = serde_json::to_string(&spec).unwrap();
        let parsed: TokenSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, TokenSpec::Native);
    }

    // ---- RpcMethod tests (unchanged) ----

    #[test]
    fn test_method_from_str() {
        assert_eq!(RpcMethod::parse_method("health"), Some(RpcMethod::Health));
        assert_eq!(RpcMethod::parse_method("address"), Some(RpcMethod::Address));
        assert_eq!(RpcMethod::parse_method("balance"), Some(RpcMethod::Balance));
        assert_eq!(
            RpcMethod::parse_method("transfer"),
            Some(RpcMethod::Transfer)
        );
        assert_eq!(RpcMethod::parse_method("skills"), Some(RpcMethod::Skills));
        assert_eq!(RpcMethod::parse_method("execute"), Some(RpcMethod::Execute));
        assert_eq!(
            RpcMethod::parse_method("auth.grant"),
            Some(RpcMethod::AuthGrant)
        );
        assert_eq!(
            RpcMethod::parse_method("auth.list"),
            Some(RpcMethod::AuthList)
        );
        assert_eq!(
            RpcMethod::parse_method("auth.revoke"),
            Some(RpcMethod::AuthRevoke)
        );
        assert_eq!(
            RpcMethod::parse_method("auth.revoke_all"),
            Some(RpcMethod::AuthRevokeAll)
        );
        assert_eq!(RpcMethod::parse_method("unknown"), None);
    }

    #[test]
    fn test_method_as_str() {
        assert_eq!(RpcMethod::Health.as_str(), "health");
        assert_eq!(RpcMethod::Address.as_str(), "address");
        assert_eq!(RpcMethod::Balance.as_str(), "balance");
        assert_eq!(RpcMethod::Transfer.as_str(), "transfer");
        assert_eq!(RpcMethod::Skills.as_str(), "skills");
        assert_eq!(RpcMethod::Execute.as_str(), "execute");
        assert_eq!(RpcMethod::AuthGrant.as_str(), "auth.grant");
        assert_eq!(RpcMethod::AuthList.as_str(), "auth.list");
        assert_eq!(RpcMethod::AuthRevoke.as_str(), "auth.revoke");
        assert_eq!(RpcMethod::AuthRevokeAll.as_str(), "auth.revoke_all");
    }

    #[test]
    fn test_method_required_scope() {
        use clawlet_core::auth::TokenScope;

        assert_eq!(RpcMethod::Health.required_scope(), None);
        assert_eq!(RpcMethod::Address.required_scope(), None);
        assert_eq!(RpcMethod::Balance.required_scope(), Some(TokenScope::Read));
        assert_eq!(RpcMethod::Skills.required_scope(), Some(TokenScope::Read));
        assert_eq!(
            RpcMethod::Transfer.required_scope(),
            Some(TokenScope::Trade)
        );
        assert_eq!(RpcMethod::Execute.required_scope(), Some(TokenScope::Trade));
        assert_eq!(RpcMethod::AuthGrant.required_scope(), None);
        assert_eq!(RpcMethod::AuthList.required_scope(), None);
        assert_eq!(RpcMethod::AuthRevoke.required_scope(), None);
        assert_eq!(RpcMethod::AuthRevokeAll.required_scope(), None);
    }

    #[test]
    fn test_method_roundtrip() {
        let methods = [
            RpcMethod::Health,
            RpcMethod::Address,
            RpcMethod::Balance,
            RpcMethod::Transfer,
            RpcMethod::Skills,
            RpcMethod::Execute,
            RpcMethod::AuthGrant,
            RpcMethod::AuthList,
            RpcMethod::AuthRevoke,
            RpcMethod::AuthRevokeAll,
        ];

        for method in methods {
            let s = method.as_str();
            let parsed = RpcMethod::parse_method(s);
            assert_eq!(parsed, Some(method), "roundtrip failed for {:?}", method);
        }
    }
}
