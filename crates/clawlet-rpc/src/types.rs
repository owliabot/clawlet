//! Shared types for JSON-RPC communication.
//!
//! This module provides request/response types, typed wrappers, and RPC method definitions.

use std::borrow::Cow;
use std::collections::HashMap;

use std::fmt;
use std::str::FromStr;

use alloy::primitives::{Address, Bytes, TxHash, B256, U256};
use clawlet_core::auth::TokenScope;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

/// A non-negative `Decimal` amount. Rejects negative values at deserialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, DeserializeFromStr, SerializeDisplay)]
pub struct Amount(Decimal);

impl Amount {
    /// Returns the inner `Decimal` value.
    pub fn value(self) -> Decimal {
        self.0
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Amount {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let d: Decimal = s.parse().map_err(|e| format!("invalid amount: {e}"))?;
        if d.is_sign_negative() {
            return Err("amount must not be negative".to_string());
        }
        Ok(Amount(d))
    }
}

// ---- RPC Method ----

/// RPC method discriminant — maps to the endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcMethod {
    Health,
    /// List supported chains (no auth required).
    Chains,
    /// Query wallet address (no auth required).
    Address,
    Balance,
    Transfer,
    Skills,
    Execute,
    /// Send a raw transaction bypassing the policy engine.
    SendRaw,
    /// Sign a message using EIP-191 personal sign.
    SignMessage,
    /// Grant a new session token (Admin only).
    AuthGrant,
    /// List all sessions including expired ones in grace period (Admin only).
    AuthList,
    /// Revoke all sessions for an agent (Admin only).
    AuthRevoke,
    /// Revoke a single session by session key (Admin only).
    AuthRevokeSession,
    /// Revoke all sessions (Admin only).
    AuthRevokeAll,
}

impl RpcMethod {
    /// Parse a method name string into an RpcMethod.
    pub fn parse_method(s: &str) -> Option<Self> {
        match s {
            "health" => Some(Self::Health),
            "chains" => Some(Self::Chains),
            "address" => Some(Self::Address),
            "balance" => Some(Self::Balance),
            "transfer" => Some(Self::Transfer),
            "skills" => Some(Self::Skills),
            "execute" => Some(Self::Execute),
            "send_raw" => Some(Self::SendRaw),
            "sign_message" => Some(Self::SignMessage),
            "auth.grant" => Some(Self::AuthGrant),
            "auth.list" => Some(Self::AuthList),
            "auth.revoke" => Some(Self::AuthRevoke),
            "auth.revoke_session" => Some(Self::AuthRevokeSession),
            "auth.revoke_all" => Some(Self::AuthRevokeAll),
            _ => None,
        }
    }

    /// Get the method name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Health => "health",
            Self::Chains => "chains",
            Self::Address => "address",
            Self::Balance => "balance",
            Self::Transfer => "transfer",
            Self::Skills => "skills",
            Self::Execute => "execute",
            Self::SendRaw => "send_raw",
            Self::SignMessage => "sign_message",
            Self::AuthGrant => "auth.grant",
            Self::AuthList => "auth.list",
            Self::AuthRevoke => "auth.revoke",
            Self::AuthRevokeSession => "auth.revoke_session",
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
            RpcMethod::Health | RpcMethod::Chains | RpcMethod::Address => None,
            RpcMethod::Balance | RpcMethod::Skills => Some(TokenScope::Read),
            RpcMethod::Transfer | RpcMethod::Execute | RpcMethod::SendRaw => {
                Some(TokenScope::Trade)
            }
            RpcMethod::SignMessage => Some(TokenScope::Read),
            RpcMethod::AuthGrant
            | RpcMethod::AuthList
            | RpcMethod::AuthRevoke
            | RpcMethod::AuthRevokeSession
            | RpcMethod::AuthRevokeAll => None,
        }
    }
}

// ---- Strongly-typed parameter wrappers ----

/// Token specifier: native ETH or an ERC-20 contract address.
#[derive(Debug, Clone, DeserializeFromStr, SerializeDisplay)]
pub enum TokenSpec {
    Native,
    Erc20(Address),
}

impl TokenSpec {
    /// Returns the string representation used for policy checks.
    pub fn as_policy_str(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for TokenSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenSpec::Native => f.write_str("ETH"),
            TokenSpec::Erc20(addr) => write!(f, "{addr}"),
        }
    }
}

impl FromStr for TokenSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("ETH") {
            return Ok(TokenSpec::Native);
        }
        let addr: Address = s
            .parse()
            .map_err(|e| format!("invalid token address: {e}"))?;
        Ok(TokenSpec::Erc20(addr))
    }
}

// ---- Request / Response types ----

/// Query parameters for balance requests.
#[derive(Debug, Deserialize, Serialize)]
pub struct BalanceQuery {
    /// The EVM address to query (hex, 0x-prefixed).
    pub address: Address,
    /// The chain ID to query against.
    pub chain_id: u64,
}

/// A single token balance entry.
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenBalance {
    /// Token symbol (e.g. "USDC").
    pub symbol: String,
    /// Human-readable balance.
    pub balance: Amount,
    /// Token contract address.
    pub address: Address,
}

/// Response for balance queries.
#[derive(Debug, Serialize, Deserialize)]
pub struct BalanceResponse {
    /// Native ETH balance.
    pub eth: Amount,
    /// ERC-20 token balances (empty for now — no token registry yet).
    pub tokens: Vec<TokenBalance>,
}

/// Request body for transfers.
#[derive(Debug, Deserialize, Serialize)]
pub struct TransferRequest {
    /// Recipient address (hex, 0x-prefixed).
    pub to: Address,
    /// Amount as a non-negative decimal value (e.g. "1.5").
    pub amount: Amount,
    /// Token to transfer — "ETH" for native, or a contract address (hex, 0x-prefixed) for ERC-20.
    pub token: TokenSpec,
    /// Chain ID to execute on.
    pub chain_id: u64,
}

/// Transfer outcome status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatus {
    Success,
    Denied,
}

/// Response for transfers.
#[derive(Debug, Serialize, Deserialize)]
pub struct TransferResponse {
    /// Outcome of the transfer.
    pub status: TransferStatus,
    /// Transaction hash (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<B256>,
    /// Audit event ID (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_id: Option<String>,
    /// Denial reason (present on denial).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A single AIS skill summary.
#[derive(Debug, Serialize, Deserialize)]
pub struct SkillSummary {
    /// Skill name.
    pub name: String,
    /// Protocol name.
    pub protocol: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Chain ID.
    pub chain_id: u64,
}

/// Response for skills listing.
#[derive(Debug, Serialize, Deserialize)]
pub struct SkillsResponse {
    pub skills: Vec<SkillSummary>,
}

/// Request body for skill execution.
#[derive(Debug, Deserialize, Serialize)]
pub struct ExecuteRequest {
    /// Skill name (matches the AIS spec name or filename).
    pub skill: String,
    /// Parameter values for execution.
    #[serde(default)]
    pub params: HashMap<String, String>,
}

/// Execute outcome status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteStatus {
    Success,
    Error,
}

/// Response for skill execution.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecuteResponse {
    /// Outcome of the execution.
    pub status: ExecuteStatus,
    /// Transaction hashes for executed actions.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tx_hashes: Vec<B256>,
    /// Error message if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Response for address query.
#[derive(Debug, Serialize, Deserialize)]
pub struct AddressResponse {
    /// The wallet address managed by this clawlet instance (hex, 0x-prefixed).
    pub address: Address,
}

/// Request body for raw transaction sends (bypasses policy engine).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendRawRequest {
    /// Recipient address (hex, 0x-prefixed).
    pub to: Address,
    /// ETH value in wei.
    #[serde(default)]
    pub value: Option<U256>,
    /// Raw calldata bytes.
    #[serde(default)]
    pub data: Option<Bytes>,
    /// Chain ID to execute on.
    pub chain_id: u64,
    /// Optional gas limit override.
    #[serde(default)]
    pub gas_limit: Option<u64>,
}

/// Response for raw transaction sends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendRawResponse {
    /// Transaction hash.
    pub tx_hash: TxHash,
    /// Audit event ID.
    pub audit_id: String,
}

/// Information about a supported chain.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChainInfo {
    /// Numeric chain ID.
    pub chain_id: u64,
    /// Human-readable chain name.
    pub name: String,
    /// Whether this chain is a testnet.
    pub testnet: bool,
}

/// Response for chains listing.
#[derive(Debug, Serialize, Deserialize)]
pub struct ChainsResponse {
    /// List of supported chains.
    pub chains: Vec<ChainInfo>,
}

/// Returns `true` if the given chain ID is a well-known testnet.
pub fn is_testnet(chain_id: u64) -> bool {
    matches!(
        chain_id,
        5          // Goerli
        | 11155111 // Sepolia
        | 80001    // Mumbai
        | 97       // BSC Testnet
        | 421613   // Arbitrum Goerli
        | 420      // Optimism Goerli
        | 84531    // Base Goerli
        | 84532    // Base Sepolia
        | 11155420 // Optimism Sepolia
        | 421614 // Arbitrum Sepolia
    )
}

/// Map a chain ID to a well-known human-readable name.
pub fn chain_name(chain_id: u64) -> Cow<'static, str> {
    match chain_id {
        1 => Cow::Borrowed("Ethereum"),
        10 => Cow::Borrowed("Optimism"),
        56 => Cow::Borrowed("BNB Chain"),
        137 => Cow::Borrowed("Polygon"),
        8453 => Cow::Borrowed("Base"),
        42161 => Cow::Borrowed("Arbitrum"),
        43114 => Cow::Borrowed("Avalanche"),
        _ => Cow::Owned(format!("Unknown ({chain_id})")),
    }
}

/// Request body for signing a message (EIP-191 personal sign).
#[derive(Debug, Deserialize, Serialize)]
pub struct SignMessageRequest {
    /// Message to sign — hex-encoded (0x-prefixed) or raw UTF-8 string.
    pub message: String,
}

/// Response for sign_message.
#[derive(Debug, Deserialize, Serialize)]
pub struct SignMessageResponse {
    /// 0x-prefixed hex signature, 65 bytes (r || s || v).
    pub signature: String,
    /// Signer address (hex, 0x-prefixed).
    pub address: String,
}

/// Errors returned by handlers.
#[derive(Debug, thiserror::Error)]
pub enum HandlerError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- chain_name tests ----

    #[test]
    fn chain_name_known_chains() {
        assert_eq!(chain_name(1), "Ethereum");
        assert_eq!(chain_name(10), "Optimism");
        assert_eq!(chain_name(56), "BNB Chain");
        assert_eq!(chain_name(137), "Polygon");
        assert_eq!(chain_name(8453), "Base");
        assert_eq!(chain_name(42161), "Arbitrum");
        assert_eq!(chain_name(43114), "Avalanche");
    }

    #[test]
    fn chain_name_unknown_chain() {
        assert_eq!(chain_name(999999), "Unknown (999999)");
    }

    #[test]
    fn chain_name_known_returns_borrowed() {
        let name = chain_name(1);
        assert!(matches!(name, Cow::Borrowed(_)));
    }

    #[test]
    fn chain_name_unknown_returns_owned() {
        let name = chain_name(999999);
        assert!(matches!(name, Cow::Owned(_)));
    }

    // ---- ChainInfo serialization tests ----

    #[test]
    fn chain_info_serialization_no_rpc_configured_field() {
        let info = ChainInfo {
            chain_id: 1,
            name: "Ethereum".to_string(),
            testnet: false,
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["chain_id"], 1);
        assert_eq!(json["name"], "Ethereum");
        assert_eq!(json["testnet"], false);
        assert!(json.get("rpc_configured").is_none());
    }

    #[test]
    fn chains_response_roundtrip() {
        let resp = ChainsResponse {
            chains: vec![
                ChainInfo {
                    chain_id: 1,
                    name: "Ethereum".to_string(),
                    testnet: false,
                },
                ChainInfo {
                    chain_id: 8453,
                    name: "Base".to_string(),
                    testnet: false,
                },
            ],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: ChainsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.chains.len(), 2);
        assert_eq!(parsed.chains[0].chain_id, 1);
        assert_eq!(parsed.chains[1].name, "Base");
    }

    // ---- RpcMethod tests ----

    #[test]
    fn test_method_from_str() {
        assert_eq!(RpcMethod::parse_method("health"), Some(RpcMethod::Health));
        assert_eq!(RpcMethod::parse_method("chains"), Some(RpcMethod::Chains));
        assert_eq!(RpcMethod::parse_method("address"), Some(RpcMethod::Address));
        assert_eq!(RpcMethod::parse_method("balance"), Some(RpcMethod::Balance));
        assert_eq!(
            RpcMethod::parse_method("transfer"),
            Some(RpcMethod::Transfer)
        );
        assert_eq!(RpcMethod::parse_method("skills"), Some(RpcMethod::Skills));
        assert_eq!(RpcMethod::parse_method("execute"), Some(RpcMethod::Execute));
        assert_eq!(
            RpcMethod::parse_method("send_raw"),
            Some(RpcMethod::SendRaw)
        );
        assert_eq!(
            RpcMethod::parse_method("sign_message"),
            Some(RpcMethod::SignMessage)
        );
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
            RpcMethod::parse_method("auth.revoke_session"),
            Some(RpcMethod::AuthRevokeSession)
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
        assert_eq!(RpcMethod::Chains.as_str(), "chains");
        assert_eq!(RpcMethod::Address.as_str(), "address");
        assert_eq!(RpcMethod::Balance.as_str(), "balance");
        assert_eq!(RpcMethod::Transfer.as_str(), "transfer");
        assert_eq!(RpcMethod::Skills.as_str(), "skills");
        assert_eq!(RpcMethod::Execute.as_str(), "execute");
        assert_eq!(RpcMethod::SendRaw.as_str(), "send_raw");
        assert_eq!(RpcMethod::SignMessage.as_str(), "sign_message");
        assert_eq!(RpcMethod::AuthGrant.as_str(), "auth.grant");
        assert_eq!(RpcMethod::AuthList.as_str(), "auth.list");
        assert_eq!(RpcMethod::AuthRevoke.as_str(), "auth.revoke");
        assert_eq!(RpcMethod::AuthRevokeSession.as_str(), "auth.revoke_session");
        assert_eq!(RpcMethod::AuthRevokeAll.as_str(), "auth.revoke_all");
    }

    #[test]
    fn test_method_required_scope() {
        use clawlet_core::auth::TokenScope;

        assert_eq!(RpcMethod::Health.required_scope(), None);
        assert_eq!(RpcMethod::Chains.required_scope(), None);
        assert_eq!(RpcMethod::Address.required_scope(), None);
        assert_eq!(RpcMethod::Balance.required_scope(), Some(TokenScope::Read));
        assert_eq!(RpcMethod::Skills.required_scope(), Some(TokenScope::Read));
        assert_eq!(
            RpcMethod::Transfer.required_scope(),
            Some(TokenScope::Trade)
        );
        assert_eq!(RpcMethod::Execute.required_scope(), Some(TokenScope::Trade));
        assert_eq!(RpcMethod::SendRaw.required_scope(), Some(TokenScope::Trade));
        assert_eq!(
            RpcMethod::SignMessage.required_scope(),
            Some(TokenScope::Read)
        );
        assert_eq!(RpcMethod::AuthGrant.required_scope(), None);
        assert_eq!(RpcMethod::AuthList.required_scope(), None);
        assert_eq!(RpcMethod::AuthRevoke.required_scope(), None);
        assert_eq!(RpcMethod::AuthRevokeAll.required_scope(), None);
    }

    #[test]
    fn test_method_roundtrip() {
        let methods = [
            RpcMethod::Health,
            RpcMethod::Chains,
            RpcMethod::Address,
            RpcMethod::Balance,
            RpcMethod::Transfer,
            RpcMethod::Skills,
            RpcMethod::Execute,
            RpcMethod::SendRaw,
            RpcMethod::SignMessage,
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

    // ---- Address tests ----

    #[test]
    fn address_valid() {
        let addr: Address =
            serde_json::from_str(r#""0x742D35CC6634c0532925A3b844bc9E7595f5B5e2""#).unwrap();
        assert_eq!(
            format!("{addr}"),
            "0x742D35CC6634c0532925A3b844bc9E7595f5B5e2"
        );
    }

    #[test]
    fn address_invalid() {
        let res = serde_json::from_str::<Address>(r#""not_an_address""#);
        assert!(res.is_err());
    }

    // ---- Amount tests ----

    #[test]
    fn amount_valid_integer() {
        let a: Amount = serde_json::from_str(r#""100""#).unwrap();
        assert_eq!(a.to_string(), "100");
    }

    #[test]
    fn amount_valid_decimal() {
        let a: Amount = serde_json::from_str(r#""1.5""#).unwrap();
        assert_eq!(a.to_string(), "1.5");
    }

    #[test]
    fn amount_zero() {
        let a: Amount = serde_json::from_str(r#""0""#).unwrap();
        assert_eq!(a.to_string(), "0");
    }

    #[test]
    fn amount_negative_rejected() {
        let res = serde_json::from_str::<Amount>(r#""-1.5""#);
        assert!(res.is_err());
    }

    #[test]
    fn amount_invalid_letters() {
        assert!(serde_json::from_str::<Amount>(r#""12abc""#).is_err());
    }

    #[test]
    fn amount_empty() {
        assert!(serde_json::from_str::<Amount>(r#""""#).is_err());
    }

    // ---- TokenSpec tests ----

    #[test]
    fn token_spec_native_eth() {
        let spec: TokenSpec = serde_json::from_str(r#""ETH""#).unwrap();
        assert!(matches!(spec, TokenSpec::Native));
    }

    #[test]
    fn token_spec_native_lowercase() {
        let spec: TokenSpec = serde_json::from_str(r#""eth""#).unwrap();
        assert!(matches!(spec, TokenSpec::Native));
    }

    #[test]
    fn token_spec_erc20() {
        let spec: TokenSpec =
            serde_json::from_str(r#""0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48""#).unwrap();
        assert!(matches!(spec, TokenSpec::Erc20(_)));
    }

    #[test]
    fn token_spec_invalid() {
        let res = serde_json::from_str::<TokenSpec>(r#""USDC""#);
        assert!(res.is_err());
    }

    // ---- BalanceQuery / TransferRequest deserialization ----

    #[test]
    fn balance_query_valid() {
        let q: BalanceQuery = serde_json::from_str(
            r#"{"address":"0x742D35CC6634c0532925A3b844bc9E7595f5B5e2","chain_id":8453}"#,
        )
        .unwrap();
        assert_eq!(
            format!("{}", q.address),
            "0x742D35CC6634c0532925A3b844bc9E7595f5B5e2"
        );
        assert_eq!(q.chain_id, 8453);
    }

    #[test]
    fn balance_query_bad_address() {
        let res =
            serde_json::from_str::<BalanceQuery>(r#"{"address":"not_an_address","chain_id":1}"#);
        assert!(res.is_err());
    }

    #[test]
    fn transfer_request_valid_native() {
        let req: TransferRequest = serde_json::from_str(
            r#"{"to":"0x742D35CC6634c0532925A3b844bc9E7595f5B5e2","amount":"1.5","token":"ETH","chain_id":8453}"#,
        )
        .unwrap();
        assert!(matches!(req.token, TokenSpec::Native));
        assert_eq!(req.amount.to_string(), "1.5");
    }

    #[test]
    fn transfer_request_invalid_amount() {
        let res = serde_json::from_str::<TransferRequest>(
            r#"{"to":"0x742D35CC6634c0532925A3b844bc9E7595f5B5e2","amount":"not_a_number","token":"ETH","chain_id":1}"#,
        );
        assert!(res.is_err());
    }

    #[test]
    fn transfer_request_negative_amount_rejected() {
        let res = serde_json::from_str::<TransferRequest>(
            r#"{"to":"0x742D35CC6634c0532925A3b844bc9E7595f5B5e2","amount":"-5","token":"ETH","chain_id":1}"#,
        );
        assert!(res.is_err());
    }
}
