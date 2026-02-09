//! Request handlers for RPC methods.
//!
//! Each handler processes a deserialized request and returns a serialized response.
//! Handlers are transport-agnostic — they work with `&AppState` and serde types.

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

use clawlet_core::ais::AisSpec;
use clawlet_core::audit::AuditEvent;
use clawlet_core::policy::PolicyDecision;
use clawlet_evm::tx::{
    build_erc20_transfer, build_eth_transfer, send_transaction,
    TransferRequest as EvmTransferRequest,
};
use clawlet_evm::U256;
use clawlet_signer::Signer;

use crate::server::AppState;

// ---- Request / Response types ----

/// Query parameters for balance requests.
#[derive(Debug, Deserialize, Serialize)]
pub struct BalanceQuery {
    /// The EVM address to query (hex, 0x-prefixed).
    pub address: String,
    /// The chain ID to query against.
    pub chain_id: u64,
}

/// A single token balance entry.
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenBalance {
    /// Token symbol (e.g. "USDC").
    pub symbol: String,
    /// Human-readable balance string.
    pub balance: String,
    /// Token contract address.
    pub address: String,
}

/// Response for balance queries.
#[derive(Debug, Serialize, Deserialize)]
pub struct BalanceResponse {
    /// Native ETH balance as a human-readable string.
    pub eth: String,
    /// ERC-20 token balances (empty for now — no token registry yet).
    pub tokens: Vec<TokenBalance>,
}

/// Request body for transfers.
#[derive(Debug, Deserialize, Serialize)]
pub struct TransferRequest {
    /// Recipient address (hex, 0x-prefixed).
    pub to: String,
    /// Amount as a decimal string (e.g. "1.0").
    pub amount: String,
    /// Token to transfer — "ETH" for native, or a contract address (hex, 0x-prefixed) for ERC-20.
    pub token: String,
    /// Chain ID to execute on.
    pub chain_id: u64,
}

/// Response for transfers.
#[derive(Debug, Serialize, Deserialize)]
pub struct TransferResponse {
    /// "success" or "denied".
    pub status: String,
    /// Transaction hash (present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
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

/// Response for skill execution.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecuteResponse {
    /// "success" or "error".
    pub status: String,
    /// Transaction hashes for executed actions.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tx_hashes: Vec<String>,
    /// Error message if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Response for address query.
#[derive(Debug, Serialize, Deserialize)]
pub struct AddressResponse {
    /// The wallet address managed by this clawlet instance (hex, 0x-prefixed).
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
    #[error("invalid address '{value}': must be 0x-prefixed followed by 40 hex characters")]
    InvalidAddress { value: String },
    #[error("invalid amount '{value}': {reason}")]
    InvalidAmount { value: String, reason: String },
    #[error("invalid token '{value}': must be \"ETH\" or a valid hex contract address")]
    InvalidToken { value: String },
    #[error("invalid chain_id: must be greater than 0")]
    InvalidChainId,
}

/// Validated transfer parameters with parsed types ready for use.
#[derive(Debug)]
struct ValidatedTransfer {
    /// Parsed recipient address.
    to: clawlet_evm::Address,
    /// Raw amount in smallest unit (wei for ETH).
    raw_amount: U256,
    /// Number of decimals used for the amount conversion.
    decimals: u8,
    /// Whether this is a native ETH transfer.
    is_native: bool,
    /// Token contract address (only set for ERC-20).
    token_address: Option<clawlet_evm::Address>,
    /// Original token string for policy/audit.
    token: String,
    /// Chain ID.
    chain_id: u64,
}

/// Validate that a string is a valid hex address (0x + 40 hex chars).
fn validate_hex_address(s: &str) -> bool {
    s.len() == 42 && s.starts_with("0x") && s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate and parse all fields of a `TransferRequest` at the boundary.
///
/// Returns a `ValidatedTransfer` with parsed addresses and raw amount,
/// or a `HandlerError` describing what's wrong.
async fn validate_transfer_request(
    state: &AppState,
    req: &TransferRequest,
) -> Result<ValidatedTransfer, HandlerError> {
    // 1. Validate chain_id > 0
    if req.chain_id == 0 {
        return Err(HandlerError::InvalidChainId);
    }

    // 2. Validate 'to' address format and parse
    if !validate_hex_address(&req.to) {
        return Err(HandlerError::InvalidAddress {
            value: req.to.clone(),
        });
    }
    let to: clawlet_evm::Address = req.to.parse().map_err(|_| HandlerError::InvalidAddress {
        value: req.to.clone(),
    })?;

    // 3. Validate token: "ETH" or valid hex address
    let is_native = req.token.eq_ignore_ascii_case("ETH");
    let token_address =
        if is_native {
            None
        } else {
            if !validate_hex_address(&req.token) {
                return Err(HandlerError::InvalidToken {
                    value: req.token.clone(),
                });
            }
            Some(req.token.parse::<clawlet_evm::Address>().map_err(|_| {
                HandlerError::InvalidToken {
                    value: req.token.clone(),
                }
            })?)
        };

    // 4. Validate amount is non-empty and a valid positive decimal
    let amount_trimmed = req.amount.trim();
    if amount_trimmed.is_empty() {
        return Err(HandlerError::InvalidAmount {
            value: req.amount.clone(),
            reason: "amount cannot be empty".to_string(),
        });
    }
    // Reject negative amounts
    if amount_trimmed.starts_with('-') {
        return Err(HandlerError::InvalidAmount {
            value: req.amount.clone(),
            reason: "amount must be positive".to_string(),
        });
    }

    // 5. Determine decimals and parse to raw amount
    let decimals: u8 = if is_native {
        18
    } else {
        let adapter = state.adapters.get(&req.chain_id).ok_or_else(|| {
            HandlerError::BadRequest(format!("unsupported chain_id: {}", req.chain_id))
        })?;
        let token_info = adapter
            .get_erc20_info(token_address.unwrap())
            .await
            .map_err(|e| HandlerError::Internal(format!("failed to query token info: {e}")))?;
        token_info.decimals
    };

    let raw_amount = parse_units(&req.amount, decimals as u32).map_err(|reason| {
        HandlerError::InvalidAmount {
            value: req.amount.clone(),
            reason,
        }
    })?;

    // 6. Reject zero amount
    if raw_amount.is_zero() {
        return Err(HandlerError::InvalidAmount {
            value: req.amount.clone(),
            reason: "amount must be greater than zero".to_string(),
        });
    }

    Ok(ValidatedTransfer {
        to,
        raw_amount,
        decimals,
        is_native,
        token_address,
        token: req.token.clone(),
        chain_id: req.chain_id,
    })
}

// ---- Handlers ----

/// Health check — always returns `{"status": "ok"}`.
pub fn handle_health(_state: &AppState) -> serde_json::Value {
    json!({ "status": "ok" })
}

/// Returns the wallet address managed by this clawlet instance.
pub fn handle_address(state: &AppState) -> Result<AddressResponse, HandlerError> {
    // Get the address from the loaded signer instance
    let address = state.signer.address().to_string();

    Ok(AddressResponse { address })
}

/// Query ETH balance for the given address and chain.
pub async fn handle_balance(
    state: &AppState,
    params: BalanceQuery,
) -> Result<BalanceResponse, HandlerError> {
    let adapter = state.adapters.get(&params.chain_id).ok_or_else(|| {
        HandlerError::BadRequest(format!("unsupported chain_id: {}", params.chain_id))
    })?;

    let address: clawlet_evm::Address = params
        .address
        .parse()
        .map_err(|e| HandlerError::BadRequest(format!("invalid address: {e}")))?;

    let wei = adapter
        .get_eth_balance(address)
        .await
        .map_err(|e| HandlerError::Internal(format!("rpc error: {e}")))?;

    let eth_str = format_units(wei, 18);

    // Log the balance query to audit
    {
        let event = AuditEvent::new(
            "balance_query",
            json!({
                "address": params.address,
                "chain_id": params.chain_id,
            }),
            "ok",
        );
        if let Ok(mut audit) = state.audit.lock() {
            let _ = audit.log_event(event);
        }
    }

    Ok(BalanceResponse {
        eth: eth_str,
        tokens: vec![],
    })
}

/// Execute a transfer within policy limits.
///
/// The `amount` field is in token units (e.g., "1.5" means 1.5 ETH or 1.5 USDC).
/// All fields are validated and the amount is converted to raw units (wei) upfront,
/// before any policy checks or transaction building.
pub async fn handle_transfer(
    state: &AppState,
    req: TransferRequest,
) -> Result<TransferResponse, HandlerError> {
    // Step 1: Validate and parse all request fields at the boundary.
    let validated = validate_transfer_request(state, &req).await?;

    // Step 2: Parse the decimal amount as f64 for USD-based policy checks.
    let amount_f64: f64 = req
        .amount
        .trim()
        .parse()
        .map_err(|_| HandlerError::InvalidAmount {
            value: req.amount.clone(),
            reason: "not a valid number".to_string(),
        })?;

    // Step 3: Policy check using the parsed amount (treated as USD value).
    let decision = state
        .policy
        .check_transfer(Some(amount_f64), &validated.token, validated.chain_id)
        .map_err(|e| HandlerError::Internal(format!("policy error: {e}")))?;

    match decision {
        PolicyDecision::Allowed => {
            let adapter = state.adapters.get(&validated.chain_id).ok_or_else(|| {
                HandlerError::BadRequest(format!("unsupported chain_id: {}", validated.chain_id))
            })?;

            let tx_req = if validated.is_native {
                build_eth_transfer(&EvmTransferRequest {
                    to: validated.to,
                    value: validated.raw_amount,
                    chain_id: validated.chain_id,
                    gas_limit: None,
                })
            } else {
                build_erc20_transfer(
                    validated.token_address.unwrap(),
                    validated.to,
                    validated.raw_amount,
                    validated.chain_id,
                )
            };

            let tx_hash = send_transaction(adapter, state.signer.as_ref(), tx_req)
                .await
                .map_err(|e| HandlerError::Internal(format!("send tx error: {e}")))?;

            let tx_hash_hex = format!("0x{}", hex::encode(tx_hash));

            let audit_id = format!(
                "{:016x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
                    & 0xFFFF_FFFF_FFFF_FFFF
            );

            {
                let event = AuditEvent::new(
                    "transfer",
                    json!({
                        "to": req.to,
                        "amount": req.amount,
                        "raw_amount": validated.raw_amount.to_string(),
                        "decimals": validated.decimals,
                        "token": req.token,
                        "chain_id": req.chain_id,
                        "tx_hash": tx_hash_hex,
                        "audit_id": audit_id,
                    }),
                    "allowed",
                );
                if let Ok(mut audit) = state.audit.lock() {
                    let _ = audit.log_event(event);
                }
            }

            Ok(TransferResponse {
                status: "success".to_string(),
                tx_hash: Some(tx_hash_hex),
                audit_id: Some(audit_id),
                reason: None,
            })
        }
        PolicyDecision::Denied(reason) => {
            {
                let event = AuditEvent::new(
                    "transfer",
                    json!({
                        "to": req.to,
                        "amount": req.amount,
                        "raw_amount": validated.raw_amount.to_string(),
                        "token": req.token,
                        "chain_id": req.chain_id,
                    }),
                    format!("denied: {reason}"),
                );
                if let Ok(mut audit) = state.audit.lock() {
                    let _ = audit.log_event(event);
                }
            }

            Ok(TransferResponse {
                status: "denied".to_string(),
                tx_hash: None,
                audit_id: None,
                reason: Some(reason),
            })
        }
        PolicyDecision::RequiresApproval(reason) => {
            {
                let event = AuditEvent::new(
                    "transfer",
                    json!({
                        "to": req.to,
                        "amount": req.amount,
                        "raw_amount": validated.raw_amount.to_string(),
                        "token": req.token,
                        "chain_id": req.chain_id,
                    }),
                    format!("requires_approval: {reason}"),
                );
                if let Ok(mut audit) = state.audit.lock() {
                    let _ = audit.log_event(event);
                }
            }

            Ok(TransferResponse {
                status: "denied".to_string(),
                tx_hash: None,
                audit_id: None,
                reason: Some(format!("requires approval: {reason}")),
            })
        }
    }
}

/// List available AIS specs from the skills directory.
pub fn handle_skills(state: &AppState) -> Result<SkillsResponse, HandlerError> {
    let mut skills = Vec::new();
    let dir = &state.skills_dir;
    let entries = std::fs::read_dir(dir)
        .map_err(|e| HandlerError::Internal(format!("failed to read skills dir: {e}")))?;

    for entry in entries {
        let entry = entry
            .map_err(|e| HandlerError::Internal(format!("failed to read skills entry: {e}")))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }

        let spec = AisSpec::from_file(&path).map_err(|e| {
            HandlerError::Internal(format!("failed to parse skill {}: {e}", path.display()))
        })?;

        skills.push(SkillSummary {
            name: spec.name,
            protocol: spec.protocol,
            description: spec.description,
            chain_id: spec.chain_id,
        });
    }

    Ok(SkillsResponse { skills })
}

/// Validate skill name to prevent path traversal attacks.
///
/// Only allows alphanumeric characters, underscores, and hyphens.
fn is_valid_skill_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Execute a skill by name.
pub async fn handle_execute(
    state: &AppState,
    req: ExecuteRequest,
) -> Result<ExecuteResponse, HandlerError> {
    // Validate skill name to prevent path traversal (e.g., "../secrets")
    if !is_valid_skill_name(&req.skill) {
        return Err(HandlerError::BadRequest(
            "invalid skill name: must be alphanumeric with underscores/hyphens only".into(),
        ));
    }

    let skill_path = state.skills_dir.join(format!("{}.yaml", req.skill));
    if !skill_path.exists() {
        return Err(HandlerError::NotFound("skill not found".into()));
    }

    // Prevent symlink escape: canonicalize and verify path is still inside skills_dir
    let canonical_path = skill_path
        .canonicalize()
        .map_err(|e| HandlerError::Internal(format!("failed to resolve skill path: {e}")))?;
    let canonical_skills_dir = state
        .skills_dir
        .canonicalize()
        .map_err(|e| HandlerError::Internal(format!("failed to resolve skills dir: {e}")))?;
    if !canonical_path.starts_with(&canonical_skills_dir) {
        return Err(HandlerError::BadRequest(
            "skill path escapes skills directory".into(),
        ));
    }

    let spec = AisSpec::from_file(&skill_path)
        .map_err(|e| HandlerError::BadRequest(format!("invalid skill: {e}")))?;

    let adapter = state.adapters.get(&spec.chain_id).ok_or_else(|| {
        HandlerError::BadRequest(format!("unsupported chain_id: {}", spec.chain_id))
    })?;

    let outputs =
        clawlet_evm::executor::execute_spec(&spec, req.params, adapter, state.signer.as_ref())
            .await
            .map_err(|e| HandlerError::Internal(format!("execute error: {e}")))?;

    let tx_hashes = outputs
        .iter()
        .map(|o| format!("0x{}", hex::encode(o.tx_hash)))
        .collect();

    Ok(ExecuteResponse {
        status: "success".to_string(),
        tx_hashes,
        error: None,
    })
}

/// Parse a decimal string (e.g. "1.5") into a U256 with the given number of decimals.
///
/// `parse_units("1.5", 18)` → `U256(1_500_000_000_000_000_000)`.
fn parse_units(amount: &str, decimals: u32) -> Result<U256, String> {
    let amount = amount.trim();
    if amount.is_empty() {
        return Err("empty amount".to_string());
    }

    let (integer, fractional) = match amount.split_once('.') {
        Some((i, f)) => (i, f),
        None => (amount, ""),
    };

    if fractional.len() > decimals as usize {
        return Err(format!(
            "too many decimal places: got {}, max {decimals}",
            fractional.len()
        ));
    }

    // Pad fractional part to `decimals` digits
    let padded = format!("{fractional:0<width$}", width = decimals as usize);

    // Combine integer + padded fractional as a single integer string
    let combined = format!("{integer}{padded}");

    // Strip leading zeros (but keep at least "0")
    let combined = combined.trim_start_matches('0');
    let combined = if combined.is_empty() { "0" } else { combined };

    U256::from_str_radix(combined, 10).map_err(|e| format!("invalid amount: {e}"))
}

/// Convert a U256 wei value to a decimal string with the given number of decimals.
fn format_units(value: clawlet_evm::U256, decimals: u32) -> String {
    let s = value.to_string();
    let decimals = decimals as usize;

    if s.len() <= decimals {
        if value.is_zero() {
            return "0.0".to_string();
        }
        let zeros = decimals - s.len();
        let mut result = "0.".to_string();
        result.push_str(&"0".repeat(zeros));
        result.push_str(s.trim_start_matches('0'));
        if result.ends_with('.') {
            result.push('0');
        }
        result
    } else {
        let integer_part = &s[..s.len() - decimals];
        let fractional_part = &s[s.len() - decimals..];
        let fractional = fractional_part.trim_end_matches('0');
        if fractional.is_empty() {
            format!("{integer_part}.0")
        } else {
            format!("{integer_part}.{fractional}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clawlet_evm::U256;

    // ---- validate_hex_address tests ----

    #[test]
    fn valid_hex_address() {
        assert!(validate_hex_address(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2"
        ));
    }

    #[test]
    fn valid_hex_address_all_lowercase() {
        assert!(validate_hex_address(
            "0x0000000000000000000000000000000000000001"
        ));
    }

    #[test]
    fn invalid_hex_address_no_prefix() {
        assert!(!validate_hex_address(
            "742d35Cc6634C0532925a3b844Bc9e7595f5b5e2"
        ));
    }

    #[test]
    fn invalid_hex_address_too_short() {
        assert!(!validate_hex_address("0x742d35Cc6634C0532925a3b844Bc9e75"));
    }

    #[test]
    fn invalid_hex_address_too_long() {
        assert!(!validate_hex_address(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2aa"
        ));
    }

    #[test]
    fn invalid_hex_address_non_hex_chars() {
        assert!(!validate_hex_address(
            "0xZZZd35Cc6634C0532925a3b844Bc9e7595f5b5e2"
        ));
    }

    #[test]
    fn invalid_hex_address_empty() {
        assert!(!validate_hex_address(""));
    }

    // ---- TransferRequest validation unit tests ----
    // (These test the validation helpers without needing AppState)

    #[test]
    fn token_validation_eth_is_native() {
        assert!("ETH".eq_ignore_ascii_case("ETH"));
        assert!("eth".eq_ignore_ascii_case("ETH"));
        assert!("Eth".eq_ignore_ascii_case("ETH"));
    }

    #[test]
    fn token_validation_contract_address() {
        let token = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        assert!(validate_hex_address(token));
    }

    #[test]
    fn token_validation_invalid() {
        assert!(!validate_hex_address("USDC")); // symbol, not address
        assert!(!validate_hex_address("0xinvalid"));
        assert!(!validate_hex_address(""));
    }

    #[test]
    fn amount_validation_negative() {
        let result = parse_units("-1.0", 18);
        // parse_units doesn't handle negative; the validation layer checks for '-' prefix
        // but parse_units itself will fail on the '-' char
        assert!(result.is_err());
    }

    #[test]
    fn amount_validation_zero_rejected_at_boundary() {
        let result = parse_units("0", 18).unwrap();
        assert!(result.is_zero());
        // The validate_transfer_request function rejects zero after parsing
    }

    #[test]
    fn amount_validation_valid_decimals() {
        let result = parse_units("1.5", 18).unwrap();
        assert!(!result.is_zero());
    }

    // ---- HandlerError display tests ----

    #[test]
    fn handler_error_invalid_address_display() {
        let err = HandlerError::InvalidAddress {
            value: "bad".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("bad"));
        assert!(msg.contains("0x-prefixed"));
    }

    #[test]
    fn handler_error_invalid_amount_display() {
        let err = HandlerError::InvalidAmount {
            value: "abc".to_string(),
            reason: "not a number".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("abc"));
        assert!(msg.contains("not a number"));
    }

    #[test]
    fn handler_error_invalid_token_display() {
        let err = HandlerError::InvalidToken {
            value: "SHIB".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("SHIB"));
    }

    #[test]
    fn handler_error_invalid_chain_id_display() {
        let err = HandlerError::InvalidChainId;
        let msg = format!("{err}");
        assert!(msg.contains("chain_id"));
    }

    // ---- parse_units tests ----

    #[test]
    fn parse_units_one_eth() {
        let result = parse_units("1.0", 18).unwrap();
        assert_eq!(result, U256::from(1_000_000_000_000_000_000u64));
    }

    #[test]
    fn parse_units_fractional() {
        let result = parse_units("1.5", 18).unwrap();
        assert_eq!(result, U256::from(1_500_000_000_000_000_000u64));
    }

    #[test]
    fn parse_units_zero() {
        let result = parse_units("0", 18).unwrap();
        assert_eq!(result, U256::ZERO);
    }

    #[test]
    fn parse_units_zero_point_zero() {
        let result = parse_units("0.0", 18).unwrap();
        assert_eq!(result, U256::ZERO);
    }

    #[test]
    fn parse_units_no_decimal() {
        let result = parse_units("100", 18).unwrap();
        assert_eq!(
            result,
            U256::from(100u64) * U256::from(10u64).pow(U256::from(18u64))
        );
    }

    #[test]
    fn parse_units_usdc_six_decimals() {
        let result = parse_units("1000.0", 6).unwrap();
        assert_eq!(result, U256::from(1_000_000_000u64));
    }

    #[test]
    fn parse_units_small_fraction() {
        let result = parse_units("0.000001", 18).unwrap();
        assert_eq!(result, U256::from(1_000_000_000_000u64));
    }

    #[test]
    fn parse_units_too_many_decimals() {
        let result = parse_units("1.1234567", 6);
        assert!(result.is_err());
    }

    #[test]
    fn parse_units_empty() {
        let result = parse_units("", 18);
        assert!(result.is_err());
    }

    #[test]
    fn parse_units_roundtrip_with_format_units() {
        let original = "1.5";
        let wei = parse_units(original, 18).unwrap();
        let back = format_units(wei, 18);
        assert_eq!(back, original);
    }

    // ---- existing tests ----

    #[test]
    fn address_response_serialization() {
        let response = AddressResponse {
            address: "0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("address"));
        assert!(json.contains("0x742d35Cc6634C0532925a3b844Bc9e7595f5b5e2"));
    }

    #[test]
    fn address_response_roundtrip() {
        let response = AddressResponse {
            address: "0x8ba1f109551bD432803012645Ac136ddd64DBA72".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        let parsed: AddressResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.address, "0x8ba1f109551bD432803012645Ac136ddd64DBA72");
    }

    #[test]
    fn format_units_one_eth() {
        let wei = U256::from(1_000_000_000_000_000_000u64);
        assert_eq!(format_units(wei, 18), "1.0");
    }

    #[test]
    fn format_units_fractional() {
        let wei = U256::from(1_500_000_000_000_000_000u64);
        assert_eq!(format_units(wei, 18), "1.5");
    }

    #[test]
    fn format_units_zero() {
        let wei = U256::ZERO;
        assert_eq!(format_units(wei, 18), "0.0");
    }

    #[test]
    fn format_units_small() {
        let wei = U256::from(1_000_000u64);
        let result = format_units(wei, 18);
        assert!(result.starts_with("0."));
    }

    #[test]
    fn format_units_usdc() {
        let amount = U256::from(1_000_000_000u64);
        assert_eq!(format_units(amount, 6), "1000.0");
    }
}
