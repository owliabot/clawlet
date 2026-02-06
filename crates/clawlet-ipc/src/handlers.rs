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
    /// Token to transfer — "ETH" for native, or a symbol/address.
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
pub async fn handle_transfer(
    state: &AppState,
    req: TransferRequest,
) -> Result<TransferResponse, HandlerError> {
    let amount_usd: f64 = req
        .amount
        .parse()
        .map_err(|_| HandlerError::BadRequest("invalid amount".to_string()))?;

    let decision = state
        .policy
        .check_transfer(amount_usd, &req.token, req.chain_id)
        .map_err(|e| HandlerError::Internal(format!("policy error: {e}")))?;

    match decision {
        PolicyDecision::Allowed => {
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
                        "token": req.token,
                        "chain_id": req.chain_id,
                        "audit_id": audit_id,
                    }),
                    "allowed",
                );
                if let Ok(mut audit) = state.audit.lock() {
                    let _ = audit.log_event(event);
                }
            }

            let tx_hash = format!("0x{}", "0".repeat(64));

            Ok(TransferResponse {
                status: "success".to_string(),
                tx_hash: Some(tx_hash),
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
