//! Request handlers for RPC methods.
//!
//! Each handler processes a deserialized request and returns a serialized response.
//! Handlers are transport-agnostic — they work with `&AppState` and serde types.

use serde_json::json;

use alloy::primitives::Bytes;
use alloy::primitives::U256;
use clawlet_core::ais::AisSpec;
use clawlet_core::audit::AuditEvent;
use clawlet_core::policy::PolicyDecision;
use clawlet_evm::tx::{
    build_erc20_transfer, build_eth_transfer, build_raw_tx, send_transaction, RawTxRequest,
    TransferRequest as EvmTransferRequest,
};
use clawlet_signer::Signer;

use crate::server::AppState;
use crate::types::{
    AddressResponse, Amount, BalanceQuery, BalanceResponse, ExecuteRequest, ExecuteResponse,
    ExecuteStatus, HandlerError, SendRawRequest, SendRawResponse, SkillSummary, SkillsResponse,
    TokenSpec, TransferRequest, TransferResponse, TransferStatus,
};

// ---- Handlers ----

/// Health check — always returns `{"status": "ok"}`.
pub fn handle_health(_state: &AppState) -> serde_json::Value {
    json!({ "status": "ok" })
}

/// Returns the wallet address managed by this clawlet instance.
pub fn handle_address(state: &AppState) -> Result<AddressResponse, HandlerError> {
    // Get the address from the loaded signer instance
    let address = state.signer.address();

    Ok(AddressResponse { address })
}

/// Query ETH balance for the given address and chain.
pub async fn handle_balance(
    state: &AppState,
    params: BalanceQuery,
) -> Result<BalanceResponse, HandlerError> {
    let chain_id = params.chain_id;
    let adapter = state
        .adapters
        .get(&chain_id)
        .ok_or_else(|| HandlerError::BadRequest(format!("unsupported chain_id: {chain_id}")))?;

    let wei = adapter
        .get_eth_balance(params.address)
        .await
        .map_err(|e| HandlerError::Internal(format!("rpc error: {e}")))?;

    let eth = from_raw(wei, 18);

    // Log the balance query to audit
    {
        let event = AuditEvent::new(
            "balance_query",
            json!({
                "address": format!("{}", params.address),
                "chain_id": chain_id,
            }),
            "ok",
        );
        if let Ok(mut audit) = state.audit.lock() {
            let _ = audit.log_event(event);
        }
    }

    Ok(BalanceResponse {
        eth,
        tokens: vec![],
    })
}

/// Execute a transfer within policy limits.
///
/// The `amount` field is in token units (e.g., "1.5" means 1.5 ETH or 1.5 USDC).
/// USD-based policy checks are skipped until a price oracle is integrated.
pub async fn handle_transfer(
    state: &AppState,
    req: TransferRequest,
) -> Result<TransferResponse, HandlerError> {
    let chain_id = req.chain_id;

    let token_str = req.token.as_policy_str();
    let token_str_ref = token_str.as_str();

    // Policy check — USD amount is None (no price oracle yet), so only
    // allowed_tokens and allowed_chains are enforced.
    let decision = state
        .policy
        .check_transfer(None, token_str_ref, chain_id)
        .map_err(|e| HandlerError::Internal(format!("policy error: {e}")))?;

    match decision {
        PolicyDecision::Allowed => {
            let adapter = state.adapters.get(&chain_id).ok_or_else(|| {
                HandlerError::BadRequest(format!("unsupported chain_id: {chain_id}"))
            })?;

            let to = req.to;

            let tx_req = match &req.token {
                TokenSpec::Native => {
                    let value = to_raw(req.amount, 18).map_err(HandlerError::BadRequest)?;
                    build_eth_transfer(&EvmTransferRequest {
                        to,
                        value,
                        chain_id,
                        gas_limit: None,
                    })
                }
                TokenSpec::Erc20(token_address) => {
                    let token_address = *token_address;
                    let token_info = adapter.get_erc20_info(token_address).await.map_err(|e| {
                        HandlerError::Internal(format!("failed to query token info: {e}"))
                    })?;
                    let amount = to_raw(req.amount, token_info.decimals as u32)
                        .map_err(HandlerError::BadRequest)?;
                    build_erc20_transfer(token_address, to, amount, chain_id)
                }
            };

            let tx_hash = send_transaction(adapter, state.signer.as_ref(), tx_req)
                .await
                .map_err(|e| HandlerError::Internal(format!("send tx error: {e}")))?;

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
                        "to": format!("{}", req.to),
                        "amount": req.amount.to_string(),
                        "token": token_str_ref,
                        "chain_id": chain_id,
                        "tx_hash": format!("{tx_hash}"),
                        "audit_id": audit_id,
                    }),
                    "allowed",
                );
                if let Ok(mut audit) = state.audit.lock() {
                    let _ = audit.log_event(event);
                }
            }

            Ok(TransferResponse {
                status: TransferStatus::Success,
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
                        "to": format!("{}", req.to),
                        "amount": req.amount.to_string(),
                        "token": token_str_ref,
                        "chain_id": chain_id,
                    }),
                    format!("denied: {reason}"),
                );
                if let Ok(mut audit) = state.audit.lock() {
                    let _ = audit.log_event(event);
                }
            }

            Ok(TransferResponse {
                status: TransferStatus::Denied,
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
                        "to": format!("{}", req.to),
                        "amount": req.amount.to_string(),
                        "token": token_str_ref,
                        "chain_id": chain_id,
                    }),
                    format!("requires_approval: {reason}"),
                );
                if let Ok(mut audit) = state.audit.lock() {
                    let _ = audit.log_event(event);
                }
            }

            Ok(TransferResponse {
                status: TransferStatus::Denied,
                tx_hash: None,
                audit_id: None,
                reason: Some(format!("requires approval: {reason}")),
            })
        }
    }
}

/// Send a raw transaction bypassing the policy engine.
///
/// This is for advanced use cases where the caller wants to send arbitrary
/// calldata to any address. Still audited, just not policy-gated.
pub async fn handle_send_raw(
    state: &AppState,
    req: SendRawRequest,
) -> Result<SendRawResponse, HandlerError> {
    let chain_id = req.chain_id;

    let adapter = state
        .adapters
        .get(&chain_id)
        .ok_or_else(|| HandlerError::BadRequest(format!("unsupported chain_id: {chain_id}")))?;

    // Parse value (default 0)
    let value = match req.value {
        Some(amount) => to_raw(amount, 18).map_err(HandlerError::BadRequest)?,
        None => U256::ZERO,
    };

    // Parse calldata (default empty)
    let data = match req.data {
        Some(ref hex_str) => {
            let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
            let bytes = hex::decode(hex_str)
                .map_err(|e| HandlerError::BadRequest(format!("invalid hex data: {e}")))?;
            Bytes::from(bytes)
        }
        None => Bytes::new(),
    };

    let tx_req = build_raw_tx(&RawTxRequest {
        to: req.to,
        value,
        data,
        chain_id,
        gas_limit: req.gas_limit,
    });

    let tx_hash = send_transaction(adapter, state.signer.as_ref(), tx_req)
        .await
        .map_err(|e| HandlerError::Internal(format!("send tx error: {e}")))?;

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
            "send_raw",
            json!({
                "to": format!("{}", req.to),
                "value": req.value.map(|v| v.to_string()).unwrap_or_else(|| "0".to_string()),
                "data": req.data.as_deref().unwrap_or(""),
                "chain_id": chain_id,
                "gas_limit": req.gas_limit,
                "tx_hash": format!("{tx_hash}"),
                "audit_id": audit_id,
            }),
            "ok",
        );
        if let Ok(mut audit) = state.audit.lock() {
            let _ = audit.log_event(event);
        }
    }

    Ok(SendRawResponse { tx_hash, audit_id })
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

    let tx_hashes = outputs.iter().map(|o| o.tx_hash).collect();

    Ok(ExecuteResponse {
        status: ExecuteStatus::Success,
        tx_hashes,
        error: None,
    })
}

/// Compute 10^decimals as a `Decimal`.
fn decimal_pow10(decimals: u32) -> rust_decimal::Decimal {
    use rust_decimal::Decimal;
    let mut result = Decimal::ONE;
    let ten = Decimal::TEN;
    for _ in 0..decimals {
        result *= ten;
    }
    result
}

/// Convert a human-readable `Amount` (Decimal) to a raw `U256` in smallest units.
///
/// `to_raw(Amount("1.5"), 18)` → `U256(1_500_000_000_000_000_000)`.
fn to_raw(amount: Amount, decimals: u32) -> Result<U256, String> {
    use rust_decimal::Decimal;

    let d = amount.value();
    let scale = decimal_pow10(decimals);
    let raw = d.checked_mul(scale).ok_or("amount overflow")?;

    // Must be an integer after scaling (no fractional smallest-units)
    if raw.fract() != Decimal::ZERO {
        return Err(format!("too many decimal places for {decimals} decimals"));
    }

    let raw = raw.trunc();
    U256::from_str_radix(&raw.to_string(), 10).map_err(|e| format!("invalid amount: {e}"))
}

/// Convert a raw `U256` in smallest units to a human-readable `Amount` (Decimal).
///
/// `from_raw(U256(1_500_000_000_000_000_000), 18)` → `Amount("1.5")`.
fn from_raw(value: U256, decimals: u32) -> Amount {
    use rust_decimal::Decimal;

    let d = Decimal::from_str_radix(&value.to_string(), 10).unwrap_or_default();
    let scale = decimal_pow10(decimals);
    let result = (d / scale).normalize();
    // Safe: wei values are non-negative
    result.to_string().parse().expect("non-negative raw / 10^n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, U256};

    /// Helper to create an Amount from a string literal.
    fn amt(s: &str) -> Amount {
        s.parse().unwrap()
    }

    // ---- to_raw tests ----

    #[test]
    fn to_raw_one_eth() {
        let result = to_raw(amt("1.0"), 18).unwrap();
        assert_eq!(result, U256::from(1_000_000_000_000_000_000u64));
    }

    #[test]
    fn to_raw_fractional() {
        let result = to_raw(amt("1.5"), 18).unwrap();
        assert_eq!(result, U256::from(1_500_000_000_000_000_000u64));
    }

    #[test]
    fn to_raw_zero() {
        let result = to_raw(amt("0"), 18).unwrap();
        assert_eq!(result, U256::ZERO);
    }

    #[test]
    fn to_raw_zero_point_zero() {
        let result = to_raw(amt("0.0"), 18).unwrap();
        assert_eq!(result, U256::ZERO);
    }

    #[test]
    fn to_raw_no_decimal() {
        let result = to_raw(amt("100"), 18).unwrap();
        assert_eq!(
            result,
            U256::from(100u64) * U256::from(10u64).pow(U256::from(18u64))
        );
    }

    #[test]
    fn to_raw_usdc_six_decimals() {
        let result = to_raw(amt("1000.0"), 6).unwrap();
        assert_eq!(result, U256::from(1_000_000_000u64));
    }

    #[test]
    fn to_raw_small_fraction() {
        let result = to_raw(amt("0.000001"), 18).unwrap();
        assert_eq!(result, U256::from(1_000_000_000_000u64));
    }

    #[test]
    fn to_raw_too_many_decimals() {
        let result = to_raw(amt("1.1234567"), 6);
        assert!(result.is_err());
    }

    #[test]
    fn to_raw_roundtrip_with_from_raw() {
        let original = amt("1.5");
        let wei = to_raw(original, 18).unwrap();
        let back = from_raw(wei, 18);
        assert_eq!(back.to_string(), original.to_string());
    }

    // ---- from_raw tests ----

    #[test]
    fn address_response_serialization() {
        let addr: Address = "0x742D35CC6634c0532925A3b844bc9E7595f5B5e2"
            .parse()
            .unwrap();
        let response = AddressResponse { address: addr };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("address"));
        let parsed: AddressResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.address, addr);
    }

    #[test]
    fn address_response_roundtrip() {
        let addr: Address = "0x8ba1f109551bD432803012645Ac136ddd64DBA72"
            .parse()
            .unwrap();
        let response = AddressResponse { address: addr };
        let json = serde_json::to_string(&response).unwrap();
        let parsed: AddressResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.address, addr);
    }

    #[test]
    fn from_raw_one_eth() {
        let wei = U256::from(1_000_000_000_000_000_000u64);
        assert_eq!(from_raw(wei, 18).to_string(), "1");
    }

    #[test]
    fn from_raw_fractional() {
        let wei = U256::from(1_500_000_000_000_000_000u64);
        assert_eq!(from_raw(wei, 18).to_string(), "1.5");
    }

    #[test]
    fn from_raw_zero() {
        let wei = U256::ZERO;
        assert_eq!(from_raw(wei, 18).to_string(), "0");
    }

    #[test]
    fn from_raw_small() {
        let wei = U256::from(1_000_000u64);
        let result = from_raw(wei, 18);
        assert!(result.to_string().starts_with("0."));
    }

    #[test]
    fn from_raw_usdc() {
        let amount = U256::from(1_000_000_000u64);
        assert_eq!(from_raw(amount, 6).to_string(), "1000");
    }
}
