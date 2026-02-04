//! Request handlers for API routes.
//!
//! Each handler processes a request, applies policy checks, and returns a response.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use clawlet_core::audit::AuditEvent;
use clawlet_core::policy::PolicyDecision;

use crate::server::AppState;

// ---- Request / Response types ----

/// Query parameters for `GET /balance`.
#[derive(Debug, Deserialize)]
pub struct BalanceQuery {
    /// The EVM address to query (hex, 0x-prefixed).
    pub address: String,
    /// The chain ID to query against.
    pub chain_id: u64,
}

/// A single token balance entry.
#[derive(Debug, Serialize)]
pub struct TokenBalance {
    /// Token symbol (e.g. "USDC").
    pub symbol: String,
    /// Human-readable balance string.
    pub balance: String,
    /// Token contract address.
    pub address: String,
}

/// Response for `GET /balance`.
#[derive(Debug, Serialize)]
pub struct BalanceResponse {
    /// Native ETH balance as a human-readable string.
    pub eth: String,
    /// ERC-20 token balances (empty for now — no token registry yet).
    pub tokens: Vec<TokenBalance>,
}

/// Request body for `POST /transfer`.
#[derive(Debug, Deserialize)]
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

/// Response for `POST /transfer`.
#[derive(Debug, Serialize)]
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

// ---- Handlers ----

/// `GET /health` — simple health check.
pub async fn handle_health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// `GET /balance` — returns ETH balance for the given address and chain.
pub async fn handle_balance(
    State(state): State<AppState>,
    Query(params): Query<BalanceQuery>,
) -> Result<Json<BalanceResponse>, (StatusCode, String)> {
    let adapter = state.adapters.get(&params.chain_id).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("unsupported chain_id: {}", params.chain_id),
        )
    })?;

    let address: clawlet_evm::Address = params
        .address
        .parse()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid address: {e}")))?;

    let wei = adapter
        .get_eth_balance(address)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("rpc error: {e}")))?;

    // Convert wei to ETH string (18 decimals)
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

    Ok(Json(BalanceResponse {
        eth: eth_str,
        tokens: vec![],
    }))
}

/// `POST /transfer` — execute a transfer within policy limits.
pub async fn handle_transfer(
    State(state): State<AppState>,
    Json(req): Json<TransferRequest>,
) -> Result<Json<TransferResponse>, (StatusCode, String)> {
    // For policy check we use the raw amount as USD approximation.
    // A real implementation would fetch price feeds.
    let amount_usd: f64 = req
        .amount
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid amount".to_string()))?;

    // Check policy
    let decision = state
        .policy
        .check_transfer(amount_usd, &req.token, req.chain_id)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("policy error: {e}"),
            )
        })?;

    match decision {
        PolicyDecision::Allowed => {
            // Generate an audit ID
            let audit_id = format!(
                "{:016x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
                    & 0xFFFF_FFFF_FFFF_FFFF
            );

            // Log to audit
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

            // In a full implementation, we would build and send the actual
            // transaction via EvmAdapter + Signer here. For now we return
            // a placeholder tx_hash indicating the transfer was policy-approved.
            let tx_hash = format!("0x{}", "0".repeat(64));

            Ok(Json(TransferResponse {
                status: "success".to_string(),
                tx_hash: Some(tx_hash),
                audit_id: Some(audit_id),
                reason: None,
            }))
        }
        PolicyDecision::Denied(reason) => {
            // Log denial to audit
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

            Ok(Json(TransferResponse {
                status: "denied".to_string(),
                tx_hash: None,
                audit_id: None,
                reason: Some(reason),
            }))
        }
        PolicyDecision::RequiresApproval(reason) => {
            // Log to audit
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

            Ok(Json(TransferResponse {
                status: "denied".to_string(),
                tx_hash: None,
                audit_id: None,
                reason: Some(format!("requires approval: {reason}")),
            }))
        }
    }
}

/// Convert a U256 wei value to a decimal string with the given number of decimals.
fn format_units(value: clawlet_evm::U256, decimals: u32) -> String {
    let s = value.to_string();
    let decimals = decimals as usize;

    if s.len() <= decimals {
        // Value is less than 1 unit
        let zeros = decimals - s.len();
        let mut result = "0.".to_string();
        result.push_str(&"0".repeat(zeros));
        result.push_str(s.trim_start_matches('0'));
        if result.ends_with('.') {
            result.push('0');
        }
        // Handle the zero case
        if value.is_zero() {
            return "0.0".to_string();
        }
        result
    } else {
        let integer_part = &s[..s.len() - decimals];
        let fractional_part = &s[s.len() - decimals..];
        // Trim trailing zeros from fractional part
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
        let wei = U256::from(1_000_000u64); // 0.000000000001 ETH
        let result = format_units(wei, 18);
        assert!(result.starts_with("0."));
    }

    #[test]
    fn format_units_usdc() {
        // 1000 USDC = 1000 * 10^6
        let amount = U256::from(1_000_000_000u64);
        assert_eq!(format_units(amount, 6), "1000.0");
    }
}
