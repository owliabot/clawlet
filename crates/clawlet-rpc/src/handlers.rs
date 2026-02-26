//! Request handlers for RPC methods.
//!
//! Each handler processes a deserialized request and returns a serialized response.
//! Handlers are transport-agnostic — they work with `&AppState` and serde types.

use serde_json::json;

use alloy::primitives::U256;
use clawlet_core::ais::AisSpec;
use clawlet_core::audit::AuditEvent;
use clawlet_core::chain::SupportedChainId;
use clawlet_core::policy::PolicyDecision;
use clawlet_evm::send_raw_validation::{
    identify_target, validate_liquidity_calldata, validate_nft_position_calldata,
    validate_swap_calldata, validate_weth_calldata, LiquidityValidation, NftPositionValidation,
    SendRawTarget, SwapValidation, WethValidation,
};
use clawlet_evm::tx::{
    build_erc20_transfer, build_eth_transfer, build_raw_tx, send_transaction, RawTxRequest,
    TransferRequest as EvmTransferRequest,
};
use clawlet_signer::Signer;

use crate::server::AppState;
use crate::types::{
    AddressResponse, Amount, BalanceQuery, BalanceResponse, ChainInfo, ChainsResponse,
    ExecuteRequest, ExecuteResponse, ExecuteStatus, HandlerError, SendRawRequest, SendRawResponse,
    SkillSummary, SkillsResponse, TokenSpec, TransferRequest, TransferResponse, TransferStatus,
};

// ---- Handlers ----

/// Health check — always returns `{"status": "ok"}`.
pub fn handle_health(_state: &AppState) -> serde_json::Value {
    json!({ "status": "ok" })
}

/// Returns the list of supported chains with their configuration status.
pub fn handle_chains(state: &AppState) -> Result<ChainsResponse, HandlerError> {
    let mut chains: Vec<ChainInfo> = state
        .adapters
        .keys()
        .map(|&chain_id| ChainInfo {
            chain_id,
            name: crate::types::chain_name(chain_id).into_owned(),
            testnet: crate::types::is_testnet(chain_id),
        })
        .collect();

    // Sort by chain_id for deterministic output
    chains.sort_by_key(|c| c.chain_id);

    Ok(ChainsResponse { chains })
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

/// Send a raw transaction with calldata validation and policy checks.
///
/// Supported target types (see [`SendRawTarget`]):
///
/// 1. **Uniswap V3 SwapRouter02** — `exactInputSingle`, `exactInput`, `exactOutputSingle`, `exactOutput`
/// 2. **Uniswap V2 Router02** — `swapExactTokensForTokens`, `swapExactETHForTokens`, `swapExactTokensForETH`,
///    `addLiquidity`, `addLiquidityETH`, `removeLiquidity`, `removeLiquidityETH`
/// 3. **WETH/WBNB/WMATIC** — `deposit()`, `withdraw(uint256)`
/// 4. **Uniswap V3 NonfungiblePositionManager** — `mint`, `increaseLiquidity`, `decreaseLiquidity`, `collect`, `burn`
///
/// Additionally enforces policy (allowed chains, allowed tokens, etc.).
pub async fn handle_send_raw(
    state: &AppState,
    req: SendRawRequest,
) -> Result<SendRawResponse, HandlerError> {
    let chain_id = req.chain_id;

    // ---- Chain ID validation ----
    let supported_chain = SupportedChainId::try_from(chain_id)
        .map_err(|e| HandlerError::BadRequest(e.to_string()))?;

    // ---- Identify target contract type ----
    let target = match identify_target(req.to, supported_chain) {
        Some(t) => t,
        None => {
            {
                let event = AuditEvent::new(
                    "send_raw",
                    json!({
                        "to": format!("{}", req.to),
                        "chain_id": chain_id,
                    }),
                    format!(
                        "denied: target address {} is not a known Uniswap router, WETH contract, or NonfungiblePositionManager",
                        req.to
                    ),
                );
                if let Ok(mut audit) = state.audit.lock() {
                    let _ = audit.log_event(event);
                }
            }
            return Err(HandlerError::BadRequest(format!(
                "target address {} is not a known Uniswap router, WETH contract, or NonfungiblePositionManager for chain {chain_id}",
                req.to
            )));
        }
    };

    // ---- Operation-specific validation and policy checks ----
    //
    // For router targets we try swap validation first, then liquidity validation.
    // Liquidity operations need two policy checks (one per token), so they are
    // handled via a separate enum variant.
    enum RouterOp {
        Swap {
            operation_type: String,
            token_str: String,
            amount_str: String,
        },
        Liquidity {
            operation_type: String,
            token_a_str: String,
            token_b_str: String,
            amount_str: String,
        },
    }

    let resolved_op = match target {
        target @ (SendRawTarget::UniswapV3Router | SendRawTarget::UniswapV2Router) => {
            // ---- Swap calldata validation ----
            let swap_result = validate_swap_calldata(&req.data, target, supported_chain);

            match swap_result {
                SwapValidation::Allowed(swap_params) => {
                    // ---- Value/function consistency check ----
                    let value = req.value.unwrap_or(U256::ZERO);
                    match swap_params.function.as_str() {
                        "swapExactETHForTokens" => {
                            if value.is_zero() {
                                return Err(HandlerError::BadRequest(
                                    "swapExactETHForTokens requires nonzero msg.value (ETH input)"
                                        .into(),
                                ));
                            }
                        }
                        "swapExactTokensForTokens" | "swapExactTokensForETH" => {
                            if !value.is_zero() {
                                return Err(HandlerError::BadRequest(format!(
                                    "{} is non-payable but req.value is nonzero ({})",
                                    swap_params.function, value
                                )));
                            }
                        }
                        _ => {}
                    }

                    let amount_str = if swap_params.function == "swapExactETHForTokens" {
                        value.to_string()
                    } else {
                        swap_params.amount_in.to_string()
                    };

                    RouterOp::Swap {
                        operation_type: swap_params.function,
                        token_str: format!("{}", swap_params.token_in),
                        amount_str,
                    }
                }
                SwapValidation::NoSelector => {
                    return Err(HandlerError::BadRequest(
                        "send_raw requires calldata with a valid Uniswap router function selector"
                            .into(),
                    ));
                }
                SwapValidation::MalformedArgs { name, reason } => {
                    {
                        let event = AuditEvent::new(
                            "send_raw",
                            json!({
                                "to": format!("{}", req.to),
                                "chain_id": chain_id,
                                "function": name,
                                "decode_error": reason,
                            }),
                            format!("denied: malformed calldata for {name}"),
                        );
                        if let Ok(mut audit) = state.audit.lock() {
                            let _ = audit.log_event(event);
                        }
                    }
                    return Err(HandlerError::BadRequest(format!(
                        "malformed calldata for {name}: ABI decode failed — {reason}"
                    )));
                }
                SwapValidation::Denied { selector } => {
                    // Liquidity functions only exist on V2 routers.
                    // If this is a V3 router, reject immediately.
                    if target == SendRawTarget::UniswapV3Router {
                        let sel_hex = format!(
                            "0x{:02x}{:02x}{:02x}{:02x}",
                            selector[0], selector[1], selector[2], selector[3]
                        );

                        {
                            let event = AuditEvent::new(
                                "send_raw",
                                json!({
                                    "to": format!("{}", req.to),
                                    "chain_id": chain_id,
                                    "selector": sel_hex,
                                }),
                                format!("denied: unsupported V3 function selector {sel_hex}"),
                            );
                            if let Ok(mut audit) = state.audit.lock() {
                                let _ = audit.log_event(event);
                            }
                        }

                        return Err(HandlerError::BadRequest(format!(
                            "function selector {sel_hex} is not allowed; \
                         only Uniswap V3 swap functions are permitted on V3 router"
                        )));
                    }

                    // V2 router — try liquidity validation.
                    match validate_liquidity_calldata(&req.data, supported_chain) {
                        LiquidityValidation::Allowed(liq_params) => {
                            // ---- Value/function consistency check for liquidity ----
                            let value = req.value.unwrap_or(U256::ZERO);
                            match liq_params.function.as_str() {
                                "addLiquidityETH" => {
                                    if value.is_zero() {
                                        return Err(HandlerError::BadRequest(
                                        "addLiquidityETH requires nonzero msg.value (ETH input)"
                                            .into(),
                                    ));
                                    }
                                }
                                "addLiquidity" | "removeLiquidity" | "removeLiquidityETH" => {
                                    if !value.is_zero() {
                                        return Err(HandlerError::BadRequest(format!(
                                            "{} is non-payable but req.value is nonzero ({})",
                                            liq_params.function, value
                                        )));
                                    }
                                }
                                _ => {}
                            }

                            let amount_str = format!(
                                "tokenA={},tokenB={}",
                                liq_params.amount_a, liq_params.amount_b
                            );

                            RouterOp::Liquidity {
                                operation_type: liq_params.function,
                                token_a_str: format!("{}", liq_params.token_a),
                                token_b_str: format!("{}", liq_params.token_b),
                                amount_str,
                            }
                        }
                        LiquidityValidation::MalformedArgs { name, reason } => {
                            {
                                let event = AuditEvent::new(
                                    "send_raw",
                                    json!({
                                        "to": format!("{}", req.to),
                                        "chain_id": chain_id,
                                        "function": name,
                                        "decode_error": reason,
                                    }),
                                    format!("denied: malformed calldata for {name}"),
                                );
                                if let Ok(mut audit) = state.audit.lock() {
                                    let _ = audit.log_event(event);
                                }
                            }
                            return Err(HandlerError::BadRequest(format!(
                                "malformed calldata for {name}: ABI decode failed — {reason}"
                            )));
                        }
                        // Liquidity validation also denied or no selector — report original
                        // swap denial.
                        _ => {
                            let sel_hex = format!(
                                "0x{:02x}{:02x}{:02x}{:02x}",
                                selector[0], selector[1], selector[2], selector[3]
                            );

                            {
                                let event = AuditEvent::new(
                                    "send_raw",
                                    json!({
                                        "to": format!("{}", req.to),
                                        "chain_id": chain_id,
                                        "selector": sel_hex,
                                    }),
                                    format!("denied: unsupported function selector {sel_hex}"),
                                );
                                if let Ok(mut audit) = state.audit.lock() {
                                    let _ = audit.log_event(event);
                                }
                            }

                            return Err(HandlerError::BadRequest(format!(
                                "function selector {sel_hex} is not allowed; \
                             only Uniswap V2/V3 swap and liquidity functions are permitted"
                            )));
                        }
                    }
                }
            }
        }
        SendRawTarget::Weth => {
            // ---- WETH calldata validation ----
            match validate_weth_calldata(&req.data, req.value) {
                WethValidation::Wrap(amount) => RouterOp::Swap {
                    operation_type: "wrap_native".to_string(),
                    token_str: "ETH".to_string(),
                    amount_str: amount.to_string(),
                },
                WethValidation::Unwrap(amount) => {
                    // WETH withdraw is nonpayable — reject if value is sent
                    if req.value.unwrap_or(U256::ZERO) > U256::ZERO {
                        return Err(HandlerError::BadRequest(
                            "WETH withdraw is nonpayable; cannot send value".to_string(),
                        ));
                    }
                    RouterOp::Swap {
                        operation_type: "unwrap_native".to_string(),
                        token_str: format!("{}", req.to),
                        amount_str: amount.to_string(),
                    }
                }
                WethValidation::Invalid { reason } => {
                    {
                        let event = AuditEvent::new(
                            "send_raw",
                            json!({
                                "to": format!("{}", req.to),
                                "chain_id": chain_id,
                                "error": reason,
                            }),
                            format!("denied: invalid WETH calldata — {reason}"),
                        );
                        if let Ok(mut audit) = state.audit.lock() {
                            let _ = audit.log_event(event);
                        }
                    }
                    return Err(HandlerError::BadRequest(format!(
                        "invalid WETH calldata: {reason}"
                    )));
                }
            }
        }
        SendRawTarget::NftPositionManager => {
            // ---- NonfungiblePositionManager calldata validation ----
            match validate_nft_position_calldata(&req.data) {
                NftPositionValidation::Allowed(nft_params) => {
                    // Early reject: decreaseLiquidity/collect/burn should never
                    // carry native value (no refund path since multicall/refundETH
                    // are denied). Check this before any RPC calls.
                    let value = req.value.unwrap_or(U256::ZERO);
                    if !value.is_zero() {
                        match nft_params.function.as_str() {
                            "mint" | "increaseLiquidity" => {} // checked below with token info
                            _ => {
                                return Err(HandlerError::BadRequest(format!(
                                    "{} should not carry native value (no refund path available); got {value}",
                                    nft_params.function
                                )));
                            }
                        }
                    }

                    // Resolve token0/token1 for the position:
                    // - mint: from calldata params
                    // - others: from on-chain positions(tokenId) query
                    let (token0, token1) = if let (Some(t0), Some(t1)) =
                        (nft_params.token0, nft_params.token1)
                    {
                        (t0, t1)
                    } else {
                        let token_id = nft_params.token_id.unwrap_or(U256::ZERO);
                        let adapter = state.adapters.get(&chain_id).ok_or_else(|| {
                            HandlerError::BadRequest(format!("unsupported chain_id: {chain_id}"))
                        })?;
                        adapter
                            .get_nft_position_tokens(req.to, token_id)
                            .await
                            .map_err(|e| {
                                HandlerError::BadRequest(format!(
                                    "failed to query positions({token_id}): {e} — \
                                     the tokenId may be invalid or the position may not exist"
                                ))
                            })?
                    };

                    // ETH stranding prevention for mint/increaseLiquidity:
                    // Only allow value if one of the tokens is the wrapped native token.
                    if !value.is_zero() {
                        let weth = clawlet_evm::send_raw_validation::wrapped_native_address(
                            supported_chain,
                        );
                        let has_native_token = token0 == weth || token1 == weth;
                        if !has_native_token {
                            return Err(HandlerError::BadRequest(format!(
                                "{} with value={value} but neither token is the wrapped native token ({weth}); \
                                 ETH would be stranded (multicall/refundETH are not available)",
                                nft_params.function
                            )));
                        }
                    }

                    if nft_params.token0.is_some() {
                        // mint path
                        RouterOp::Liquidity {
                            operation_type: nft_params.function,
                            token_a_str: format!("{token0}"),
                            token_b_str: format!("{token1}"),
                            amount_str: "position_mint".to_string(),
                        }
                    } else {
                        // increaseLiquidity, decreaseLiquidity, collect, burn
                        let token_id = nft_params.token_id.unwrap_or(U256::ZERO);

                        RouterOp::Liquidity {
                            operation_type: nft_params.function,
                            token_a_str: format!("{token0}"),
                            token_b_str: format!("{token1}"),
                            amount_str: format!("tokenId={token_id}"),
                        }
                    }
                }
                NftPositionValidation::NoSelector => {
                    return Err(HandlerError::BadRequest(
                    "send_raw requires calldata with a valid NonfungiblePositionManager function selector"
                        .into(),
                ));
                }
                NftPositionValidation::MalformedArgs { name, reason } => {
                    {
                        let event = AuditEvent::new(
                            "send_raw",
                            json!({
                                "to": format!("{}", req.to),
                                "chain_id": chain_id,
                                "function": name,
                                "decode_error": reason,
                            }),
                            format!("denied: malformed calldata for {name}"),
                        );
                        if let Ok(mut audit) = state.audit.lock() {
                            let _ = audit.log_event(event);
                        }
                    }
                    return Err(HandlerError::BadRequest(format!(
                        "malformed calldata for {name}: ABI decode failed — {reason}"
                    )));
                }
                NftPositionValidation::Denied { selector } => {
                    let sel_hex = format!(
                        "0x{:02x}{:02x}{:02x}{:02x}",
                        selector[0], selector[1], selector[2], selector[3]
                    );
                    {
                        let event = AuditEvent::new(
                        "send_raw",
                        json!({
                            "to": format!("{}", req.to),
                            "chain_id": chain_id,
                            "selector": sel_hex,
                        }),
                        format!("denied: unsupported NonfungiblePositionManager function selector {sel_hex}"),
                    );
                        if let Ok(mut audit) = state.audit.lock() {
                            let _ = audit.log_event(event);
                        }
                    }
                    return Err(HandlerError::BadRequest(format!(
                    "function selector {sel_hex} is not allowed; \
                     only mint, increaseLiquidity, decreaseLiquidity, collect, and burn are permitted on NonfungiblePositionManager"
                )));
                }
            }
        }
    };

    // ---- Policy check ----
    // For swap/WETH operations: single token policy check.
    // For liquidity operations: dual token policy check (both tokens must pass).
    let (operation_type, token_str, amount_str) = match resolved_op {
        RouterOp::Swap {
            operation_type,
            token_str,
            amount_str,
        } => {
            check_policy(state, &token_str, chain_id, &operation_type, &req)?;
            (operation_type, token_str, amount_str)
        }
        RouterOp::Liquidity {
            operation_type,
            token_a_str,
            token_b_str,
            amount_str,
        } => {
            // Both tokens must pass policy check
            check_policy(state, &token_a_str, chain_id, &operation_type, &req)?;
            check_policy(state, &token_b_str, chain_id, &operation_type, &req)?;

            let token_str = format!("{token_a_str},{token_b_str}");
            (operation_type, token_str, amount_str)
        }
    };

    // ---- Build and send ----
    let adapter = state
        .adapters
        .get(&chain_id)
        .ok_or_else(|| HandlerError::BadRequest(format!("unsupported chain_id: {chain_id}")))?;

    let value = req.value.unwrap_or(U256::ZERO);
    let data = req.data.clone().unwrap_or_default();

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
                "data": req.data.as_ref().map(|b| b.to_string()).unwrap_or_default(),
                "chain_id": chain_id,
                "gas_limit": req.gas_limit,
                "operation": operation_type,
                "token": token_str,
                "amount": amount_str,
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

/// Run a single policy check for one token and return an error if denied.
fn check_policy(
    state: &AppState,
    token_str: &str,
    chain_id: u64,
    operation_type: &str,
    req: &SendRawRequest,
) -> Result<(), HandlerError> {
    let decision = state
        .policy
        .check_transfer(None, token_str, chain_id)
        .map_err(|e| HandlerError::Internal(format!("policy error: {e}")))?;

    match decision {
        PolicyDecision::Allowed => Ok(()),
        PolicyDecision::Denied(reason) => {
            {
                let event = AuditEvent::new(
                    "send_raw",
                    json!({
                        "to": format!("{}", req.to),
                        "chain_id": chain_id,
                        "operation": operation_type,
                        "token": token_str,
                    }),
                    format!("denied: {reason}"),
                );
                if let Ok(mut audit) = state.audit.lock() {
                    let _ = audit.log_event(event);
                }
            }
            Err(HandlerError::BadRequest(format!("policy denied: {reason}")))
        }
        PolicyDecision::RequiresApproval(reason) => {
            {
                let event = AuditEvent::new(
                    "send_raw",
                    json!({
                        "to": format!("{}", req.to),
                        "chain_id": chain_id,
                        "operation": operation_type,
                        "token": token_str,
                    }),
                    format!("requires_approval: {reason}"),
                );
                if let Ok(mut audit) = state.audit.lock() {
                    let _ = audit.log_event(event);
                }
            }
            Err(HandlerError::BadRequest(format!(
                "policy requires approval: {reason}"
            )))
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

    // ---- handle_send_raw tests ----

    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    use clawlet_core::audit::AuditLogger;
    use clawlet_core::policy::{Policy, PolicyEngine};
    use clawlet_evm::EvmAdapter;
    use clawlet_signer::signer::LocalSigner;

    use alloy::primitives::Bytes;
    use alloy::sol_types::SolCall;

    use clawlet_core::chain::SupportedChainId;
    use clawlet_evm::send_raw_validation::{wrapped_native_address, IUniswapV2Router, IWETH};

    use crate::server::AppState;

    /// Helper to create a minimal AppState for testing.
    ///
    /// Uses a permissive policy, dummy audit logger, and an empty adapters map
    /// (tests will fail before needing network if they test validation paths).
    fn mock_app_state() -> (AppState, TempDir) {
        use clawlet_core::auth::SessionStore;
        use clawlet_core::config::AuthConfig;
        use std::sync::RwLock;

        // Create temp dir for audit log
        let temp_dir = TempDir::new().unwrap();
        let audit_path = temp_dir.path().join("audit.jsonl");
        let keystore_path = temp_dir.path().join("keystore");

        // Permissive policy: allow all chains and tokens
        let policy = Policy {
            daily_transfer_limit_usd: 1_000_000.0,
            per_tx_limit_usd: 100_000.0,
            allowed_tokens: vec![], // empty = all allowed
            allowed_chains: vec![], // empty = all allowed
            require_approval_above_usd: None,
        };
        let policy_engine = PolicyEngine::new(policy);

        let audit = AuditLogger::new(&audit_path).unwrap();

        // No adapters — tests will fail before needing network access
        let adapters: HashMap<u64, EvmAdapter> = HashMap::new();

        // Dummy signer (private key for testing only - Anvil test account #0)
        let private_key_bytes: [u8; 32] = [
            0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38,
            0xff, 0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b,
            0xf4, 0xf2, 0xff, 0x80,
        ];
        let signer = LocalSigner::from_bytes(&private_key_bytes).unwrap();

        let session_store = SessionStore::new();
        let auth_config = AuthConfig {
            default_session_ttl_hours: 24,
            max_failed_attempts: 5,
            lockout_minutes: 15,
        };

        let state = AppState {
            policy: Arc::new(policy_engine),
            audit: Arc::new(Mutex::new(audit)),
            adapters: Arc::new(adapters),
            session_store: Arc::new(RwLock::new(session_store)),
            auth_config,
            signer: Arc::new(signer),
            skills_dir: PathBuf::from("skills"),
            keystore_path,
        };

        (state, temp_dir)
    }

    // ---- Target validation ----

    #[tokio::test]
    async fn send_raw_unknown_address_rejected() {
        let (state, _temp) = mock_app_state();

        let unknown_addr: Address = "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap();

        let req = SendRawRequest {
            to: unknown_addr,
            value: None,
            data: Some(Bytes::from(vec![0xde, 0xad, 0xbe, 0xef])),
            chain_id: 1, // Ethereum
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(msg.contains(
                    "not a known Uniswap router, WETH contract, or NonfungiblePositionManager"
                ));
            }
            _ => panic!("expected BadRequest error"),
        }
    }

    // ---- WETH wrap path ----

    #[tokio::test]
    async fn send_raw_weth_wrap_with_deposit_calldata() {
        let (state, _temp) = mock_app_state();

        let weth_addr = wrapped_native_address(SupportedChainId::Ethereum);
        let deposit_call = IWETH::depositCall {};
        let calldata = deposit_call.abi_encode();

        let req = SendRawRequest {
            to: weth_addr,
            value: Some(U256::from(1_000_000_000_000_000_000u64)), // 1 ETH
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        // This should pass validation and policy check, but fail when trying to send
        // (no adapter configured). We're testing that it reaches the "send tx" stage
        // rather than being rejected early.
        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            // Should fail with "unsupported chain_id" since we have no adapters
            HandlerError::BadRequest(msg) => {
                assert!(msg.contains("unsupported chain_id"));
            }
            _ => panic!("expected BadRequest for missing adapter, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_weth_deposit_requires_value() {
        let (state, _temp) = mock_app_state();

        let weth_addr = wrapped_native_address(SupportedChainId::Ethereum);
        let deposit_call = IWETH::depositCall {};
        let calldata = deposit_call.abi_encode();

        let req = SendRawRequest {
            to: weth_addr,
            value: Some(U256::ZERO), // No value
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(msg.contains("deposit() requires value > 0"));
            }
            _ => panic!("expected BadRequest error"),
        }
    }

    #[tokio::test]
    async fn send_raw_weth_fallback_deposit() {
        let (state, _temp) = mock_app_state();

        let weth_addr = wrapped_native_address(SupportedChainId::Ethereum);

        let req = SendRawRequest {
            to: weth_addr,
            value: Some(U256::from(1_000_000_000_000_000_000u64)), // 1 ETH
            data: Some(Bytes::new()),                              // Empty calldata
            chain_id: 1,
            gas_limit: None,
        };

        // Should pass validation and fail at adapter stage
        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(msg.contains("unsupported chain_id"));
            }
            _ => panic!("expected BadRequest for missing adapter"),
        }
    }

    // ---- WETH unwrap path ----

    #[tokio::test]
    async fn send_raw_weth_unwrap() {
        let (state, _temp) = mock_app_state();

        let weth_addr = wrapped_native_address(SupportedChainId::Ethereum);
        let withdraw_call = IWETH::withdrawCall {
            wad: U256::from(1_000_000_000_000_000_000u64), // 1 WETH
        };
        let calldata = withdraw_call.abi_encode();

        let req = SendRawRequest {
            to: weth_addr,
            value: Some(U256::ZERO), // No value (nonpayable)
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        // Should pass validation and fail at adapter stage
        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(msg.contains("unsupported chain_id"));
            }
            _ => panic!("expected BadRequest for missing adapter"),
        }
    }

    #[tokio::test]
    async fn send_raw_weth_unwrap_nonpayable() {
        let (state, _temp) = mock_app_state();

        let weth_addr = wrapped_native_address(SupportedChainId::Ethereum);
        let withdraw_call = IWETH::withdrawCall {
            wad: U256::from(1_000_000_000_000_000_000u64),
        };
        let calldata = withdraw_call.abi_encode();

        let req = SendRawRequest {
            to: weth_addr,
            value: Some(U256::from(100u64)), // Sending value to nonpayable function
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(msg.contains("WETH withdraw is nonpayable"));
            }
            _ => panic!("expected BadRequest error"),
        }
    }

    #[tokio::test]
    async fn send_raw_weth_unwrap_zero_amount() {
        let (state, _temp) = mock_app_state();

        let weth_addr = wrapped_native_address(SupportedChainId::Ethereum);
        let withdraw_call = IWETH::withdrawCall { wad: U256::ZERO };
        let calldata = withdraw_call.abi_encode();

        let req = SendRawRequest {
            to: weth_addr,
            value: None,
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(msg.contains("withdraw amount must be > 0"));
            }
            _ => panic!("expected BadRequest error"),
        }
    }

    // ---- Swap value/payability (V2) ----

    #[tokio::test]
    async fn send_raw_v2_swap_exact_eth_requires_value() {
        let (state, _temp) = mock_app_state();

        // Use Ethereum V2 router address
        let router_v2: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
            .parse()
            .unwrap();
        let weth = wrapped_native_address(SupportedChainId::Ethereum);
        let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();

        let call = IUniswapV2Router::swapExactETHForTokensCall {
            amountOutMin: U256::from(1000u64),
            path: vec![weth, usdc],
            to: state.signer.address(),
            deadline: U256::from(9999999999u64),
        };
        let calldata = call.abi_encode();

        let req = SendRawRequest {
            to: router_v2,
            value: Some(U256::ZERO), // No value sent
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(msg.contains("swapExactETHForTokens requires nonzero msg.value"));
            }
            _ => panic!("expected BadRequest error"),
        }
    }

    #[tokio::test]
    async fn send_raw_v2_swap_exact_tokens_nonpayable() {
        let (state, _temp) = mock_app_state();

        let router_v2: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
            .parse()
            .unwrap();
        let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();
        let dai: Address = "0x6B175474E89094C44Da98b954EedeAC495271d0F"
            .parse()
            .unwrap();

        let call = IUniswapV2Router::swapExactTokensForTokensCall {
            amountIn: U256::from(1_000_000u64),
            amountOutMin: U256::from(1u64),
            path: vec![usdc, dai],
            to: state.signer.address(),
            deadline: U256::from(9999999999u64),
        };
        let calldata = call.abi_encode();

        let req = SendRawRequest {
            to: router_v2,
            value: Some(U256::from(1_000_000_000u64)), // Sending value to nonpayable
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(msg.contains("is non-payable but req.value is nonzero"));
            }
            _ => panic!("expected BadRequest error"),
        }
    }

    // ---- Invalid calldata ----

    #[tokio::test]
    async fn send_raw_router_unknown_selector() {
        let (state, _temp) = mock_app_state();

        let router_v2: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
            .parse()
            .unwrap();

        let req = SendRawRequest {
            to: router_v2,
            value: None,
            data: Some(Bytes::from(vec![0xde, 0xad, 0xbe, 0xef])), // Unknown selector
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(msg.contains("is not allowed"));
            }
            _ => panic!("expected BadRequest error"),
        }
    }

    #[tokio::test]
    async fn send_raw_weth_approve_rejected() {
        let (state, _temp) = mock_app_state();

        let weth_addr = wrapped_native_address(SupportedChainId::Ethereum);

        // ERC20 approve selector: 0x095ea7b3
        let spender: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let amount = U256::from(1_000_000u64);

        // Manually construct approve calldata
        let mut calldata = vec![0x09, 0x5e, 0xa7, 0xb3]; // approve selector
        calldata.extend_from_slice(&[0u8; 12]); // padding
        calldata.extend_from_slice(spender.as_slice());
        calldata.extend_from_slice(&amount.to_be_bytes::<32>());

        let req = SendRawRequest {
            to: weth_addr,
            value: None,
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(msg.contains("only deposit and withdraw functions are allowed"));
            }
            _ => panic!("expected BadRequest error"),
        }
    }

    // ---- Chain validation ----

    #[tokio::test]
    async fn send_raw_unsupported_chain_id() {
        let (state, _temp) = mock_app_state();

        let weth_addr = wrapped_native_address(SupportedChainId::Ethereum);
        let deposit_call = IWETH::depositCall {};
        let calldata = deposit_call.abi_encode();

        let req = SendRawRequest {
            to: weth_addr,
            value: Some(U256::from(1_000_000_000_000_000_000u64)),
            data: Some(Bytes::from(calldata)),
            chain_id: 99999, // Unsupported chain
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(msg.contains("unsupported chain"));
            }
            _ => panic!("expected BadRequest error"),
        }
    }

    // ---- Router NoSelector / MalformedArgs tests ----

    #[tokio::test]
    async fn send_raw_router_empty_calldata() {
        let (state, _temp) = mock_app_state();

        // Uniswap V3 router on Ethereum
        let router_v3: Address = "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"
            .parse()
            .unwrap();

        let req = SendRawRequest {
            to: router_v3,
            value: None,
            data: Some(Bytes::new()), // Empty calldata
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(msg.contains("requires calldata with a valid"));
            }
            _ => panic!("expected BadRequest error for empty calldata"),
        }
    }

    #[tokio::test]
    async fn send_raw_router_none_calldata() {
        let (state, _temp) = mock_app_state();

        // Uniswap V2 router on Ethereum
        let router_v2: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
            .parse()
            .unwrap();

        let req = SendRawRequest {
            to: router_v2,
            value: None,
            data: None, // No calldata
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(msg.contains("requires calldata with a valid"));
            }
            _ => panic!("expected BadRequest error for None calldata"),
        }
    }

    #[tokio::test]
    async fn send_raw_router_malformed_args() {
        let (state, _temp) = mock_app_state();

        // Uniswap V3 router on Ethereum
        let router_v3: Address = "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"
            .parse()
            .unwrap();

        // exactInputSingle selector (0x04e45aaf) + garbage bytes
        let mut malformed_calldata = vec![0x04, 0xe4, 0x5a, 0xaf];
        malformed_calldata.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // Not valid ABI encoding

        let req = SendRawRequest {
            to: router_v3,
            value: None,
            data: Some(Bytes::from(malformed_calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(msg.contains("malformed calldata"));
                assert!(msg.contains("ABI decode failed"));
            }
            _ => panic!("expected BadRequest error for malformed args"),
        }
    }

    // ---- Helper for restrictive policy ----

    /// Helper to create a restrictive AppState for testing policy denial.
    ///
    /// Uses a restrictive policy with allowed_tokens limited to only USDC,
    /// which excludes ETH and WETH.
    fn mock_app_state_restrictive() -> (AppState, TempDir) {
        use clawlet_core::auth::SessionStore;
        use clawlet_core::config::AuthConfig;
        use std::sync::RwLock;

        let temp_dir = TempDir::new().unwrap();
        let audit_path = temp_dir.path().join("audit.jsonl");
        let keystore_path = temp_dir.path().join("keystore");

        // Restrictive policy: only USDC allowed (excludes ETH and WETH)
        let policy = Policy {
            daily_transfer_limit_usd: 1_000_000.0,
            per_tx_limit_usd: 100_000.0,
            allowed_tokens: vec!["USDC".to_string()], // Only USDC, no ETH or WETH
            allowed_chains: vec![],                   // All chains allowed
            require_approval_above_usd: None,
        };
        let policy_engine = PolicyEngine::new(policy);

        let audit = AuditLogger::new(&audit_path).unwrap();
        let adapters: HashMap<u64, EvmAdapter> = HashMap::new();

        let private_key_bytes: [u8; 32] = [
            0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38,
            0xff, 0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b,
            0xf4, 0xf2, 0xff, 0x80,
        ];
        let signer = LocalSigner::from_bytes(&private_key_bytes).unwrap();

        let session_store = SessionStore::new();
        let auth_config = AuthConfig {
            default_session_ttl_hours: 24,
            max_failed_attempts: 5,
            lockout_minutes: 15,
        };

        let state = AppState {
            policy: Arc::new(policy_engine),
            audit: Arc::new(Mutex::new(audit)),
            adapters: Arc::new(adapters),
            session_store: Arc::new(RwLock::new(session_store)),
            auth_config,
            signer: Arc::new(signer),
            skills_dir: PathBuf::from("skills"),
            keystore_path,
        };

        (state, temp_dir)
    }

    // ---- Policy deny path tests ----

    #[tokio::test]
    async fn send_raw_weth_wrap_policy_denied() {
        let (state, _temp) = mock_app_state_restrictive();

        let weth_addr = wrapped_native_address(SupportedChainId::Ethereum);
        let deposit_call = IWETH::depositCall {};
        let calldata = deposit_call.abi_encode();

        let req = SendRawRequest {
            to: weth_addr,
            value: Some(U256::from(1_000_000_000_000_000_000u64)), // 1 ETH
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(msg.contains("policy denied"));
            }
            _ => panic!("expected BadRequest error for policy denial, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_weth_unwrap_policy_denied() {
        let (state, _temp) = mock_app_state_restrictive();

        let weth_addr = wrapped_native_address(SupportedChainId::Ethereum);
        let withdraw_call = IWETH::withdrawCall {
            wad: U256::from(1_000_000_000_000_000_000u64), // 1 WETH
        };
        let calldata = withdraw_call.abi_encode();

        let req = SendRawRequest {
            to: weth_addr,
            value: None,
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(msg.contains("policy denied"));
            }
            _ => panic!("expected BadRequest error for policy denial, got {:?}", err),
        }
    }

    // ---- Liquidity operation tests ----

    #[tokio::test]
    async fn send_raw_add_liquidity_passes_validation() {
        let (state, _temp) = mock_app_state();

        let router_v2: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
            .parse()
            .unwrap();
        let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();
        let dai: Address = "0x6B175474E89094C44Da98b954EedeAC495271d0F"
            .parse()
            .unwrap();

        let call = IUniswapV2Router::addLiquidityCall {
            tokenA: usdc,
            tokenB: dai,
            amountADesired: U256::from(1_000_000u64),
            amountBDesired: U256::from(1_000_000_000_000_000_000u64),
            amountAMin: U256::from(900_000u64),
            amountBMin: U256::from(900_000_000_000_000_000u64),
            to: state.signer.address(),
            deadline: U256::from(9999999999u64),
        };
        let calldata = call.abi_encode();

        let req = SendRawRequest {
            to: router_v2,
            value: Some(U256::ZERO), // addLiquidity is non-payable
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        // Should pass validation and fail at adapter stage
        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("unsupported chain_id"),
                    "expected missing adapter error, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest for missing adapter, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_add_liquidity_nonpayable() {
        let (state, _temp) = mock_app_state();

        let router_v2: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
            .parse()
            .unwrap();
        let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();
        let dai: Address = "0x6B175474E89094C44Da98b954EedeAC495271d0F"
            .parse()
            .unwrap();

        let call = IUniswapV2Router::addLiquidityCall {
            tokenA: usdc,
            tokenB: dai,
            amountADesired: U256::from(1_000_000u64),
            amountBDesired: U256::from(1_000_000_000_000_000_000u64),
            amountAMin: U256::from(900_000u64),
            amountBMin: U256::from(900_000_000_000_000_000u64),
            to: state.signer.address(),
            deadline: U256::from(9999999999u64),
        };
        let calldata = call.abi_encode();

        let req = SendRawRequest {
            to: router_v2,
            value: Some(U256::from(1_000_000u64)), // Sending value to nonpayable
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("is non-payable but req.value is nonzero"),
                    "expected nonpayable error, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest error, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_add_liquidity_eth_requires_value() {
        let (state, _temp) = mock_app_state();

        let router_v2: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
            .parse()
            .unwrap();
        let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();

        let call = IUniswapV2Router::addLiquidityETHCall {
            token: usdc,
            amountTokenDesired: U256::from(1_000_000u64),
            amountTokenMin: U256::from(900_000u64),
            amountETHMin: U256::from(900_000_000_000_000_000u64),
            to: state.signer.address(),
            deadline: U256::from(9999999999u64),
        };
        let calldata = call.abi_encode();

        let req = SendRawRequest {
            to: router_v2,
            value: Some(U256::ZERO), // No value sent
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("addLiquidityETH requires nonzero msg.value"),
                    "expected payable error, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest error, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_add_liquidity_eth_passes_validation() {
        let (state, _temp) = mock_app_state();

        let router_v2: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
            .parse()
            .unwrap();
        let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();

        let call = IUniswapV2Router::addLiquidityETHCall {
            token: usdc,
            amountTokenDesired: U256::from(1_000_000u64),
            amountTokenMin: U256::from(900_000u64),
            amountETHMin: U256::from(900_000_000_000_000_000u64),
            to: state.signer.address(),
            deadline: U256::from(9999999999u64),
        };
        let calldata = call.abi_encode();

        let req = SendRawRequest {
            to: router_v2,
            value: Some(U256::from(1_000_000_000_000_000_000u64)), // 1 ETH
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        // Should pass validation and fail at adapter stage
        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("unsupported chain_id"),
                    "expected missing adapter error, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest for missing adapter, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_remove_liquidity_passes_validation() {
        let (state, _temp) = mock_app_state();

        let router_v2: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
            .parse()
            .unwrap();
        let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();
        let dai: Address = "0x6B175474E89094C44Da98b954EedeAC495271d0F"
            .parse()
            .unwrap();

        let call = IUniswapV2Router::removeLiquidityCall {
            tokenA: usdc,
            tokenB: dai,
            liquidity: U256::from(500_000u64),
            amountAMin: U256::from(450_000u64),
            amountBMin: U256::from(450_000_000_000_000_000u64),
            to: state.signer.address(),
            deadline: U256::from(9999999999u64),
        };
        let calldata = call.abi_encode();

        let req = SendRawRequest {
            to: router_v2,
            value: Some(U256::ZERO), // removeLiquidity is non-payable
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("unsupported chain_id"),
                    "expected missing adapter error, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest for missing adapter, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_remove_liquidity_eth_passes_validation() {
        let (state, _temp) = mock_app_state();

        let router_v2: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
            .parse()
            .unwrap();
        let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();

        let call = IUniswapV2Router::removeLiquidityETHCall {
            token: usdc,
            liquidity: U256::from(500_000u64),
            amountTokenMin: U256::from(450_000u64),
            amountETHMin: U256::from(450_000_000_000_000_000u64),
            to: state.signer.address(),
            deadline: U256::from(9999999999u64),
        };
        let calldata = call.abi_encode();

        let req = SendRawRequest {
            to: router_v2,
            value: Some(U256::ZERO), // removeLiquidityETH is non-payable
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("unsupported chain_id"),
                    "expected missing adapter error, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest for missing adapter, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_remove_liquidity_nonpayable() {
        let (state, _temp) = mock_app_state();

        let router_v2: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
            .parse()
            .unwrap();
        let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();
        let dai: Address = "0x6B175474E89094C44Da98b954EedeAC495271d0F"
            .parse()
            .unwrap();

        let call = IUniswapV2Router::removeLiquidityCall {
            tokenA: usdc,
            tokenB: dai,
            liquidity: U256::from(500_000u64),
            amountAMin: U256::from(1u64),
            amountBMin: U256::from(1u64),
            to: state.signer.address(),
            deadline: U256::from(9999999999u64),
        };
        let calldata = call.abi_encode();

        let req = SendRawRequest {
            to: router_v2,
            value: Some(U256::from(100u64)), // Sending value to nonpayable
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("is non-payable but req.value is nonzero"),
                    "expected nonpayable error, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest error, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_remove_liquidity_eth_nonpayable() {
        let (state, _temp) = mock_app_state();

        let router_v2: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
            .parse()
            .unwrap();
        let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();

        let call = IUniswapV2Router::removeLiquidityETHCall {
            token: usdc,
            liquidity: U256::from(500_000u64),
            amountTokenMin: U256::from(1u64),
            amountETHMin: U256::from(1u64),
            to: state.signer.address(),
            deadline: U256::from(9999999999u64),
        };
        let calldata = call.abi_encode();

        let req = SendRawRequest {
            to: router_v2,
            value: Some(U256::from(100u64)), // Sending value to nonpayable
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("is non-payable but req.value is nonzero"),
                    "expected nonpayable error, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest error, got {:?}", err),
        }
    }

    // ---- Liquidity policy deny tests (dual-token check) ----

    #[tokio::test]
    async fn send_raw_add_liquidity_policy_denied_token_a() {
        // Restrictive policy: only USDC allowed.
        // addLiquidity with DAI+WETH should be denied because WETH is not in allowed_tokens.
        let (state, _temp) = mock_app_state_restrictive();

        let router_v2: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
            .parse()
            .unwrap();
        let weth = wrapped_native_address(SupportedChainId::Ethereum);
        let dai: Address = "0x6B175474E89094C44Da98b954EedeAC495271d0F"
            .parse()
            .unwrap();

        let call = IUniswapV2Router::addLiquidityCall {
            tokenA: dai,
            tokenB: weth,
            amountADesired: U256::from(1_000_000u64),
            amountBDesired: U256::from(1_000_000u64),
            amountAMin: U256::from(1u64),
            amountBMin: U256::from(1u64),
            to: state.signer.address(),
            deadline: U256::from(9999999999u64),
        };
        let calldata = call.abi_encode();

        let req = SendRawRequest {
            to: router_v2,
            value: Some(U256::ZERO),
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("policy denied"),
                    "expected policy denied error, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest error for policy denial, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_add_liquidity_eth_policy_denied_weth() {
        // Restrictive policy: only USDC allowed.
        // addLiquidityETH with USDC+WETH: token_a (USDC) passes, but token_b (WETH) should fail.
        let (state, _temp) = mock_app_state_restrictive();

        let router_v2: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
            .parse()
            .unwrap();
        let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();

        let call = IUniswapV2Router::addLiquidityETHCall {
            token: usdc,
            amountTokenDesired: U256::from(1_000_000u64),
            amountTokenMin: U256::from(1u64),
            amountETHMin: U256::from(1u64),
            to: state.signer.address(),
            deadline: U256::from(9999999999u64),
        };
        let calldata = call.abi_encode();

        let req = SendRawRequest {
            to: router_v2,
            value: Some(U256::from(1_000_000_000_000_000_000u64)), // 1 ETH
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                // token_a (USDC) passes but token_b (WETH address) should be denied
                assert!(
                    msg.contains("policy denied"),
                    "expected policy denied error for WETH, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest error for policy denial, got {:?}", err),
        }
    }

    // ---- NonfungiblePositionManager handler tests ----

    use clawlet_evm::send_raw_validation::{
        nft_position_manager_address, INonfungiblePositionManager,
    };

    #[tokio::test]
    async fn send_raw_nft_pm_mint_passes_validation() {
        let (state, _temp) = mock_app_state();

        let nft_pm = nft_position_manager_address(SupportedChainId::Ethereum);
        let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();
        let weth = wrapped_native_address(SupportedChainId::Ethereum);

        let call = INonfungiblePositionManager::mintCall {
            params: INonfungiblePositionManager::MintParams {
                token0: weth,
                token1: usdc,
                fee: alloy::primitives::Uint::from(3000u32),
                tickLower: alloy::primitives::Signed::try_from(-887220i32).unwrap(),
                tickUpper: alloy::primitives::Signed::try_from(887220i32).unwrap(),
                amount0Desired: U256::from(1_000_000_000_000_000_000u64),
                amount1Desired: U256::from(1_000_000u64),
                amount0Min: U256::ZERO,
                amount1Min: U256::ZERO,
                recipient: state.signer.address(),
                deadline: U256::from(9999999999u64),
            },
        };
        let calldata = call.abi_encode();

        let req = SendRawRequest {
            to: nft_pm,
            value: Some(U256::from(1_000_000_000_000_000_000u64)), // mint is payable
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        // Should pass validation and fail at adapter stage
        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("unsupported chain_id"),
                    "expected missing adapter error, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest for missing adapter, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_nft_pm_mint_policy_denied() {
        let (state, _temp) = mock_app_state_restrictive();

        let nft_pm = nft_position_manager_address(SupportedChainId::Ethereum);
        let weth = wrapped_native_address(SupportedChainId::Ethereum);
        let dai: Address = "0x6B175474E89094C44Da98b954EedeAC495271d0F"
            .parse()
            .unwrap();

        let call = INonfungiblePositionManager::mintCall {
            params: INonfungiblePositionManager::MintParams {
                token0: weth,
                token1: dai,
                fee: alloy::primitives::Uint::from(3000u32),
                tickLower: alloy::primitives::Signed::try_from(-887220i32).unwrap(),
                tickUpper: alloy::primitives::Signed::try_from(887220i32).unwrap(),
                amount0Desired: U256::from(1_000_000_000_000_000_000u64),
                amount1Desired: U256::from(1_000_000_000_000_000_000u64),
                amount0Min: U256::ZERO,
                amount1Min: U256::ZERO,
                recipient: state.signer.address(),
                deadline: U256::from(9999999999u64),
            },
        };
        let calldata = call.abi_encode();

        let req = SendRawRequest {
            to: nft_pm,
            value: Some(U256::from(1_000_000_000_000_000_000u64)),
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("policy denied"),
                    "expected policy denied error, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest error for policy denial, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_nft_pm_collect_passes_validation() {
        let (state, _temp) = mock_app_state();

        let nft_pm = nft_position_manager_address(SupportedChainId::Ethereum);

        let call = INonfungiblePositionManager::collectCall {
            params: INonfungiblePositionManager::CollectParams {
                tokenId: U256::from(42u64),
                recipient: state.signer.address(),
                amount0Max: u128::MAX,
                amount1Max: u128::MAX,
            },
        };
        let calldata = call.abi_encode();

        let req = SendRawRequest {
            to: nft_pm,
            value: Some(U256::ZERO),
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        // Should pass validation (no token policy check) and fail at adapter stage
        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("unsupported chain_id"),
                    "expected missing adapter error, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest for missing adapter, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_nft_pm_collect_queries_position_tokens() {
        // collect now queries on-chain positions(tokenId) for token policy check;
        // with no adapter configured, it fails at the adapter lookup stage
        let (state, _temp) = mock_app_state_restrictive();

        let nft_pm = nft_position_manager_address(SupportedChainId::Ethereum);

        let call = INonfungiblePositionManager::collectCall {
            params: INonfungiblePositionManager::CollectParams {
                tokenId: U256::from(42u64),
                recipient: state.signer.address(),
                amount0Max: u128::MAX,
                amount1Max: u128::MAX,
            },
        };
        let calldata = call.abi_encode();

        let req = SendRawRequest {
            to: nft_pm,
            value: Some(U256::ZERO),
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        // Should pass validation and policy (no token check), fail at adapter
        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("unsupported chain_id"),
                    "expected missing adapter error, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest for missing adapter, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_nft_pm_burn_rejects_value() {
        // burn should reject nonzero value (no refund path since multicall/refundETH are denied)
        // The early check catches this before any adapter/RPC calls
        let (state, _temp) = mock_app_state();

        let nft_pm = nft_position_manager_address(SupportedChainId::Ethereum);

        let call = INonfungiblePositionManager::burnCall {
            tokenId: U256::from(7u64),
        };
        let calldata = call.abi_encode();

        let req = SendRawRequest {
            to: nft_pm,
            value: Some(U256::from(100u64)),
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("should not carry native value"),
                    "expected value rejection, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest error, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_nft_pm_burn_zero_value_passes() {
        // burn with zero value should pass validation
        let (state, _temp) = mock_app_state();

        let nft_pm = nft_position_manager_address(SupportedChainId::Ethereum);

        let call = INonfungiblePositionManager::burnCall {
            tokenId: U256::from(7u64),
        };
        let calldata = call.abi_encode();

        let req = SendRawRequest {
            to: nft_pm,
            value: Some(U256::ZERO),
            data: Some(Bytes::from(calldata)),
            chain_id: 1,
            gas_limit: None,
        };

        // Should pass value check, fail at adapter lookup
        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("unsupported chain_id"),
                    "expected missing adapter error, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest for missing adapter, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_nft_pm_unknown_selector() {
        let (state, _temp) = mock_app_state();

        let nft_pm = nft_position_manager_address(SupportedChainId::Ethereum);

        let req = SendRawRequest {
            to: nft_pm,
            value: None,
            data: Some(Bytes::from(vec![0xde, 0xad, 0xbe, 0xef])),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("is not allowed"),
                    "expected denied error, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest error, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_nft_pm_empty_calldata() {
        let (state, _temp) = mock_app_state();

        let nft_pm = nft_position_manager_address(SupportedChainId::Ethereum);

        let req = SendRawRequest {
            to: nft_pm,
            value: None,
            data: Some(Bytes::new()),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("requires calldata with a valid NonfungiblePositionManager"),
                    "expected no selector error, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest error, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_nft_pm_mint_value_on_non_weth_pair_rejected() {
        // mint with value > 0 but neither token is WETH → ETH would strand
        let (state, _temp) = mock_app_state();

        let nft_pm = nft_position_manager_address(SupportedChainId::Ethereum);
        let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();
        let dai: Address = "0x6B175474E89094C44Da98b954EedeAC495271d0F"
            .parse()
            .unwrap();

        let call = INonfungiblePositionManager::mintCall {
            params: INonfungiblePositionManager::MintParams {
                token0: dai,
                token1: usdc,
                fee: alloy::primitives::Uint::from(500u32),
                tickLower: alloy::primitives::Signed::try_from(-887220i32).unwrap(),
                tickUpper: alloy::primitives::Signed::try_from(887220i32).unwrap(),
                amount0Desired: U256::from(1_000_000_000_000_000_000u64),
                amount1Desired: U256::from(1_000_000u64),
                amount0Min: U256::ZERO,
                amount1Min: U256::ZERO,
                recipient: state.signer.address(),
                deadline: U256::from(9999999999u64),
            },
        };

        let req = SendRawRequest {
            to: nft_pm,
            value: Some(U256::from(1_000_000_000_000_000_000u64)), // 1 ETH
            data: Some(Bytes::from(call.abi_encode())),
            chain_id: 1,
            gas_limit: None,
        };

        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("neither token is the wrapped native token"),
                    "expected ETH stranding error, got: {msg}"
                );
            }
            _ => panic!("expected BadRequest error, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn send_raw_nft_pm_mint_value_on_weth_pair_passes() {
        // mint with value > 0 and one token is WETH → should pass validation
        let (state, _temp) = mock_app_state();

        let nft_pm = nft_position_manager_address(SupportedChainId::Ethereum);
        let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();
        let weth = wrapped_native_address(SupportedChainId::Ethereum);

        let call = INonfungiblePositionManager::mintCall {
            params: INonfungiblePositionManager::MintParams {
                token0: usdc,
                token1: weth,
                fee: alloy::primitives::Uint::from(3000u32),
                tickLower: alloy::primitives::Signed::try_from(-887220i32).unwrap(),
                tickUpper: alloy::primitives::Signed::try_from(887220i32).unwrap(),
                amount0Desired: U256::from(1_000_000u64),
                amount1Desired: U256::from(1_000_000_000_000_000_000u64),
                amount0Min: U256::ZERO,
                amount1Min: U256::ZERO,
                recipient: state.signer.address(),
                deadline: U256::from(9999999999u64),
            },
        };

        let req = SendRawRequest {
            to: nft_pm,
            value: Some(U256::from(1_000_000_000_000_000_000u64)), // 1 ETH
            data: Some(Bytes::from(call.abi_encode())),
            chain_id: 1,
            gas_limit: None,
        };

        // Should pass value check, fail at adapter lookup (unsupported chain_id)
        let result = handle_send_raw(&state, req).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            HandlerError::BadRequest(msg) => {
                assert!(
                    msg.contains("unsupported chain_id"),
                    "expected missing adapter error (value check should pass), got: {msg}"
                );
            }
            _ => panic!("expected BadRequest for missing adapter, got {:?}", err),
        }
    }

    // NOTE: increaseLiquidity value checks require an adapter (to query positions()),
    // so they are tested in the anvil fork integration tests rather than here.
    // See tests/integration/src/lib.rs: test_nft_pm_send_raw_collect_policy_denied
    // TODO: ETH overpay prevention — currently we only check that at least one token
    // is WETH when value > 0, but don't cap value at the actual amount needed.
    // Excess ETH would strand in the NonfungiblePositionManager contract since
    // multicall/refundETH are denied. This requires parsing amountDesired fields
    // and accounting for slippage, so it's deferred as a follow-up.
}
