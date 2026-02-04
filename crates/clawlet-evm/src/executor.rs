//! AIS execution engine for EVM actions.

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use alloy::dyn_abi::{DynSolType, DynSolValue, JsonAbiExt, Specifier};
use alloy::json_abi::Function;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::{TransactionReceipt, TransactionRequest};
use thiserror::Error;

use clawlet_core::ais::{AisAction, AisActionType, AisApproval, AisArg, AisSpec};
use clawlet_signer::signer::Signer;

use crate::adapter::{core_address_to_alloy, EvmAdapter};
use crate::token;
use crate::tx;

/// Errors from AIS execution.
#[derive(Debug, Error)]
pub enum AisExecError {
    #[error("missing required param: {0}")]
    MissingParam(String),
    #[error("unknown action id: {0}")]
    UnknownAction(String),
    #[error("template resolution error: {0}")]
    Template(String),
    #[error("function parse error: {0}")]
    FunctionParse(String),
    #[error("ABI encoding error: {0}")]
    Abi(String),
    #[error("invalid action configuration: {0}")]
    InvalidAction(String),
    #[error("adapter error: {0}")]
    Adapter(#[from] crate::adapter::EvmAdapterError),
    #[error("tx error: {0}")]
    Tx(#[from] crate::tx::TxError),
    #[error("token error: {0}")]
    Token(#[from] crate::token::TokenError),
    #[error("RPC error: {0}")]
    Rpc(String),
}

/// Output of a single action execution.
#[derive(Debug, Clone)]
pub struct ActionOutput {
    /// Action id.
    pub id: String,
    /// Transaction hash.
    pub tx_hash: B256,
    /// Transaction receipt (if available).
    pub receipt: Option<TransactionReceipt>,
}

/// Execution context for template resolution.
#[derive(Debug, Clone, Default)]
struct ExecContext {
    params: HashMap<String, String>,
    prev: HashMap<String, String>,
}

/// Execute the full AIS spec and return outputs.
pub async fn execute_spec(
    spec: &AisSpec,
    params: HashMap<String, String>,
    adapter: &EvmAdapter,
    signer: &impl Signer,
) -> Result<Vec<ActionOutput>, AisExecError> {
    let merged_params = merge_params(spec, params)?;
    let mut ctx = ExecContext {
        params: merged_params,
        prev: HashMap::new(),
    };

    let action_map: HashMap<String, AisAction> = spec
        .actions
        .iter()
        .cloned()
        .map(|a| (a.id.clone(), a))
        .collect();

    let mut outputs = Vec::new();
    for action in &spec.actions {
        let mut visiting = Vec::new();
        let expanded = expand_action(action, &action_map, &mut visiting)?;
        for step in expanded {
            let output = execute_evm_call(step, &mut ctx, adapter, signer)
                .await
                .map_err(|e| {
                    AisExecError::InvalidAction(format!("action '{}' failed: {e}", step.id))
                })?;
            ctx.prev.clear();
            ctx.prev.insert(
                "tx_hash".to_string(),
                format!("0x{}", hex::encode(output.tx_hash)),
            );
            if let Some(receipt) = &output.receipt {
                if let Some(block) = receipt.block_number {
                    ctx.prev
                        .insert("block_number".to_string(), block.to_string());
                }
                let status = receipt.status();
                ctx.prev.insert("status".to_string(), status.to_string());
            }
            outputs.push(output);
        }
    }

    Ok(outputs)
}

fn expand_action<'a>(
    action: &'a AisAction,
    action_map: &'a HashMap<String, AisAction>,
    visiting: &mut Vec<String>,
) -> Result<Vec<&'a AisAction>, AisExecError> {
    if visiting.contains(&action.id) {
        return Err(AisExecError::InvalidAction(format!(
            "composite cycle detected at '{}'",
            action.id
        )));
    }

    match action.action_type {
        AisActionType::EvmCall => Ok(vec![action]),
        AisActionType::Composite => {
            let steps = action
                .steps
                .as_ref()
                .ok_or_else(|| AisExecError::InvalidAction("composite missing steps".into()))?;
            visiting.push(action.id.clone());
            let mut out = Vec::new();
            for step_id in steps {
                let step = action_map
                    .get(step_id)
                    .ok_or_else(|| AisExecError::UnknownAction(step_id.clone()))?;
                out.extend(expand_action(step, action_map, visiting)?);
            }
            visiting.pop();
            Ok(out)
        }
    }
}

async fn execute_evm_call(
    action: &AisAction,
    ctx: &mut ExecContext,
    adapter: &EvmAdapter,
    signer: &impl Signer,
) -> Result<ActionOutput, AisExecError> {
    let contract = action
        .contract
        .as_ref()
        .ok_or_else(|| AisExecError::InvalidAction("missing contract".into()))?;
    let function = action
        .function
        .as_ref()
        .ok_or_else(|| AisExecError::InvalidAction("missing function".into()))?;
    let args = action
        .args
        .as_ref()
        .ok_or_else(|| AisExecError::InvalidAction("missing args".into()))?;

    let contract = resolve_template(contract, ctx)?;
    let to: Address = contract
        .parse()
        .map_err(|e| AisExecError::InvalidAction(format!("invalid contract address: {e}")))?;

    let func = Function::parse(function).map_err(|e| AisExecError::FunctionParse(e.to_string()))?;

    let types: Vec<DynSolType> = func
        .inputs
        .iter()
        .map(Specifier::<DynSolType>::resolve)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| AisExecError::Abi(e.to_string()))?;

    if types.len() != args.len() {
        return Err(AisExecError::InvalidAction(format!(
            "arg length mismatch: expected {}, got {}",
            types.len(),
            args.len()
        )));
    }

    let values = args
        .iter()
        .zip(types.iter())
        .map(|(arg, ty)| resolve_arg(arg, ty, ctx))
        .collect::<Result<Vec<_>, _>>()?;

    if action.requires_approval {
        let approval = action.approval.as_ref().ok_or_else(|| {
            AisExecError::InvalidAction("requires_approval missing approval".into())
        })?;
        smart_approve(approval, ctx, adapter, signer).await?;
    }

    let data = func
        .abi_encode_input(&values)
        .map_err(|e| AisExecError::Abi(e.to_string()))?;

    let mut tx_req = TransactionRequest::default()
        .to(to)
        .input(Bytes::from(data).into());

    let chain_id = adapter
        .get_chain_id()
        .await
        .map_err(AisExecError::Adapter)?;
    tx_req.set_chain_id(chain_id);

    let tx_hash = tx::send_transaction(adapter, signer, tx_req).await?;
    let receipt = wait_for_receipt(adapter, tx_hash).await?;

    Ok(ActionOutput {
        id: action.id.clone(),
        tx_hash,
        receipt,
    })
}

async fn smart_approve(
    approval: &AisApproval,
    ctx: &mut ExecContext,
    adapter: &EvmAdapter,
    signer: &impl Signer,
) -> Result<(), AisExecError> {
    let token_str = resolve_template(&approval.token, ctx)?;
    let spender_str = resolve_template(&approval.spender, ctx)?;
    let amount_str = resolve_template(&approval.amount, ctx)?;

    let token_addr: Address = token_str
        .parse()
        .map_err(|e| AisExecError::InvalidAction(format!("invalid token address: {e}")))?;
    let spender: Address = spender_str
        .parse()
        .map_err(|e| AisExecError::InvalidAction(format!("invalid spender address: {e}")))?;
    let amount: U256 = U256::from_str(&amount_str)
        .map_err(|e| AisExecError::InvalidAction(format!("invalid approval amount: {e}")))?;

    let owner = core_address_to_alloy(&signer.address());
    let allowance = token::check_allowance(adapter, owner, spender, token_addr).await?;

    if allowance < amount {
        let tx_hash = token::approve_token(adapter, signer, token_addr, spender, amount).await?;
        let _ = wait_for_receipt(adapter, tx_hash).await?;
    }

    Ok(())
}

async fn wait_for_receipt(
    adapter: &EvmAdapter,
    tx_hash: B256,
) -> Result<Option<TransactionReceipt>, AisExecError> {
    let mut attempts = 0u32;
    loop {
        let receipt = adapter
            .provider()
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(|e| AisExecError::Rpc(e.to_string()))?;
        if receipt.is_some() {
            return Ok(receipt);
        }
        attempts += 1;
        if attempts >= 10 {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn merge_params(
    spec: &AisSpec,
    mut params: HashMap<String, String>,
) -> Result<HashMap<String, String>, AisExecError> {
    for (name, param) in &spec.params {
        if !params.contains_key(name) {
            if let Some(default) = &param.default {
                params.insert(name.clone(), default.clone());
            } else {
                return Err(AisExecError::MissingParam(name.clone()));
            }
        }
    }
    Ok(params)
}

fn resolve_arg(
    arg: &AisArg,
    ty: &DynSolType,
    ctx: &mut ExecContext,
) -> Result<DynSolValue, AisExecError> {
    match (arg, ty) {
        (AisArg::Tuple(tuple), DynSolType::Tuple(inner)) => {
            if tuple.type_name != "tuple" {
                return Err(AisExecError::InvalidAction(
                    "tuple arg missing type: tuple".into(),
                ));
            }
            if tuple.fields.len() != inner.len() {
                return Err(AisExecError::InvalidAction(format!(
                    "tuple field length mismatch: expected {}, got {}",
                    inner.len(),
                    tuple.fields.len()
                )));
            }
            let mut values = Vec::with_capacity(inner.len());
            for (field, field_ty) in tuple.fields.iter().zip(inner.iter()) {
                values.push(resolve_arg(field, field_ty, ctx)?);
            }
            Ok(DynSolValue::Tuple(values))
        }
        (AisArg::Value(value), _) => {
            let resolved = resolve_template(value, ctx)?;
            ty.coerce_str(&resolved)
                .map_err(|e| AisExecError::Abi(e.to_string()))
        }
        (AisArg::Tuple(_), _) => Err(AisExecError::InvalidAction(
            "tuple arg provided for non-tuple type".into(),
        )),
    }
}

fn resolve_template(input: &str, ctx: &ExecContext) -> Result<String, AisExecError> {
    let mut out = String::new();
    let mut rest = input;

    while let Some(start) = rest.find("{{") {
        let (prefix, tail) = rest.split_at(start);
        out.push_str(prefix);
        let Some(end) = tail.find("}}") else {
            return Err(AisExecError::Template("unclosed template".into()));
        };
        let key = tail[2..end].trim();
        let value = if let Some(prev_key) = key.strip_prefix("prev.") {
            ctx.prev
                .get(prev_key)
                .cloned()
                .ok_or_else(|| AisExecError::Template(format!("missing prev.{prev_key}")))?
        } else {
            ctx.params
                .get(key)
                .cloned()
                .ok_or_else(|| AisExecError::Template(format!("missing param {key}")))?
        };
        out.push_str(&value);
        rest = &tail[end + 2..];
    }

    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ExecContext {
        let mut params = HashMap::new();
        params.insert(
            "token".to_string(),
            "0x0000000000000000000000000000000000000001".into(),
        );
        params.insert("amount".to_string(), "1000".into());
        let mut prev = HashMap::new();
        prev.insert("tx_hash".to_string(), "0xabc".into());
        ExecContext { params, prev }
    }

    #[test]
    fn resolve_template_params_and_prev() {
        let ctx = ctx();
        let out = resolve_template("{{token}}", &ctx).unwrap();
        assert_eq!(out, "0x0000000000000000000000000000000000000001");
        let out = resolve_template("hash={{prev.tx_hash}}", &ctx).unwrap();
        assert_eq!(out, "hash=0xabc");
    }

    #[test]
    fn resolve_template_missing() {
        let ctx = ctx();
        let err = resolve_template("{{missing}}", &ctx).unwrap_err();
        assert!(err.to_string().contains("missing param"));
    }

    #[test]
    fn resolve_tuple_arg() {
        let mut ctx = ctx();
        let ty = DynSolType::Tuple(vec![DynSolType::Address, DynSolType::Uint(256)]);
        let arg = AisArg::Tuple(clawlet_core::ais::AisTupleArg {
            type_name: "tuple".into(),
            fields: vec![
                AisArg::Value("{{token}}".into()),
                AisArg::Value("{{amount}}".into()),
            ],
        });
        let value = resolve_arg(&arg, &ty, &mut ctx).unwrap();
        match value {
            DynSolValue::Tuple(values) => {
                assert_eq!(values.len(), 2);
            }
            _ => panic!("expected tuple"),
        }
    }
}
