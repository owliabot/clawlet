//! ERC-20 token helpers for allowance and approvals.

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy::sol_types::SolCall;

use crate::abi::IERC20;
use crate::adapter::EvmAdapter;
use crate::tx;
use clawlet_signer::signer::Signer;

/// Errors from token operations.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("adapter error: {0}")]
    Adapter(#[from] crate::adapter::EvmAdapterError),
    #[error("tx error: {0}")]
    Tx(#[from] crate::tx::TxError),
    #[error("RPC error: {0}")]
    Rpc(String),
}

/// Check ERC-20 allowance for `owner -> spender`.
pub async fn check_allowance(
    adapter: &EvmAdapter,
    owner: Address,
    spender: Address,
    token: Address,
) -> Result<U256, TokenError> {
    let call = IERC20::allowanceCall {
        _owner: owner,
        _spender: spender,
    };
    let data = call.abi_encode();

    let result: Bytes = adapter
        .provider()
        .call(TransactionRequest::default().to(token).input(data.into()))
        .await
        .map_err(|e| TokenError::Rpc(e.to_string()))?;

    let decoded = <IERC20::allowanceCall as SolCall>::abi_decode_returns(&result)
        .map_err(|e| TokenError::Rpc(e.to_string()))?;

    Ok(decoded)
}

/// Approve `spender` to spend `amount` of `token`.
pub async fn approve_token(
    adapter: &EvmAdapter,
    signer: &impl Signer,
    token: Address,
    spender: Address,
    amount: U256,
) -> Result<alloy::primitives::B256, TokenError> {
    let call = IERC20::approveCall {
        _spender: spender,
        _value: amount,
    };
    let data = call.abi_encode();

    let mut tx_req = TransactionRequest::default().to(token).input(data.into());
    // Chain ID must be populated before signing.
    let chain_id = adapter.get_chain_id().await.map_err(TokenError::Adapter)?;
    tx_req.set_chain_id(chain_id);

    let tx_hash = tx::send_transaction(adapter, signer, tx_req).await?;
    Ok(tx_hash)
}
