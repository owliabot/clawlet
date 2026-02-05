//! Transaction building and broadcasting.
//!
//! Constructs EVM transactions and submits them to the network.

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, TxKind, U256};
use alloy::rpc::types::TransactionRequest;
use alloy::sol_types::SolCall;
use sha3::{Digest, Keccak256};
use thiserror::Error;

use crate::abi::IERC20;
use crate::adapter::EvmAdapter;
use clawlet_signer::signer::Signer;

/// Errors from transaction operations.
#[derive(Debug, Error)]
pub enum TxError {
    #[error("adapter error: {0}")]
    Adapter(#[from] crate::adapter::EvmAdapterError),
    #[error("signer error: {0}")]
    Signer(String),
    #[error("RPC send error: {0}")]
    Send(String),
}

/// Result alias for transaction operations.
pub type Result<T> = std::result::Result<T, TxError>;

/// A request to transfer ETH.
#[derive(Debug, Clone)]
pub struct TransferRequest {
    /// Recipient address.
    pub to: Address,
    /// Value in wei.
    pub value: U256,
    /// Chain ID.
    pub chain_id: u64,
    /// Optional gas limit override.
    pub gas_limit: Option<u64>,
}

/// Builds a simple ETH transfer transaction request.
pub fn build_eth_transfer(req: &TransferRequest) -> TransactionRequest {
    let mut tx = TransactionRequest::default().to(req.to).value(req.value);

    tx.set_chain_id(req.chain_id);

    if let Some(gas) = req.gas_limit {
        tx = tx.gas_limit(gas);
    }

    tx
}

/// Builds an ERC-20 `transfer(to, amount)` transaction request.
pub fn build_erc20_transfer(
    token: Address,
    to: Address,
    amount: U256,
    chain_id: u64,
) -> TransactionRequest {
    let call = IERC20::transferCall { to, amount };
    let data = call.abi_encode();

    let mut tx = TransactionRequest::default()
        .to(token)
        .input(Bytes::from(data).into());

    tx.set_chain_id(chain_id);
    tx
}

/// Signs a transaction using the clawlet Signer and broadcasts it via the adapter.
///
/// This function:
/// 1. Populates missing fields (nonce, gas, fees) via the adapter's provider
/// 2. Signs the transaction hash with the provided signer (EIP-155 legacy tx)
/// 3. Submits the raw signed transaction to the network
///
/// Returns the transaction hash on success.
pub async fn send_transaction(
    adapter: &EvmAdapter,
    signer: &impl Signer,
    tx: TransactionRequest,
) -> Result<alloy::primitives::B256> {
    use alloy::providers::Provider;

    // Get the sender address from the signer
    let sender_core_addr = signer.address();
    let sender = crate::adapter::core_address_to_alloy(&sender_core_addr);

    let tx = tx.from(sender);

    // Get nonce
    let nonce: u64 = adapter
        .provider()
        .get_transaction_count(sender)
        .await
        .map_err(|e| TxError::Send(e.to_string()))?;

    let tx = tx.nonce(nonce);

    // Estimate gas if not set
    let tx = if tx.gas.is_none() {
        let gas: u64 = adapter
            .provider()
            .estimate_gas(tx.clone())
            .await
            .map_err(|e| TxError::Send(e.to_string()))?;
        tx.gas_limit(gas)
    } else {
        tx
    };

    // Build a legacy transaction for signing
    let chain_id = tx.chain_id.unwrap_or(1);
    let nonce = tx.nonce.unwrap_or(0);
    let gas_limit = tx.gas.unwrap_or(21000);
    // For contract creation, to should be None (empty in RLP)
    // For regular calls, to should be Some(address)
    let to_addr: Option<Address> = match tx.to {
        Some(TxKind::Call(addr)) => Some(addr),
        Some(TxKind::Create) => None, // Contract creation
        None => None,                 // Also contract creation
    };
    let value = tx.value.unwrap_or(U256::ZERO);
    let input = tx.input.input().cloned().unwrap_or_default();

    // Get gas price
    let gas_price: u128 = adapter
        .provider()
        .get_gas_price()
        .await
        .map_err(|e| TxError::Send(e.to_string()))?;

    // RLP-encode the unsigned transaction for signing (EIP-155)
    let unsigned_rlp = rlp_encode_unsigned_tx(
        nonce,
        gas_price,
        gas_limit,
        to_addr.as_ref(),
        &value,
        &input,
        chain_id,
    );

    // Hash the unsigned transaction
    let tx_hash: [u8; 32] = Keccak256::digest(&unsigned_rlp).into();

    // Sign with our signer
    let sig = signer
        .sign_hash(&tx_hash)
        .map_err(|e| TxError::Signer(e.to_string()))?;

    // Compute EIP-155 v value
    let v = u64::from(sig.v - 27) + chain_id * 2 + 35;

    // RLP-encode the signed transaction
    let signed_rlp = rlp_encode_signed_tx(
        nonce,
        gas_price,
        gas_limit,
        to_addr.as_ref(),
        &value,
        &input,
        v,
        &sig.r,
        &sig.s,
    );

    // Send raw transaction
    let pending = adapter
        .provider()
        .send_raw_transaction(&signed_rlp)
        .await
        .map_err(|e| TxError::Send(e.to_string()))?;

    Ok(*pending.tx_hash())
}

// ---- RLP encoding helpers for legacy transactions ----

fn rlp_encode_uint(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x80]; // empty string
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let significant = &bytes[start..];
    if significant.len() == 1 && significant[0] < 0x80 {
        significant.to_vec()
    } else {
        let mut out = vec![0x80 + significant.len() as u8];
        out.extend_from_slice(significant);
        out
    }
}

fn rlp_encode_u128(value: u128) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
    let significant = &bytes[start..];
    if significant.len() == 1 && significant[0] < 0x80 {
        significant.to_vec()
    } else {
        let mut out = vec![0x80 + significant.len() as u8];
        out.extend_from_slice(significant);
        out
    }
}

fn rlp_encode_u256(value: &U256) -> Vec<u8> {
    if value.is_zero() {
        return vec![0x80];
    }
    let bytes: [u8; 32] = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(31);
    let significant = &bytes[start..];
    if significant.len() == 1 && significant[0] < 0x80 {
        significant.to_vec()
    } else {
        let mut out = vec![0x80 + significant.len() as u8];
        out.extend_from_slice(significant);
        out
    }
}

fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return vec![0x80];
    }
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }
    if data.len() < 56 {
        let mut out = vec![0x80 + data.len() as u8];
        out.extend_from_slice(data);
        out
    } else {
        let len_bytes = {
            let b = data.len().to_be_bytes();
            let start = b.iter().position(|&x| x != 0).unwrap_or(7);
            b[start..].to_vec()
        };
        let mut out = vec![0xb7 + len_bytes.len() as u8];
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(data);
        out
    }
}

fn rlp_encode_address(addr: &Address) -> Vec<u8> {
    // Address is always 20 bytes
    let mut out = vec![0x80 + 20];
    out.extend_from_slice(addr.as_slice());
    out
}

/// RLP-encode an optional address.
/// For contract creation, `to` is None and encodes as empty bytes (0x80).
fn rlp_encode_optional_address(addr: Option<&Address>) -> Vec<u8> {
    match addr {
        Some(a) => rlp_encode_address(a),
        None => vec![0x80], // Empty bytes for contract creation
    }
}

fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.iter().flat_map(|i| i.iter().copied()).collect();
    if payload.len() < 56 {
        let mut out = vec![0xc0 + payload.len() as u8];
        out.extend_from_slice(&payload);
        out
    } else {
        let len_bytes = {
            let b = payload.len().to_be_bytes();
            let start = b.iter().position(|&x| x != 0).unwrap_or(7);
            b[start..].to_vec()
        };
        let mut out = vec![0xf7 + len_bytes.len() as u8];
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(&payload);
        out
    }
}

/// RLP-encode an unsigned legacy transaction (EIP-155) for signing.
/// For contract creation, `to` should be None.
fn rlp_encode_unsigned_tx(
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: Option<&Address>,
    value: &U256,
    data: &Bytes,
    chain_id: u64,
) -> Vec<u8> {
    let items = vec![
        rlp_encode_uint(nonce),
        rlp_encode_u128(gas_price),
        rlp_encode_uint(gas_limit),
        rlp_encode_optional_address(to),
        rlp_encode_u256(value),
        rlp_encode_bytes(data),
        rlp_encode_uint(chain_id),
        rlp_encode_uint(0), // EIP-155: r = 0
        rlp_encode_uint(0), // EIP-155: s = 0
    ];
    rlp_encode_list(&items)
}

/// RLP-encode a signed legacy transaction.
/// For contract creation, `to` should be None.
#[allow(clippy::too_many_arguments)]
fn rlp_encode_signed_tx(
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: Option<&Address>,
    value: &U256,
    data: &Bytes,
    v: u64,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Vec<u8> {
    // Strip leading zeros from r and s for RLP encoding
    let r_start = r.iter().position(|&b| b != 0).unwrap_or(31);
    let s_start = s.iter().position(|&b| b != 0).unwrap_or(31);

    let items = vec![
        rlp_encode_uint(nonce),
        rlp_encode_u128(gas_price),
        rlp_encode_uint(gas_limit),
        rlp_encode_optional_address(to),
        rlp_encode_u256(value),
        rlp_encode_bytes(data),
        rlp_encode_uint(v),
        rlp_encode_bytes(&r[r_start..]),
        rlp_encode_bytes(&s[s_start..]),
    ];
    rlp_encode_list(&items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_eth_transfer_basic() {
        let req = TransferRequest {
            to: Address::ZERO,
            value: U256::from(1_000_000_000_000_000_000u64), // 1 ETH
            chain_id: 1,
            gas_limit: Some(21000),
        };

        let tx = build_eth_transfer(&req);
        assert_eq!(tx.to, Some(TxKind::Call(Address::ZERO)));
        assert_eq!(tx.value, Some(req.value));
        assert_eq!(tx.chain_id, Some(1));
        assert_eq!(tx.gas, Some(21000));
    }

    #[test]
    fn build_eth_transfer_no_gas_limit() {
        let req = TransferRequest {
            to: Address::ZERO,
            value: U256::from(1u64),
            chain_id: 137,
            gas_limit: None,
        };

        let tx = build_eth_transfer(&req);
        assert_eq!(tx.chain_id, Some(137));
        assert!(tx.gas.is_none());
    }

    #[test]
    fn build_erc20_transfer_encodes_calldata() {
        let token = Address::ZERO;
        let to = Address::with_last_byte(1);
        let amount = U256::from(1000u64);

        let tx = build_erc20_transfer(token, to, amount, 1);

        // Should be sent TO the token contract
        assert_eq!(tx.to, Some(TxKind::Call(token)));
        // Should have no ETH value
        assert!(tx.value.is_none());
        // Should have calldata
        let input = tx.input.input().unwrap();
        // transfer selector = 0xa9059cbb
        assert_eq!(&input[..4], &[0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(input.len(), 68); // 4 + 32 + 32
    }

    #[test]
    fn rlp_encode_uint_zero() {
        assert_eq!(rlp_encode_uint(0), vec![0x80]);
    }

    #[test]
    fn rlp_encode_uint_single_byte() {
        assert_eq!(rlp_encode_uint(1), vec![0x01]);
        assert_eq!(rlp_encode_uint(127), vec![127]);
    }

    #[test]
    fn rlp_encode_uint_multi_byte() {
        // 128 = 0x80, needs length prefix
        assert_eq!(rlp_encode_uint(128), vec![0x81, 0x80]);
        assert_eq!(rlp_encode_uint(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn rlp_encode_empty_bytes() {
        assert_eq!(rlp_encode_bytes(&[]), vec![0x80]);
    }

    #[test]
    fn rlp_unsigned_tx_is_valid_rlp() {
        let encoded = rlp_encode_unsigned_tx(
            0,
            20_000_000_000,
            21000,
            Some(&Address::ZERO),
            &U256::from(1u64),
            &Bytes::new(),
            1,
        );
        // Should start with a list prefix
        assert!(encoded[0] >= 0xc0);
    }

    #[test]
    fn rlp_signed_tx_is_valid_rlp() {
        let r = [0u8; 32];
        let s = [0u8; 32];
        let encoded = rlp_encode_signed_tx(
            0,
            20_000_000_000,
            21000,
            Some(&Address::ZERO),
            &U256::from(1u64),
            &Bytes::new(),
            37, // chain_id=1: v = 27 + 1*2 + 35 = 37 (or 38)
            &r,
            &s,
        );
        assert!(encoded[0] >= 0xc0);
    }

    #[test]
    fn rlp_unsigned_tx_contract_creation() {
        // Contract creation: to = None
        let encoded = rlp_encode_unsigned_tx(
            0,
            20_000_000_000,
            100000,
            None, // Contract creation
            &U256::ZERO,
            &Bytes::from(vec![0x60, 0x80]), // Minimal bytecode
            1,
        );
        // Should be valid RLP list
        assert!(encoded[0] >= 0xc0);
    }
}
