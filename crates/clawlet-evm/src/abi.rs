//! ABI encoding and decoding utilities.
//!
//! Handles ERC-20 function selectors, event topics, and parameter encoding.

/// Encodes an ERC-20 `balanceOf(address)` call.
///
/// # Panics
/// Not yet implemented.
pub fn encode_balance_of(_address: &[u8; 20]) -> Vec<u8> {
    todo!("M1-5: implement ABI encoding for balanceOf")
}

/// Encodes an ERC-20 `transfer(address,uint256)` call.
///
/// # Panics
/// Not yet implemented.
pub fn encode_transfer(_to: &[u8; 20], _amount: &[u8; 32]) -> Vec<u8> {
    todo!("M1-6: implement ABI encoding for transfer")
}
