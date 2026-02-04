//! Transaction building and broadcasting.
//!
//! Constructs EIP-1559 transactions and submits them to the network.

/// A raw unsigned transaction.
#[derive(Debug, Clone)]
pub struct UnsignedTx {
    /// Recipient address.
    pub to: [u8; 20],
    /// Value in wei.
    pub value: u128,
    /// Calldata.
    pub data: Vec<u8>,
    /// Chain ID.
    pub chain_id: u64,
}

/// Builds and signs a transaction, returning the RLP-encoded signed bytes.
///
/// # Panics
/// Not yet implemented.
pub fn build_and_sign(_tx: UnsignedTx, _signer: &dyn clawlet_signer::signer::Signer) -> Vec<u8> {
    todo!("M1-6: implement transaction building and signing")
}
