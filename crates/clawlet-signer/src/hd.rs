//! BIP-44 hierarchical deterministic key derivation.
//!
//! Derives EVM keys from a seed using the standard path `m/44'/60'/0'/0/n`.

/// Derives a private key from a seed at the given account index.
///
/// # Panics
/// Not yet implemented.
pub fn derive(_seed: &[u8], _account_index: u32) -> Vec<u8> {
    todo!("M1-4: implement BIP-44 HD derivation")
}
