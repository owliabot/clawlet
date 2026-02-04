//! BIP-44 hierarchical deterministic key derivation for EVM.
//!
//! Derives secp256k1 keys from a BIP-39 mnemonic using the standard
//! Ethereum derivation path `m/44'/60'/0'/0/{index}`.

use bip32::DerivationPath;
use bip39::Mnemonic;
use k256::ecdsa::SigningKey;
use thiserror::Error;

/// Errors arising from HD derivation.
#[derive(Debug, Error)]
pub enum HdError {
    #[error("invalid mnemonic: {0}")]
    Mnemonic(String),

    #[error("BIP-32 derivation error: {0}")]
    Derivation(#[from] bip32::Error),
}

/// Result alias for HD operations.
pub type Result<T> = std::result::Result<T, HdError>;

/// Derives a signing key from a BIP-39 mnemonic at the given BIP-44 index.
///
/// Uses the standard Ethereum path: `m/44'/60'/0'/0/{index}`
pub fn derive_key(mnemonic: &str, index: u32) -> Result<SigningKey> {
    let mnemonic = Mnemonic::parse(mnemonic).map_err(|e| HdError::Mnemonic(e.to_string()))?;
    let seed = mnemonic.to_seed("");

    let path: DerivationPath = format!("m/44'/60'/0'/0/{index}")
        .parse()
        .map_err(HdError::Derivation)?;

    let child_xpriv = bip32::XPrv::derive_from_path(seed, &path)?;
    let signing_key = child_xpriv.private_key().clone();

    Ok(signing_key)
}

/// Generates a new random 24-word BIP-39 mnemonic.
pub fn generate_mnemonic() -> String {
    let mut entropy = [0u8; 32]; // 256 bits = 24 words
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut entropy);
    let mnemonic = Mnemonic::from_entropy(&entropy).expect("valid entropy length");
    mnemonic.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::public_key_to_address;

    #[test]
    fn generate_mnemonic_24_words() {
        let mnemonic = generate_mnemonic();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);

        // Verify it's a valid mnemonic
        assert!(Mnemonic::parse(&mnemonic).is_ok());
    }

    #[test]
    fn derive_key_deterministic() {
        let mnemonic = generate_mnemonic();

        let key1 = derive_key(&mnemonic, 0).unwrap();
        let key2 = derive_key(&mnemonic, 0).unwrap();

        let addr1 = public_key_to_address(&key1);
        let addr2 = public_key_to_address(&key2);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn derive_different_indices_produce_different_keys() {
        let mnemonic = generate_mnemonic();

        let key0 = derive_key(&mnemonic, 0).unwrap();
        let key1 = derive_key(&mnemonic, 1).unwrap();

        let addr0 = public_key_to_address(&key0);
        let addr1 = public_key_to_address(&key1);
        assert_ne!(addr0, addr1);
    }

    #[test]
    fn derive_known_mnemonic() {
        // Standard test mnemonic from BIP-39 spec
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let key = derive_key(mnemonic, 0).unwrap();
        let addr = public_key_to_address(&key);

        // Well-known address for this mnemonic at m/44'/60'/0'/0/0
        // 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
        let expected = "9858effd232b4033e47d90003d41ec34ecaeda94";
        let actual = hex::encode(addr.0);
        assert_eq!(actual, expected);
    }

    #[test]
    fn invalid_mnemonic_fails() {
        let result = derive_key("not a valid mnemonic phrase", 0);
        assert!(result.is_err());
    }

    #[test]
    fn derive_multiple_indices() {
        let mnemonic = generate_mnemonic();
        let mut addresses = std::collections::HashSet::new();

        for i in 0..5 {
            let key = derive_key(&mnemonic, i).unwrap();
            let addr = public_key_to_address(&key);
            addresses.insert(addr.0);
        }

        // All 5 addresses should be unique
        assert_eq!(addresses.len(), 5);
    }
}
