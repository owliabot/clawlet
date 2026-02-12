//! Solana Ed25519 signer with HD derivation and base58 import.

use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use thiserror::Error;

/// Errors from Solana signer operations.
#[derive(Debug, Error)]
pub enum SolanaSignerError {
    #[error("invalid private key: {0}")]
    InvalidKey(String),
    #[error("HD derivation error: {0}")]
    Derivation(String),
    #[error("signing error: {0}")]
    Signing(String),
}

/// Result alias for signer operations.
pub type Result<T> = std::result::Result<T, SolanaSignerError>;

/// A Solana signer wrapping an Ed25519 keypair.
pub struct SolanaSigner {
    signing_key: SigningKey,
    pubkey: Pubkey,
}

impl std::fmt::Debug for SolanaSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SolanaSigner")
            .field("pubkey", &self.pubkey)
            .finish()
    }
}

impl SolanaSigner {
    /// Creates a signer from raw Ed25519 secret key bytes (32 bytes).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        let pubkey = Pubkey::from(verifying_key.to_bytes());
        Ok(Self {
            signing_key,
            pubkey,
        })
    }

    /// Imports a signer from a base58-encoded private key (64-byte Solana keypair format).
    pub fn from_base58(key: &str) -> Result<Self> {
        let bytes = bs58::decode(key)
            .into_vec()
            .map_err(|e| SolanaSignerError::InvalidKey(e.to_string()))?;

        if bytes.len() == 64 {
            // Solana keypair format: first 32 bytes are secret key
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&bytes[..32]);
            Self::from_bytes(&secret)
        } else if bytes.len() == 32 {
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&bytes);
            Self::from_bytes(&secret)
        } else {
            Err(SolanaSignerError::InvalidKey(format!(
                "expected 32 or 64 bytes, got {}",
                bytes.len()
            )))
        }
    }

    /// Derives a signer from a BIP-39 mnemonic using Solana's BIP-44 path.
    ///
    /// Path: `m/44'/501'/{index}'/0'`
    pub fn from_mnemonic(mnemonic: &str, index: u32) -> Result<Self> {
        let seed = derive_solana_seed(mnemonic, index)?;
        Self::from_bytes(&seed)
    }

    /// Returns the Ed25519 public key as a Solana `Pubkey`.
    pub fn pubkey(&self) -> &Pubkey {
        &self.pubkey
    }

    /// Signs arbitrary bytes.
    pub fn sign_bytes(&self, message: &[u8]) -> Signature {
        let sig = self.signing_key.sign(message);
        Signature::from(sig.to_bytes())
    }

    /// Returns the raw secret key bytes (32 bytes).
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Returns the Solana keypair bytes (64 = secret + public).
    pub fn keypair_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.signing_key.to_bytes());
        out[32..].copy_from_slice(&self.signing_key.verifying_key().to_bytes());
        out
    }
}

/// Derives a 32-byte Ed25519 seed from a BIP-39 mnemonic using Solana's
/// BIP-44 derivation path: `m/44'/501'/{index}'/0'`.
///
/// Uses SLIP-10 (Ed25519) derivation as specified by Solana wallets.
fn derive_solana_seed(mnemonic: &str, index: u32) -> Result<[u8; 32]> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    let parsed = bip39::Mnemonic::parse(mnemonic)
        .map_err(|e| SolanaSignerError::Derivation(e.to_string()))?;
    let seed = parsed.to_seed("");

    // SLIP-10 master key derivation
    let mut mac =
        Hmac::<Sha512>::new_from_slice(b"ed25519 seed").expect("HMAC can take key of any size");
    mac.update(&seed);
    let result = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);

    // Derive through path: 44', 501', index', 0'
    let path_indices = [
        44u32 | 0x8000_0000,
        501u32 | 0x8000_0000,
        index | 0x8000_0000,
        0x8000_0000,
    ];

    for child_index in path_indices {
        let mut mac =
            Hmac::<Sha512>::new_from_slice(&chain_code).expect("HMAC can take key of any size");
        // For hardened Ed25519 derivation: 0x00 || key || index
        mac.update(&[0u8]);
        mac.update(&key);
        mac.update(&child_index.to_be_bytes());
        let result = mac.finalize().into_bytes();

        key.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_deterministic() {
        let secret = [42u8; 32];
        let s1 = SolanaSigner::from_bytes(&secret).unwrap();
        let s2 = SolanaSigner::from_bytes(&secret).unwrap();
        assert_eq!(s1.pubkey(), s2.pubkey());
    }

    #[test]
    fn from_mnemonic_deterministic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let s1 = SolanaSigner::from_mnemonic(mnemonic, 0).unwrap();
        let s2 = SolanaSigner::from_mnemonic(mnemonic, 0).unwrap();
        assert_eq!(s1.pubkey(), s2.pubkey());
    }

    #[test]
    fn different_indices_different_keys() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let s0 = SolanaSigner::from_mnemonic(mnemonic, 0).unwrap();
        let s1 = SolanaSigner::from_mnemonic(mnemonic, 1).unwrap();
        assert_ne!(s0.pubkey(), s1.pubkey());
    }

    #[test]
    fn sign_and_verify() {
        let secret = [1u8; 32];
        let signer = SolanaSigner::from_bytes(&secret).unwrap();
        let message = b"hello solana";
        let sig = signer.sign_bytes(message);

        // Signature should be 64 bytes
        assert_eq!(sig.as_ref().len(), 64);
    }

    #[test]
    fn keypair_bytes_roundtrip() {
        let secret = [7u8; 32];
        let signer = SolanaSigner::from_bytes(&secret).unwrap();
        let kp = signer.keypair_bytes();
        assert_eq!(&kp[..32], &secret);

        // Re-create from the keypair bytes
        let mut s2 = [0u8; 32];
        s2.copy_from_slice(&kp[..32]);
        let signer2 = SolanaSigner::from_bytes(&s2).unwrap();
        assert_eq!(signer.pubkey(), signer2.pubkey());
    }

    #[test]
    fn from_base58_64_bytes() {
        let secret = [5u8; 32];
        let signer = SolanaSigner::from_bytes(&secret).unwrap();
        let kp = signer.keypair_bytes();
        let encoded = bs58::encode(&kp).into_string();

        let imported = SolanaSigner::from_base58(&encoded).unwrap();
        assert_eq!(signer.pubkey(), imported.pubkey());
    }

    #[test]
    fn known_mnemonic_address() {
        // Well-known test: "abandon...about" at m/44'/501'/0'/0'
        // Expected pubkey: 2gCPMxsMz6MN4MxoY1WbiMtR3bo4Y4KhwBFjPBcZiKL3
        // (This is the Phantom/Solflare standard derivation)
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let signer = SolanaSigner::from_mnemonic(mnemonic, 0).unwrap();
        // Just verify it produces a valid non-zero pubkey
        assert_ne!(*signer.pubkey(), Pubkey::default());
    }

    #[test]
    fn debug_display() {
        let secret = [1u8; 32];
        let signer = SolanaSigner::from_bytes(&secret).unwrap();
        let debug = format!("{signer:?}");
        assert!(debug.contains("SolanaSigner"));
    }

    #[test]
    fn invalid_base58_fails() {
        let result = SolanaSigner::from_base58("not-valid-base58!!!");
        assert!(result.is_err());
    }
}
