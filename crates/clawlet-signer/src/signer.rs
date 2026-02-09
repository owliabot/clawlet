//! Signing interface and local signer implementation.
//!
//! Provides the `Signer` trait and `LocalSigner` for signing hashes and
//! EIP-191 personal messages using a secp256k1 private key.

use alloy::primitives::Address;
use k256::ecdsa::{self, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};
use thiserror::Error;

use crate::keystore::public_key_to_address;

/// Errors arising from signing operations.
#[derive(Debug, Error)]
pub enum SignerError {
    #[error("ECDSA signing error: {0}")]
    Ecdsa(#[from] ecdsa::Error),
}

/// Result alias for signer operations.
pub type Result<T> = std::result::Result<T, SignerError>;

/// A 65-byte ECDSA signature with recovery id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// r component (32 bytes, big-endian)
    pub r: [u8; 32],
    /// s component (32 bytes, big-endian)
    pub s: [u8; 32],
    /// Recovery id (27 or 28 for Ethereum)
    pub v: u8,
}

impl Signature {
    /// Serializes the signature to 65 bytes: r (32) || s (32) || v (1).
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out[64] = self.v;
        out
    }
}

/// Trait for signing hashes and messages.
pub trait Signer {
    /// Returns the signer's Ethereum address.
    fn address(&self) -> Address;

    /// Signs a 32-byte hash directly.
    fn sign_hash(&self, hash: &[u8; 32]) -> Result<Signature>;

    /// Signs a message using EIP-191 personal sign.
    ///
    /// Prepends `"\x19Ethereum Signed Message:\n{len}"` before hashing and signing.
    fn sign_message(&self, message: &[u8]) -> Result<Signature>;
}

/// A local signer that wraps a `k256::ecdsa::SigningKey`.
pub struct LocalSigner {
    key: SigningKey,
    address: Address,
}

impl LocalSigner {
    /// Creates a new `LocalSigner` from a signing key.
    pub fn new(key: SigningKey) -> Self {
        let address = public_key_to_address(&key);
        Self { key, address }
    }

    /// Creates a new `LocalSigner` from raw private key bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> std::result::Result<Self, k256::ecdsa::Error> {
        let key = SigningKey::from_bytes(bytes.into())?;
        Ok(Self::new(key))
    }

    fn sign_prehash(&self, hash: &[u8; 32]) -> Result<Signature> {
        let (sig, recid): (ecdsa::Signature, _) = self.key.sign_prehash_recoverable(hash)?;
        let bytes = sig.to_bytes();

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);

        // Ethereum uses v = 27 + recovery_id
        let v = 27 + recid.to_byte();

        Ok(Signature { r, s, v })
    }
}

impl Signer for LocalSigner {
    fn address(&self) -> Address {
        self.address
    }

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<Signature> {
        self.sign_prehash(hash)
    }

    fn sign_message(&self, message: &[u8]) -> Result<Signature> {
        // EIP-191 personal sign prefix
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut hasher = Keccak256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(message);
        let hash: [u8; 32] = hasher.finalize().into();

        self.sign_prehash(&hash)
    }
}

/// Recovers the signer's Ethereum address from a signature and message hash.
pub fn recover_address(hash: &[u8; 32], sig: &Signature) -> std::result::Result<Address, String> {
    let recid = ecdsa::RecoveryId::from_byte(sig.v - 27)
        .ok_or_else(|| "invalid recovery id".to_string())?;

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&sig.r);
    sig_bytes[32..].copy_from_slice(&sig.s);

    let signature =
        ecdsa::Signature::from_bytes(sig_bytes.as_ref().into()).map_err(|e| e.to_string())?;

    let verifying_key =
        VerifyingKey::recover_from_prehash(hash, &signature, recid).map_err(|e| e.to_string())?;

    let pubkey_bytes = verifying_key.to_encoded_point(false);
    let pubkey_hash = Keccak256::digest(&pubkey_bytes.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&pubkey_hash[12..]);

    Ok(Address::from(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signer() -> LocalSigner {
        // Well-known test private key
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 1;
        LocalSigner::from_bytes(&key_bytes).unwrap()
    }

    #[test]
    fn local_signer_address_is_deterministic() {
        let signer = test_signer();
        let addr1 = signer.address();
        let addr2 = signer.address();
        assert_eq!(addr1, addr2);
        assert_ne!(addr1, Address::ZERO);
    }

    #[test]
    fn sign_hash_produces_valid_signature() {
        let signer = test_signer();
        let hash = [0xab_u8; 32];

        let sig = signer.sign_hash(&hash).unwrap();
        assert!(sig.v == 27 || sig.v == 28);
        assert_eq!(sig.to_bytes().len(), 65);

        // Recover and verify
        let recovered = recover_address(&hash, &sig).unwrap();
        assert_eq!(recovered, signer.address());
    }

    #[test]
    fn sign_message_eip191() {
        let signer = test_signer();
        let message = b"Hello, Clawlet!";

        let sig = signer.sign_message(message).unwrap();
        assert!(sig.v == 27 || sig.v == 28);

        // Manually compute the EIP-191 hash to verify recovery
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut hasher = Keccak256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(message);
        let hash: [u8; 32] = hasher.finalize().into();

        let recovered = recover_address(&hash, &sig).unwrap();
        assert_eq!(recovered, signer.address());
    }

    #[test]
    fn signature_to_bytes_roundtrip() {
        let sig = Signature {
            r: [1u8; 32],
            s: [2u8; 32],
            v: 27,
        };
        let bytes = sig.to_bytes();
        assert_eq!(&bytes[..32], &[1u8; 32]);
        assert_eq!(&bytes[32..64], &[2u8; 32]);
        assert_eq!(bytes[64], 27);
    }

    #[test]
    fn different_messages_produce_different_signatures() {
        let signer = test_signer();
        let sig1 = signer.sign_message(b"message 1").unwrap();
        let sig2 = signer.sign_message(b"message 2").unwrap();
        assert_ne!(sig1, sig2);
    }
}
