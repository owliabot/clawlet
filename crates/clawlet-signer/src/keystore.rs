//! Encrypted keystore management.
//!
//! Creates, unlocks, and lists Ethereum-compatible V3 keystore files
//! using the `eth-keystore` crate for scrypt/aes-128-ctr encryption.

use std::path::{Path, PathBuf};

use clawlet_core::types::Address;
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use thiserror::Error;

/// Errors arising from keystore operations.
#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("keystore crypto error: {0}")]
    Keystore(String),

    #[error("invalid private key")]
    InvalidKey,

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Result alias for keystore operations.
pub type Result<T> = std::result::Result<T, KeystoreError>;

/// Manages encrypted private key files on disk.
pub struct Keystore;

impl Keystore {
    /// Creates a new keystore file with a random private key.
    ///
    /// Returns the derived Ethereum address and the path to the keystore JSON file.
    pub fn create(dir: &Path, password: &str) -> Result<(Address, PathBuf)> {
        std::fs::create_dir_all(dir)?;

        let mut rng = rand::thread_rng();
        let (secret, name) = eth_keystore::new(dir, &mut rng, password, None)
            .map_err(|e| KeystoreError::Keystore(e.to_string()))?;

        let path = dir.join(name);
        let signing_key = SigningKey::from_bytes(secret.as_slice().into())
            .map_err(|_| KeystoreError::InvalidKey)?;
        let address = public_key_to_address(&signing_key);
        Ok((address, path))
    }

    /// Creates a new keystore file from an existing private key.
    ///
    /// Returns the derived Ethereum address and the path to the keystore JSON file.
    pub fn create_from_key(
        dir: &Path,
        password: &str,
        private_key: &[u8],
    ) -> Result<(Address, PathBuf)> {
        std::fs::create_dir_all(dir)?;

        let mut rng = rand::thread_rng();
        let name = eth_keystore::encrypt_key(dir, &mut rng, private_key, password, None)
            .map_err(|e| KeystoreError::Keystore(e.to_string()))?;

        let path = dir.join(name);
        let signing_key =
            SigningKey::from_bytes(private_key.into()).map_err(|_| KeystoreError::InvalidKey)?;
        let address = public_key_to_address(&signing_key);
        Ok((address, path))
    }

    /// Unlocks a keystore file with the given password.
    ///
    /// Returns the decrypted signing key.
    pub fn unlock(path: &Path, password: &str) -> Result<SigningKey> {
        let secret = eth_keystore::decrypt_key(path, password)
            .map_err(|e| KeystoreError::Keystore(e.to_string()))?;

        SigningKey::from_bytes(secret.as_slice().into()).map_err(|_| KeystoreError::InvalidKey)
    }

    /// Lists all keystore files in a directory, returning their addresses and paths.
    ///
    /// Skips files that cannot be parsed or whose address cannot be determined.
    pub fn list(dir: &Path) -> Result<Vec<(Address, PathBuf)>> {
        let mut results = Vec::new();

        if !dir.exists() {
            return Ok(results);
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            // Try to parse the keystore JSON to extract the address field
            if let Some(addr) = extract_address_from_keystore(&path) {
                results.push((addr, path));
            }
        }

        Ok(results)
    }
}

/// Derives an Ethereum address from a signing key.
pub fn public_key_to_address(key: &SigningKey) -> Address {
    use k256::ecdsa::VerifyingKey;

    let verifying_key = VerifyingKey::from(key);
    let pubkey_bytes = verifying_key.to_encoded_point(false);
    // Skip the 0x04 prefix byte, hash the remaining 64 bytes
    let hash = Keccak256::digest(&pubkey_bytes.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Address(addr)
}

/// Tries to extract an Ethereum address from a keystore JSON file.
fn extract_address_from_keystore(path: &Path) -> Option<Address> {
    let data = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&data).ok()?;
    let addr_val = json.get("address")?;

    // Handle both string "0xabc..." / "abc..." and hex-encoded H160 "0x00...abc"
    let addr_str = addr_val.as_str()?;
    let stripped = addr_str.strip_prefix("0x").unwrap_or(addr_str);
    let bytes = hex::decode(stripped).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Some(Address(addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn create_and_unlock_keystore() {
        let dir = TempDir::new().unwrap();
        let password = "test-password-123";

        let (address, path) = Keystore::create(dir.path(), password).unwrap();
        assert!(path.exists());
        assert_ne!(address.0, [0u8; 20]);

        // Unlock and verify the same address
        let key = Keystore::unlock(&path, password).unwrap();
        let derived = public_key_to_address(&key);
        assert_eq!(address, derived);
    }

    #[test]
    fn unlock_wrong_password_fails() {
        let dir = TempDir::new().unwrap();
        let (_address, path) = Keystore::create(dir.path(), "correct").unwrap();

        let result = Keystore::unlock(&path, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn list_keystores() {
        let dir = TempDir::new().unwrap();

        let (addr1, _) = Keystore::create(dir.path(), "pw1").unwrap();
        let (addr2, _) = Keystore::create(dir.path(), "pw2").unwrap();

        let list = Keystore::list(dir.path()).unwrap();
        assert_eq!(list.len(), 2);

        let addrs: Vec<_> = list.iter().map(|(a, _)| a.clone()).collect();
        assert!(addrs.contains(&addr1));
        assert!(addrs.contains(&addr2));
    }

    #[test]
    fn list_empty_dir() {
        let dir = TempDir::new().unwrap();
        let list = Keystore::list(dir.path()).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn list_nonexistent_dir() {
        let list = Keystore::list(Path::new("/tmp/does-not-exist-clawlet-test")).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn public_key_to_address_deterministic() {
        let key = SigningKey::from_bytes(&[1u8; 32].into()).unwrap();
        let addr1 = public_key_to_address(&key);
        let addr2 = public_key_to_address(&key);
        assert_eq!(addr1, addr2);
        assert_ne!(addr1.0, [0u8; 20]);
    }
}
